"""Risk scoring, ranking and evidence correlation.

Every finding is scored (contracts/report_data.example.json -> scoring_model):

* score           = severity x exposure x data_sensitivity x activity weights
* likelihood      = the likelihood rule (exposure, +1 if anomalous access)
* impact (1-5)    = the weighted impact model in analysis/impact.py
* remediation_window = fixed by severity

The risk matrix counts every finding, so its total equals total_findings.
Top risks come from active findings only, ranked by score, then likelihood x
impact, impact, likelihood and finding ID, keeping the highest-ranked finding
per asset. All numbers are produced here and are authoritative.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, List, Optional

import config
from analysis import scoring
from analysis.impact import compute_impact, effective_sensitivity
from analysis.likelihood import compute_likelihood
from api.data_access.json_repository import JsonRepository
from api.schemas.anomalies import Anomaly
from api.schemas.assets import Asset
from api.schemas.findings import Finding
from api.schemas.inventory import DataInventoryRecord
from api.schemas.reports import RiskMatrixCell
from api.schemas.risks import EvidenceRef, ReportRisk, RiskScoringDetail, ScoredRisk, TopRisksResponse
from api.services.anomaly_service import AnomalyService
from api.services.common import require_organization
from api.services.finding_service import is_active, sort_findings
from api.services.inventory_service import InventoryService


def risk_id_for(rank: int) -> str:
    return f"R-{rank:03d}"


def _inventory_detail(record: DataInventoryRecord) -> str:
    kinds = [k for k, flag in (("PII", record.contains_pii), ("financial", record.contains_financial_data)) if flag]
    labels = "; ".join([record.data_classification] + ([", ".join(kinds)] if kinds else []))
    if record.record_count is None:
        note = f" - {record.record_count_note}" if record.record_count_note else ""
        return f"Record count unknown{note} ({labels})"
    return f"{record.record_count:,} records ({labels})"


class RiskService:
    def __init__(self, repo: JsonRepository, anomalies: AnomalyService, inventory: InventoryService):
        self.repo = repo
        self.anomalies = anomalies
        self.inventory = inventory

    # -- construction ----------------------------------------------------------

    def _evidence(
        self,
        finding: Finding,
        asset_findings: List[Finding],
        inventory: Optional[DataInventoryRecord],
        anomalies: List[Anomaly],
    ) -> List[EvidenceRef]:
        evidence = [EvidenceRef(source="findings", ref=finding.finding_id, detail=finding.title)]
        evidence += [
            EvidenceRef(source="findings", ref=f.finding_id, detail=f"Related {f.severity} finding: {f.title}")
            for f in asset_findings
            if f.finding_id != finding.finding_id
        ]
        if inventory is not None:
            evidence.append(
                EvidenceRef(source="data_inventory", ref=inventory.asset_id, detail=_inventory_detail(inventory))
            )
        evidence += [
            EvidenceRef(
                source="auth_logs",
                ref=a.anomaly_id,
                detail=f"{a.detail} on {a.timestamp:%Y-%m-%d}",
            )
            for a in sorted(anomalies, key=lambda a: (a.timestamp, a.anomaly_id), reverse=True)
        ]
        return evidence

    def _score(
        self,
        asset: Asset,
        finding: Finding,
        asset_findings: List[Finding],
        anomalies: List[Anomaly],
    ) -> ScoredRisk:
        inventory = self.inventory.record_for(asset.organization_id, asset.asset_id)
        anomalous = bool(anomalies)
        likelihood = compute_likelihood(finding.exposure, anomalous)
        impact = compute_impact(asset, inventory)
        product = scoring.risk_score(likelihood.score, impact.score)
        sensitivity = effective_sensitivity(asset, inventory)
        breakdown = scoring.score_breakdown(finding.severity, finding.exposure, sensitivity, anomalous)

        risk = ReportRisk(
            rank=0,
            risk_id="",
            asset_id=asset.asset_id,
            service=asset.service,
            title=finding.title,
            severity=finding.severity,
            exposure=finding.exposure,
            data_sensitivity=config.REPORT_SENSITIVITY_LABELS[sensitivity],
            record_count=inventory.record_count if inventory else None,
            anomalous_access=anomalous,
            score=scoring.weighted_risk_score(breakdown),
            score_breakdown=breakdown,
            likelihood=likelihood.score,
            impact=impact.score,
            evidence=self._evidence(finding, asset_findings, inventory, anomalies),
            remediation_window=config.REMEDIATION_WINDOW_BY_SEVERITY[finding.severity],
        )
        detail = RiskScoringDetail(
            finding_id=finding.finding_id,
            score_formula=scoring.RISK_SCORE_FORMULA,
            likelihood=likelihood,
            impact=impact,
            likelihood_x_impact=product,
            likelihood_x_impact_band=scoring.risk_band(product),
            confidence=impact.confidence,
        )
        return ScoredRisk(finding_id=finding.finding_id, asset_id=asset.asset_id, risk=risk, detail=detail)

    # -- public API ------------------------------------------------------------

    def scored_findings(self, organization_id: str, include_inactive: bool = False) -> List[ScoredRisk]:
        """Findings scored and sorted by the deterministic ranking key.

        Active findings only by default; ``include_inactive`` adds resolved and accepted ones
        (used for the risk matrix, which must cover every finding)."""
        require_organization(self.repo, organization_id)
        findings_by_asset: Dict[str, List[Finding]] = {}
        active_by_asset: Dict[str, List[Finding]] = {}
        for finding in self.repo.findings_for(organization_id):
            if is_active(finding):
                active_by_asset.setdefault(finding.asset_id, []).append(finding)
            if include_inactive or is_active(finding):
                findings_by_asset.setdefault(finding.asset_id, []).append(finding)

        anomalies_by_asset: Dict[str, List[Anomaly]] = {}
        for anomaly in self.anomalies.default_window_anomalies(organization_id):
            if anomaly.asset_id:
                anomalies_by_asset.setdefault(anomaly.asset_id, []).append(anomaly)

        scored = []
        for asset in self.repo.assets_for(organization_id):
            related = sort_findings(active_by_asset.get(asset.asset_id, []))
            anomalies = anomalies_by_asset.get(asset.asset_id, [])
            for finding in sort_findings(findings_by_asset.get(asset.asset_id, [])):
                scored.append(self._score(asset, finding, related, anomalies))

        scored.sort(
            key=lambda s: (
                -s.risk.score,
                -s.detail.likelihood_x_impact,
                -s.risk.impact,
                -s.risk.likelihood,
                s.finding_id,
            )
        )
        return scored

    def ranked_risks(self, organization_id: str) -> List[ScoredRisk]:
        """Qualifying risks, highest-ranked finding per asset, with rank and risk_id assigned."""
        ranked, seen_assets = [], set()
        for item in self.scored_findings(organization_id):
            if item.detail.likelihood_x_impact < config.MIN_QUALIFYING_LIKELIHOOD_IMPACT:
                continue
            if item.asset_id in seen_assets:
                continue
            seen_assets.add(item.asset_id)
            rank = len(ranked) + 1
            item.risk.rank = rank
            item.risk.risk_id = risk_id_for(rank)
            ranked.append(item)
        return ranked

    def risk_matrix(self, organization_id: str) -> List[RiskMatrixCell]:
        """Every finding by (likelihood, impact), ordered by impact then likelihood, highest first."""
        scored = self.scored_findings(organization_id, include_inactive=True)
        counts = Counter((s.risk.likelihood, s.risk.impact) for s in scored)
        return [
            RiskMatrixCell(likelihood=l, impact=i, count=c)
            for (l, i), c in sorted(counts.items(), key=lambda item: (-item[0][1], -item[0][0]))
        ]

    def top_risks(self, organization_id: str, limit: Optional[int] = None) -> TopRisksResponse:
        limit = config.DEFAULT_TOP_RISKS if limit is None else limit
        ranked = self.ranked_risks(organization_id)
        selected = ranked[:limit]
        sufficient = len(ranked) >= config.MIN_TOP_RISKS
        message = None
        if not sufficient:
            message = (
                f"Insufficient qualifying risks: only {len(ranked)} asset(s) have a finding with "
                f"likelihood x impact of at least {config.MIN_QUALIFYING_LIKELIHOOD_IMPACT} "
                f"(minimum {config.MIN_TOP_RISKS} expected). All available qualifying risks are returned."
            )
        return TopRisksResponse(
            organization_id=organization_id,
            requested_limit=limit,
            returned=len(selected),
            qualifying_risks=len(ranked),
            sufficient_risks=sufficient,
            message=message,
            items=[s.risk for s in selected],
            scoring_details={s.risk.risk_id: s.detail for s in selected},
        )
