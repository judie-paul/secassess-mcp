"""Assessment report generation and storage.

The report body matches contracts/report_data.example.json exactly. The backend
fills every numeric and statistical field, the scoring_model and anomaly_types
blocks, and each risk's remediation_window (fixed by severity). The AI-authored
fields (business_impact, remediation) are accepted only through validated
annotations and are null until supplied. Metadata that the example format has
no field for (report ID, completion status, insufficient-risk note) is returned
in HTTP headers by the API layer.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import config
from analysis import scoring
from api.data_access.json_repository import JsonRepository
from api.errors import DataLoadError, InvalidRequestError, NotFoundError
from api.schemas.reports import AssessmentReport, AssessmentRequest
from api.schemas.risks import ReportRisk
from api.services.anomaly_service import AnomalyService
from api.services.common import require_organization
from api.services.organization_service import OrganizationService
from api.services.risk_service import RiskService

REPORT_ID_PATTERN = re.compile(r"^RPT-[0-9A-F]{12}$")


@dataclass
class ReportResult:
    report_id: str
    status: str  # "complete" when every top risk is annotated, else "draft"
    note: Optional[str]
    report: AssessmentReport


class ReportService:
    def __init__(
        self,
        repo: JsonRepository,
        organizations: OrganizationService,
        risks: RiskService,
        anomalies: AnomalyService,
        reports_dir: Optional[Path] = None,
    ):
        self.repo = repo
        self.organizations = organizations
        self.risks = risks
        self.anomalies = anomalies
        self.reports_dir = Path(reports_dir or config.REPORTS_DIR)

    def _report_id(self, organization_id: str, request: AssessmentRequest) -> str:
        payload = json.dumps(
            {
                "organization_id": organization_id,
                "generated_at": config.report_timestamp().isoformat(),
                "request": request.model_dump(mode="json"),
            },
            sort_keys=True,
        )
        return "RPT-" + hashlib.sha256(payload.encode()).hexdigest()[:12].upper()

    def build(self, organization_id: str, request: AssessmentRequest) -> ReportResult:
        organization = require_organization(self.repo, organization_id)
        top = self.risks.top_risks(organization_id, request.top_risks_limit)

        annotations = {}
        for annotation in request.annotations:
            if annotation.risk_id in annotations:
                raise InvalidRequestError(f"Duplicate annotation for risk {annotation.risk_id}")
            annotations[annotation.risk_id] = annotation
        unknown = sorted(set(annotations) - {r.risk_id for r in top.items})
        if unknown:
            raise InvalidRequestError(
                f"Annotations reference risks that are not in the top risks: {', '.join(unknown)}"
            )

        top_risks = []
        for risk in top.items:
            note = annotations.get(risk.risk_id)
            fields = risk.model_dump()
            if note:
                fields.update(business_impact=note.business_impact, remediation=note.remediation)
            top_risks.append(ReportRisk(**fields))

        report = AssessmentReport(
            schema_version=config.SCHEMA_VERSION,
            generated_at=config.report_timestamp(),
            organisation=organization.name,
            scoring_model=scoring.scoring_model(),
            anomaly_types=scoring.anomaly_types(),
            summary=self.organizations.report_summary(organization_id),
            findings_by_service=self.organizations.findings_by_service(organization_id),
            risk_matrix=self.risks.risk_matrix(organization_id),
            top_risks=top_risks,
            anomalies=[a.to_report() for a in self.anomalies.default_window_anomalies(organization_id)],
        )
        complete = bool(top_risks) and all(r.business_impact and r.remediation for r in top_risks)
        return ReportResult(
            report_id=self._report_id(organization_id, request),
            status="complete" if complete else "draft",
            note=top.message,
            report=report,
        )

    def _path(self, organization_id: str, report_id: str) -> Path:
        return self.reports_dir / organization_id / f"{report_id}.json"

    def create(self, organization_id: str, request: AssessmentRequest) -> ReportResult:
        result = self.build(organization_id, request)
        path = self._path(organization_id, result.report_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((result.report.model_dump_json(indent=2) + "\n").encode("utf-8"))
        return result

    def get(self, organization_id: str, report_id: str) -> AssessmentReport:
        require_organization(self.repo, organization_id)
        # The pattern check also prevents path traversal through report_id.
        if not REPORT_ID_PATTERN.match(report_id):
            raise NotFoundError("Report", report_id)
        path = self._path(organization_id, report_id)
        if not path.exists():
            raise NotFoundError("Report", report_id)
        try:
            return AssessmentReport.model_validate_json(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise DataLoadError(f"Stored report {report_id} is corrupt") from exc
