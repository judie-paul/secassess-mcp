"""Wires the repository and services together for the API."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import Request

from api.data_access.json_repository import JsonRepository
from api.services.anomaly_service import AnomalyService
from api.services.asset_service import AssetService
from api.services.auth_log_service import AuthLogService
from api.services.finding_service import FindingService
from api.services.inventory_service import InventoryService
from api.services.organization_service import OrganizationService
from api.services.report_service import ReportService
from api.services.risk_service import RiskService


class Services:
    def __init__(self, data_dir: Optional[Path] = None, reports_dir: Optional[Path] = None):
        self.repo = JsonRepository(data_dir)
        self.findings = FindingService(self.repo)
        self.auth_logs = AuthLogService(self.repo)
        self.inventory = InventoryService(self.repo)
        self.anomalies = AnomalyService(self.repo)
        self.risks = RiskService(self.repo, self.anomalies, self.inventory)
        self.organizations = OrganizationService(self.repo, self.anomalies, self.risks)
        self.assets = AssetService(self.repo, self.findings, self.inventory, self.anomalies)
        self.reports = ReportService(self.repo, self.organizations, self.risks, self.anomalies, reports_dir)


def get_services(request: Request) -> Services:
    return request.app.state.services
