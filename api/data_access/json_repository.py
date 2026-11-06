"""Read-only access to the JSON demo datasets.

Files are parsed and validated with Pydantic on first use and cached for the
lifetime of the repository. Any problem (missing file, malformed JSON, schema
mismatch, broken cross-references) raises DataLoadError naming the file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, TypeVar

from pydantic import BaseModel, TypeAdapter, ValidationError

import config
from api.errors import DataLoadError
from api.schemas.assets import Asset
from api.schemas.auth_logs import AuthEvent
from api.schemas.findings import Finding
from api.schemas.inventory import DataInventoryRecord
from api.schemas.organizations import Organization

M = TypeVar("M", bound=BaseModel)


class JsonRepository:
    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = Path(data_dir or config.DATA_DIR)
        self._cache: Dict[str, Any] = {}

    # -- low level -----------------------------------------------------------

    def _path(self, key: str) -> Path:
        return self.data_dir / config.DATA_FILES[key]

    def read_raw(self, key: str) -> Any:
        path = self._path(key)
        if not path.exists():
            raise DataLoadError(f"Data file not found: {path.name}")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise DataLoadError(f"Invalid JSON in {path.name}: line {exc.lineno}, column {exc.colno}: {exc.msg}")

    def _load_list(self, key: str, model: Type[M]) -> List[M]:
        if key not in self._cache:
            raw = self.read_raw(key)
            if not isinstance(raw, list):
                raise DataLoadError(f"{config.DATA_FILES[key]} must contain a JSON array")
            try:
                self._cache[key] = TypeAdapter(List[model]).validate_python(raw)
            except ValidationError as exc:
                first = exc.errors()[0]
                location = ".".join(str(p) for p in first["loc"])
                raise DataLoadError(
                    f"{config.DATA_FILES[key]} failed validation at {location}: {first['msg']}"
                ) from exc
        return self._cache[key]

    # -- datasets --------------------------------------------------------------

    def organizations(self) -> List[Organization]:
        return self._load_list("organizations", Organization)

    def assets(self) -> List[Asset]:
        return self._load_list("assets", Asset)

    def findings(self) -> List[Finding]:
        return self._load_list("findings", Finding)

    def auth_logs(self) -> List[AuthEvent]:
        return self._load_list("auth_logs", AuthEvent)

    def data_inventory(self) -> List[DataInventoryRecord]:
        return self._load_list("data_inventory", DataInventoryRecord)

    def anomaly_snapshot(self) -> Dict[str, Any]:
        if "anomalies" not in self._cache:
            raw = self.read_raw("anomalies")
            if not isinstance(raw, dict) or "anomalies" not in raw:
                raise DataLoadError(f"{config.DATA_FILES['anomalies']} must be an object with an 'anomalies' list")
            self._cache["anomalies"] = raw
        return self._cache["anomalies"]

    # -- per-organization helpers -----------------------------------------------

    def organization(self, organization_id: str) -> Optional[Organization]:
        return next((o for o in self.organizations() if o.organization_id == organization_id), None)

    def assets_for(self, organization_id: str) -> List[Asset]:
        return [a for a in self.assets() if a.organization_id == organization_id]

    def findings_for(self, organization_id: str) -> List[Finding]:
        return [f for f in self.findings() if f.organization_id == organization_id]

    def auth_logs_for(self, organization_id: str) -> List[AuthEvent]:
        return [e for e in self.auth_logs() if e.organization_id == organization_id]

    def inventory_for(self, organization_id: str) -> List[DataInventoryRecord]:
        return [r for r in self.data_inventory() if r.organization_id == organization_id]

    # -- integrity -------------------------------------------------------------

    def integrity_errors(self) -> List[str]:
        """Cross-file reference problems; an empty list means the dataset is consistent."""
        errors: List[str] = []
        org_ids = {o.organization_id for o in self.organizations()}
        assets = {a.asset_id: a for a in self.assets()}
        event_ids = {e.event_id for e in self.auth_logs()}

        def check(kind: str, record_id: str, org_id: str, asset_id: Optional[str]) -> None:
            if org_id not in org_ids:
                errors.append(f"{kind} {record_id}: unknown organization {org_id}")
            if asset_id is None:
                return
            if asset_id not in assets:
                errors.append(f"{kind} {record_id}: unknown asset {asset_id}")
            elif assets[asset_id].organization_id != org_id:
                errors.append(f"{kind} {record_id}: asset {asset_id} belongs to another organization")

        for asset in assets.values():
            check("asset", asset.asset_id, asset.organization_id, None)
        for f in self.findings():
            check("finding", f.finding_id, f.organization_id, f.asset_id)
            if assets.get(f.asset_id) and assets[f.asset_id].service != f.service:
                errors.append(f"finding {f.finding_id}: service does not match asset {f.asset_id}")
        for r in self.data_inventory():
            check("inventory", r.asset_id, r.organization_id, r.asset_id)
        for e in self.auth_logs():
            check("auth event", e.event_id, e.organization_id, e.asset_id)
        if len(event_ids) != len(self.auth_logs()):
            errors.append("auth_logs.json contains duplicate event IDs")
        for a in self.anomaly_snapshot()["anomalies"]:
            check("anomaly", a["anomaly_id"], a["organization_id"], a.get("asset_id"))
            missing = [i for i in a["supporting_event_ids"] if i not in event_ids]
            if missing:
                errors.append(f"anomaly {a['anomaly_id']}: unknown events {missing}")
        return errors
