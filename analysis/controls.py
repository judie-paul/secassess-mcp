"""Security-control gap detection used in asset detail."""

from __future__ import annotations

from typing import List, Sequence

import config
from api.schemas.assets import Asset
from api.schemas.findings import Finding


def failed_controls(asset: Asset, findings: Sequence[Finding]) -> List[str]:
    """Controls recorded as missing on the asset, plus those implied by active finding categories."""
    controls = asset.security_controls.model_dump()
    failed = {name for name, state in controls.items() if state is False}
    for finding in findings:
        mapped = config.CONTROL_FINDING_CATEGORY_MAP.get(finding.category)
        if mapped:
            failed.add(mapped)
    return sorted(failed)
