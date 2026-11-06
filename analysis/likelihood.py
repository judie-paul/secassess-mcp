"""Likelihood rule (contracts/report_data.example.json -> scoring_model.likelihood_rule).

    likelihood = LIKELIHOOD_BY_EXPOSURE[exposure]
                 + LIKELIHOOD_ANOMALOUS_BONUS if the asset had anomalous access
                 capped at LIKELIHOOD_MAX

With the default config: public = 4, internal = 2; +1 if anomalous access; max 5.
"""

from __future__ import annotations

import config
from api.schemas.risks import LikelihoodDetail


def compute_likelihood(exposure: str, anomalous_access: bool) -> LikelihoodDetail:
    base = config.LIKELIHOOD_BY_EXPOSURE[exposure]
    bonus = config.LIKELIHOOD_ANOMALOUS_BONUS if anomalous_access else 0
    return LikelihoodDetail(
        rule=config.likelihood_rule_text(),
        exposure=exposure,
        base=base,
        anomalous_access=anomalous_access,
        anomalous_bonus=bonus,
        score=min(base + bonus, config.LIKELIHOOD_MAX),
    )
