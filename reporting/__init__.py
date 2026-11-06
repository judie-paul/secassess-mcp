"""Part B: turns backend risk data (the contract JSON) into an assessment deck."""

from .build_pptx import build_report
from .contract import ContractError, load_contract, validate_contract

__all__ = ["build_report", "load_contract", "validate_contract", "ContractError"]
