import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CONTRACT = ROOT / "contracts" / "report_data.example.json"
NARRATIVE = ROOT / "contracts" / "narrative.example.json"


@pytest.fixture
def data():
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


@pytest.fixture
def narrative():
    return json.loads(NARRATIVE.read_text(encoding="utf-8"))


@pytest.fixture
def clone():
    return copy.deepcopy
