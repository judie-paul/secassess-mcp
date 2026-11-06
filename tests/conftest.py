import copy
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CONTRACT = ROOT / "contracts" / "report_data.example.json"
NARRATIVE = ROOT / "contracts" / "narrative.example.json"

# --- Part B (reporting) fixtures -------------------------------------------------


@pytest.fixture
def data():
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


@pytest.fixture
def narrative():
    return json.loads(NARRATIVE.read_text(encoding="utf-8"))


@pytest.fixture
def clone():
    return copy.deepcopy


# --- Part A (backend / MCP) fixtures ---------------------------------------------

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import config  # noqa: E402
from api.dependencies import Services  # noqa: E402
from api.main import create_app  # noqa: E402
from mcp_server.client import BackendClient  # noqa: E402
from mcp_server.server import create_server  # noqa: E402

ORG = "org-001"
SMALL_ORG = "org-002"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def reports_dir(tmp_path: Path) -> Path:
    return tmp_path / "reports"


@pytest.fixture
def app(reports_dir):
    return create_app(reports_dir=reports_dir)


@pytest.fixture
def client(app) -> TestClient:
    return TestClient(app)


@pytest.fixture
def services(reports_dir) -> Services:
    return Services(reports_dir=reports_dir)


@pytest.fixture
def data_copy(tmp_path: Path) -> Path:
    """A writable copy of the demo data for tests that corrupt files."""
    target = tmp_path / "data"
    shutil.copytree(config.DATA_DIR, target, ignore=shutil.ignore_patterns("reports", "__pycache__"))
    return target


@pytest.fixture
def mcp(app):
    transport = httpx.ASGITransport(app=app)
    return create_server(BackendClient("http://testserver", transport=transport))
