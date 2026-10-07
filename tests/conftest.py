import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "fastapi-security" / "skills" / "fastapi-security-audit" / "scripts"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def scan_routes():
    return load("scan_routes")


@pytest.fixture(scope="session")
def scan_patterns():
    return load("scan_patterns")


@pytest.fixture(scope="session")
def vuln_routes(scan_routes):
    return scan_routes.analyse(scan_routes.scan_project(FIXTURES / "vuln_app"), set())


@pytest.fixture(scope="session")
def safe_routes(scan_routes):
    return scan_routes.analyse(scan_routes.scan_project(FIXTURES / "safe_app"), set())
