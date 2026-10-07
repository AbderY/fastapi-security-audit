import json
import os
import subprocess
import sys

from conftest import FIXTURES, SCRIPTS

HOOK = SCRIPTS / "route_guard_hook.py"


def run_hook(project, edited):
    payload = json.dumps({"tool_input": {"file_path": str(edited)}})
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(project)}
    return subprocess.run([sys.executable, str(HOOK)], input=payload, capture_output=True,
                          text=True, env=env)


def test_hook_flags_unprotected_routes_in_edited_file():
    project = FIXTURES / "vuln_app"
    proc = run_hook(project, project / "app" / "routers" / "admin.py")
    assert proc.returncode == 2
    assert "DELETE /admin/users/{user_id}" in proc.stderr


def test_hook_is_silent_on_protected_code():
    project = FIXTURES / "vuln_app"
    assert run_hook(project, project / "app" / "routers" / "protected.py").returncode == 0
    assert run_hook(FIXTURES / "safe_app", FIXTURES / "safe_app" / "main.py").returncode == 0


def test_hook_ignores_non_python_files():
    project = FIXTURES / "vuln_app"
    assert run_hook(project, project / "app" / "templates" / "scenario.html").returncode == 0
