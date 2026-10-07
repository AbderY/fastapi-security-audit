from conftest import FIXTURES


def route(result, method, path):
    matches = [r for r in result["routes"] if r["method"] == method and r["path"] == path]
    assert matches, f"{method} {path} not found in {[(r['method'], r['path']) for r in result['routes']]}"
    return matches[0]


def verdict(result, method, path):
    for item in result["findings"] + result["reviews"]:
        if item["method"] == method and item["path"] == path:
            return item.get("severity") or item.get("review")
    return None


def test_prefixes_are_resolved_through_routers_and_includes(vuln_routes):
    paths = {(r["method"], r["path"]) for r in vuln_routes["routes"]}
    assert ("GET", "/admin/users") in paths            # include_router(prefix=...)
    assert ("GET", "/items/{item_id}") in paths        # APIRouter(prefix=CONSTANT)
    assert ("POST", "/internal/rebuild") in paths
    assert ("GET", "/v2/me") in paths


def test_unprotected_admin_routes_are_high(vuln_routes):
    assert verdict(vuln_routes, "GET", "/admin/users") == "HIGH"
    assert verdict(vuln_routes, "DELETE", "/admin/users/{user_id}") == "HIGH"
    assert verdict(vuln_routes, "POST", "/sync") == "HIGH"


def test_include_level_dependency_protects_router(vuln_routes):
    r = route(vuln_routes, "POST", "/internal/rebuild")
    assert r["status"] == "dependency"
    assert "require_admin" in r["auth"]
    assert verdict(vuln_routes, "POST", "/internal/rebuild") is None


def test_transitive_and_annotated_dependencies(vuln_routes):
    assert route(vuln_routes, "POST", "/items")["status"] == "dependency"
    assert route(vuln_routes, "GET", "/v2/me")["status"] == "dependency"


def test_admin_path_without_role_check_is_medium(vuln_routes):
    assert verdict(vuln_routes, "GET", "/v2/admin/stats") == "MEDIUM"


def test_in_body_check_through_tainted_helper(vuln_routes):
    r = route(vuln_routes, "PUT", "/items/{item_id}")
    assert r["status"] == "in-body"
    assert verdict(vuln_routes, "PUT", "/items/{item_id}") is None


def test_optional_auth_on_write_is_medium(vuln_routes):
    assert route(vuln_routes, "PATCH", "/items/{item_id}/share")["status"] == "optional"
    assert verdict(vuln_routes, "PATCH", "/items/{item_id}/share") == "MEDIUM"


def test_credential_without_check(vuln_routes):
    assert verdict(vuln_routes, "POST", "/items/import") == "HIGH"
    # jwt.decode counts as a check here; scan_patterns flags that it skips the signature.
    assert route(vuln_routes, "GET", "/debug/token")["status"] == "in-body"


def test_review_lists(vuln_routes):
    assert verdict(vuln_routes, "POST", "/items/webhook") == "public-write"
    assert verdict(vuln_routes, "GET", "/items/{item_id}") == "public-read"
    assert verdict(vuln_routes, "GET", "/items/all") == "public-read"


def test_disabled_route_is_not_flagged(vuln_routes):
    assert route(vuln_routes, "POST", "/items/legacy-sync")["status"] == "disabled"
    assert verdict(vuln_routes, "POST", "/items/legacy-sync") is None


def test_safe_app_has_no_findings(safe_routes):
    assert safe_routes["findings"] == []
    assert route(safe_routes, "DELETE", "/admin/users/{user_id}")["status"] == "dependency"
    assert route(safe_routes, "GET", "/notes/{note_id}")["status"] == "dependency"


def test_explicit_auth_deps_limit_guessing(scan_routes):
    scan = scan_routes.scan_project(FIXTURES / "vuln_app")
    result = scan_routes.analyse(scan, {"require_admin"})
    # get_current_user still counts: it reads the Authorization header and raises 401.
    assert route(result, "POST", "/items")["status"] == "dependency"


def test_cli_markdown_and_fail_on(scan_routes, capsys):
    code = scan_routes.main([str(FIXTURES / "vuln_app"), "--fail-on", "high"])
    out = capsys.readouterr().out
    assert code == 1
    assert "# FastAPI route scan" in out and "HIGH" in out
    assert scan_routes.main([str(FIXTURES / "safe_app"), "--fail-on", "medium"]) == 0


def test_middleware_with_path_condition(tmp_path, scan_routes):
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI, Request\n"
        "from fastapi.responses import RedirectResponse\n"
        "from starlette.middleware.base import BaseHTTPMiddleware\n"
        "class StudioAuth(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request: Request, call_next):\n"
        "        if request.url.path.startswith('/studio/'):\n"
        "            if not request.cookies.get('session'):\n"
        "                return RedirectResponse(url='/login')\n"
        "        return await call_next(request)\n"
        "app = FastAPI()\n"
        "app.add_middleware(StudioAuth)\n"
        "@app.get('/studio/users')\n"
        "def studio_users():\n"
        "    return []\n",
        encoding="utf-8",
    )
    result = scan_routes.analyse(scan_routes.scan_project(tmp_path), set())
    assert route(result, "GET", "/studio/users")["status"] == "middleware"
    assert result["findings"] == []
    assert result["middlewares"][0]["prefixes"] == ["/studio/"]
