from conftest import FIXTURES


def rules(result):
    return [(h["rule"], h["file"]) for h in result["hits"]]


def test_python_rules(scan_patterns):
    result = scan_patterns.scan(FIXTURES / "vuln_app")
    found = {r for r, _ in rules(result)}
    for rule in ("cors-wildcard-credentials", "jwt-verify-disabled", "tls-verify-disabled",
                 "sql-string-built", "hardcoded-secret", "secret-default-fallback",
                 "debug-enabled", "open-redirect"):
        assert rule in found, rule


def test_secret_values_are_never_printed(scan_patterns):
    result = scan_patterns.scan(FIXTURES / "vuln_app")
    text = str(result)
    assert "s3cr3t-hardcoded-value-123" not in text
    assert "fallback-signing-key-42" not in text


def test_template_rules(scan_patterns):
    result = scan_patterns.scan(FIXTURES / "vuln_app")
    script_hits = [h for h in result["hits"] if h["rule"] == "template-var-in-script"]
    snippets = " ".join(h["snippet"] for h in script_hits)
    assert "scenario_json" in snippets      # |safe inside <script>
    assert "owner_name" in snippets         # bare variable inside <script>
    assert "tojson" not in snippets         # |tojson is the fix
    assert "t('scenario.label')" not in snippets  # literal-only call
    assert "loop.last" not in snippets      # literals and loop helpers only
    assert any(h["rule"] == "template-safe-filter" and "bio" in h["snippet"] for h in result["hits"])


def test_safe_app_is_clean(scan_patterns):
    assert scan_patterns.scan(FIXTURES / "safe_app")["hits"] == []


def test_yaml_and_pickle(tmp_path, scan_patterns):
    (tmp_path / "loader.py").write_text(
        "import pickle, yaml\n"
        "a = yaml.load(data)\n"
        "b = yaml.load(data, Loader=yaml.SafeLoader)\n"
        "c = pickle.loads(blob)\n",
        encoding="utf-8",
    )
    hits = scan_patterns.scan(tmp_path)["hits"]
    assert [h["line"] for h in hits if h["rule"] == "yaml-unsafe-load"] == [2]
    assert [h["line"] for h in hits if h["rule"] == "pickle-load"] == [4]


def test_constant_redirect_is_not_flagged(tmp_path, scan_patterns):
    (tmp_path / "views.py").write_text(
        "from fastapi.responses import RedirectResponse\n"
        "def go(next: str):\n"
        "    login_url = '/login'\n"
        "    if not next.startswith('/'):\n"
        "        return RedirectResponse(url=login_url)\n"
        "    return RedirectResponse(next)\n",
        encoding="utf-8",
    )
    hits = [h for h in scan_patterns.scan(tmp_path)["hits"] if h["rule"] == "open-redirect"]
    assert [h["line"] for h in hits] == [6]
