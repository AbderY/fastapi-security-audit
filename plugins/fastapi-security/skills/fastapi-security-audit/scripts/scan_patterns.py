#!/usr/bin/env python3
"""Flag risky code patterns in a FastAPI project: CORS, JWT, TLS, SQL, secrets,
redirects, unsafe deserialisation and template escaping.

Python files are parsed with `ast` (nothing is imported or executed); HTML and
Jinja templates are matched with regular expressions. Each hit is a lead to
confirm by reading the code, not a verdict. Secret values are never printed.

Usage:
  python scan_patterns.py PROJECT_DIR [--format md|json] [--fail-on high|medium|low]
                          [--include-tests]

Exit code: 0; 1 with --fail-on when a hit at or above that severity exists;
2 on a usage error.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from datetime import date
from pathlib import Path

SKIP_DIRS = {
    ".git", ".hg", ".venv", "venv", "env", "node_modules", "__pycache__",
    "site-packages", "build", "dist", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".idea", ".vscode", ".claude",
}
TEST_DIRS = {"tests", "test"}
TEMPLATE_SUFFIXES = {".html", ".htm", ".jinja", ".jinja2", ".j2"}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

SECRET_NAME_RE = re.compile(
    r"secret|passw(or)?d|api_?key|private_?key|access_?key|auth_?token|client_?secret|"
    r"signing_?key|webhook_?secret|jwt_?key",
    re.I,
)
NOT_A_SECRET_RE = re.compile(
    r"(header|name|env|var|field|param|prefix|url|path|len|length|algorithm|alg|file|"
    r"label|type|id)$",
    re.I,
)
PLACEHOLDER_RE = re.compile(r"changeme|change-me|change_me|your|xxx|example|dummy|placeholder|<|>|\$\{|todo", re.I)
REDIRECT_INPUT_RE = re.compile(r"next|redirect|return|url|target|continue|dest|callback|goto", re.I)
HTTP_CLIENT_CALLS = {"get", "post", "put", "patch", "delete", "head", "request", "Client",
                     "AsyncClient", "urlopen"}

RULES = {
    "cors-wildcard-credentials": ("HIGH", "CORS allows any origin with credentials: any site can make authenticated calls."),
    "cors-wildcard": ("LOW", "CORS allows any origin. Fine for a public API without cookies; check it is not used with credentials."),
    "jwt-verify-disabled": ("HIGH", "JWT decoded without verifying the signature."),
    "jwt-none-algorithm": ("HIGH", "JWT accepts the 'none' algorithm."),
    "tls-verify-disabled": ("MEDIUM", "TLS certificate verification disabled on an outgoing call."),
    "sql-string-built": ("MEDIUM", "SQL built from a formatted string. Use bound parameters."),
    "hardcoded-secret": ("MEDIUM", "Secret-looking value hardcoded in the source. Move it to the environment or a secret store."),
    "secret-default-fallback": ("MEDIUM", "Secret read from the environment with a hardcoded fallback: a missing variable silently uses a known value."),
    "debug-enabled": ("LOW", "FastAPI debug mode enabled: tracebacks reach clients."),
    "open-redirect": ("MEDIUM", "Redirect target comes from a variable that looks user-controlled. Restrict it to same-origin paths."),
    "yaml-unsafe-load": ("MEDIUM", "yaml.load without a safe loader can build arbitrary objects."),
    "pickle-load": ("MEDIUM", "pickle.load(s) on data that may come from outside executes code."),
    "markup-formatted": ("MEDIUM", "Markup() built from a formatted string: the values are not escaped (XSS)."),
    "autoescape-disabled": ("MEDIUM", "Template autoescaping disabled (XSS)."),
    "shell-injection": ("MEDIUM", "Shell command built from non-constant input."),
    "template-var-in-script": ("MEDIUM", "Template value injected into JavaScript without |tojson (XSS)."),
    "template-safe-filter": ("LOW", "Value rendered with |safe, so not escaped. Confirm it never contains user input."),
    "template-autoescape-off": ("MEDIUM", "{% autoescape false %} block in a template (XSS)."),
}


def dotted(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def last(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def kw(call: ast.Call, name: str):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def is_false(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def is_true(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def is_formatted(node) -> bool:
    """f-string, "..." % x, "..." + x or "...".format(x) with at least one variable part."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        sides = (node.left, node.right)
        return any(isinstance(s, ast.Constant) and isinstance(s.value, str) for s in sides) \
            and not all(isinstance(s, ast.Constant) for s in sides)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return isinstance(node.func.value, ast.Constant) and bool(node.args or node.keywords)
    return False


def contains_star(node) -> bool:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(isinstance(e, ast.Constant) and e.value == "*" for e in node.elts)
    return isinstance(node, ast.Constant) and node.value == "*"


def looks_like_secret(name: str, value) -> bool:
    if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
        return False
    text = value.value
    return bool(SECRET_NAME_RE.search(name)) and not NOT_A_SECRET_RE.search(name) \
        and len(text) >= 8 and not PLACEHOLDER_RE.search(text) and len(set(text)) > 3


def mask(name: str) -> str:
    return f"{name} = '***'"


class PyVisitor(ast.NodeVisitor):
    def __init__(self, rel: str, lines: list):
        self.rel = rel
        self.lines = lines
        self.hits: list = []
        self.params: list = []  # parameter names of the enclosing functions

    def visit_FunctionDef(self, node):
        args = node.args
        names = {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs}
        self.params.append(names)
        self.generic_visit(node)
        self.params.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _user_controlled(self, expr) -> bool:
        """A redirect target taken from a parameter like `next`, or from the query string or form."""
        if isinstance(expr, ast.Constant):
            return False
        text = ast.unparse(expr)
        if re.search(r"query_params|\.form\b|\.args\b|referer", text, re.I):
            return True
        params = set().union(*self.params) if self.params else set()
        return any(isinstance(n, ast.Name) and n.id in params and REDIRECT_INPUT_RE.search(n.id)
                   for n in ast.walk(expr))

    def hit(self, rule: str, node, snippet: str | None = None):
        line = getattr(node, "lineno", 0)
        text = snippet if snippet is not None else (self.lines[line - 1].strip() if 0 < line <= len(self.lines) else "")
        severity, why = RULES[rule]
        self.hits.append({"rule": rule, "severity": severity, "file": self.rel, "line": line,
                          "snippet": text[:160], "why": why})

    def visit_Assign(self, node):
        for t in node.targets:
            name = dotted(t) if isinstance(t, (ast.Name, ast.Attribute)) else ""
            if name and looks_like_secret(last(name), node.value):
                self.hit("hardcoded-secret", node, mask(last(name)))
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        name = dotted(node.target) if isinstance(node.target, (ast.Name, ast.Attribute)) else ""
        if name and node.value is not None and looks_like_secret(last(name), node.value):
            self.hit("hardcoded-secret", node, mask(last(name)))
        self.generic_visit(node)

    def visit_Call(self, node):
        full = dotted(node.func)
        name = last(full) if full else ""
        self._cors(node, name, full)
        self._jwt(node, name, full)
        if is_false(kw(node, "verify")) and "jwt" not in full.lower() and (
                name in HTTP_CLIENT_CALLS or full.split(".")[0] in ("requests", "httpx", "session", "client")):
            self.hit("tls-verify-disabled", node)
        if name in ("execute", "executemany", "executescript", "exec_driver_sql", "text", "raw") \
                and node.args and is_formatted(node.args[0]):
            self.hit("sql-string-built", node)
        if name in ("getenv", "get") and full.endswith(("os.getenv", "environ.get")) and len(node.args) >= 2:
            key = node.args[0]
            if isinstance(key, ast.Constant) and isinstance(key.value, str) \
                    and looks_like_secret(key.value, node.args[1]):
                self.hit("secret-default-fallback", node, f"{full}('{key.value}', '***')")
        if name == "FastAPI" and is_true(kw(node, "debug")):
            self.hit("debug-enabled", node)
        if name == "RedirectResponse":
            target = node.args[0] if node.args else kw(node, "url")
            if target is not None and self._user_controlled(target):
                self.hit("open-redirect", node)
        if full.endswith("yaml.load"):
            loader = kw(node, "Loader")
            if loader is None and len(node.args) > 1:
                loader = node.args[1]
            if loader is None or "Safe" not in ast.unparse(loader):
                self.hit("yaml-unsafe-load", node)
        if full.endswith("yaml.unsafe_load"):
            self.hit("yaml-unsafe-load", node)
        if full in ("pickle.loads", "pickle.load", "cPickle.loads"):
            self.hit("pickle-load", node)
        if name == "Markup" and node.args and is_formatted(node.args[0]):
            self.hit("markup-formatted", node)
        if name in ("Environment", "Jinja2Templates") and is_false(kw(node, "autoescape")):
            self.hit("autoescape-disabled", node)
        if is_true(kw(node, "shell")) and node.args and not isinstance(node.args[0], ast.Constant):
            self.hit("shell-injection", node)
        if full == "os.system" and node.args and not isinstance(node.args[0], ast.Constant):
            self.hit("shell-injection", node)
        self.generic_visit(node)

    def _cors(self, node, name, full):
        target = None
        if name == "add_middleware" and node.args and last(dotted(node.args[0])) == "CORSMiddleware":
            target = node
        elif name == "CORSMiddleware":
            target = node
        if target is None:
            return
        origins = kw(target, "allow_origins")
        regex = kw(target, "allow_origin_regex")
        wildcard = (origins is not None and contains_star(origins)) or (
            isinstance(regex, ast.Constant) and regex.value in (".*", "^.*$", ".+", "^.+$", "https?://.*"))
        if wildcard and is_true(kw(target, "allow_credentials")):
            self.hit("cors-wildcard-credentials", node)
        elif wildcard:
            self.hit("cors-wildcard", node)

    def _jwt(self, node, name, full):
        if name not in ("decode", "encode") or "jwt" not in full.lower() and "jose" not in full.lower():
            return
        options = kw(node, "options")
        if isinstance(options, ast.Dict):
            for k, v in zip(options.keys, options.values):
                if isinstance(k, ast.Constant) and k.value == "verify_signature" and is_false(v):
                    self.hit("jwt-verify-disabled", node)
        if name == "decode" and is_false(kw(node, "verify")):
            self.hit("jwt-verify-disabled", node)
        for key in ("algorithms", "algorithm"):
            val = kw(node, key)
            values = val.elts if isinstance(val, (ast.List, ast.Tuple)) else [val] if val is not None else []
            if any(isinstance(v, ast.Constant) and str(v.value).lower() == "none" for v in values):
                self.hit("jwt-none-algorithm", node)


SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>", re.I | re.S)
EXPR_RE = re.compile(r"\{\{(.*?)\}\}", re.S)
SAFE_RE = re.compile(r"\|\s*safe\b")
# t("key"), url_for('static', path='x'), studio('/'): only literals, so developer-controlled.
LITERAL_CALL_RE = re.compile(
    r"""^\s*[\w.]+\(\s*(?:(?:\w+\s*=\s*)?(?:'[^']*'|"[^"]*"|\d+)\s*,?\s*)*\)\s*$"""
)
AUTOESCAPE_OFF_RE = re.compile(r"\{%-?\s*autoescape\s+false\s*-?%\}", re.I)


JINJA_WORDS = {"if", "else", "not", "and", "or", "is", "in", "loop", "last", "first", "index",
               "index0", "length", "true", "false", "none", "True", "False", "None"}


def only_literals(expr: str) -> bool:
    """{{ ',' if not loop.last }}: literals and loop helpers only."""
    stripped = re.sub(r"'[^']*'|\"[^\"]*\"|\d+", " ", expr)
    return set(re.findall(r"[A-Za-z_]\w*", stripped)) <= JINJA_WORDS


def scan_template(rel: str, text: str) -> list:
    hits = []

    def add(rule, pos, snippet):
        severity, why = RULES[rule]
        line = text.count("\n", 0, pos) + 1
        hits.append({"rule": rule, "severity": severity, "file": rel, "line": line,
                     "snippet": " ".join(snippet.split())[:160], "why": why})

    in_script = []
    for block in SCRIPT_RE.finditer(text):
        in_script.append((block.start(1), block.end(1)))
        for expr in EXPR_RE.finditer(block.group(1)):
            body = expr.group(1)
            if "tojson" in body or LITERAL_CALL_RE.match(body) or only_literals(body):
                continue
            start = block.start(1) + expr.start()
            before = text[start - 1] if start > 0 else ""
            if SAFE_RE.search(body) or before not in ("'", '"', "`"):
                add("template-var-in-script", start, expr.group(0))
    for expr in EXPR_RE.finditer(text):
        if any(a <= expr.start() < b for a, b in in_script):
            continue
        if SAFE_RE.search(expr.group(1)):
            add("template-safe-filter", expr.start(), expr.group(0))
    for m in AUTOESCAPE_OFF_RE.finditer(text):
        add("template-autoescape-off", m.start(), m.group(0))
    return hits


def scan(root: Path, include_tests: bool = False) -> dict:
    hits, errors, files = [], [], 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts[:-1]
        if any(p in SKIP_DIRS for p in rel_parts):
            continue
        if not include_tests and any(p in TEST_DIRS for p in rel_parts):
            continue
        rel = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        if suffix == ".py":
            text = path.read_text(encoding="utf-8", errors="replace")
            try:
                tree = ast.parse(text, filename=str(path))
            except SyntaxError as exc:
                errors.append(f"{rel}: {exc.msg} (line {exc.lineno})")
                continue
            visitor = PyVisitor(rel, text.splitlines())
            visitor.visit(tree)
            hits.extend(visitor.hits)
            files += 1
        elif suffix in TEMPLATE_SUFFIXES:
            hits.extend(scan_template(rel, path.read_text(encoding="utf-8", errors="replace")))
            files += 1
    hits.sort(key=lambda h: (SEVERITY_ORDER[h["severity"]], h["file"], h["line"]))
    return {"root": str(root), "date": date.today().isoformat(), "files": files,
            "parse_errors": errors, "hits": hits}


def to_markdown(result: dict) -> str:
    hits = result["hits"]
    main = [h for h in hits if h["severity"] != "LOW"]
    low = [h for h in hits if h["severity"] == "LOW"]
    lines = ["# Code pattern scan", "",
             f"Project `{result['root']}` · {result['files']} files · {result['date']}", "",
             f"## High and medium hits ({len(main)})", ""]
    if main:
        lines += ["| # | Severity | Rule | Where | Code | Why |", "| --- | --- | --- | --- | --- | --- |"]
        for i, h in enumerate(main, 1):
            code = h["snippet"].replace("|", "\\|").replace("`", "'")
            why = h["why"].replace("|", "\\|")
            lines.append(f"| {i} | {h['severity']} | {h['rule']} | `{h['file']}:{h['line']}` | `{code}` | {why} |")
    else:
        lines.append("None.")
    if low:
        lines += ["", f"## Low hits ({len(low)})", ""]
        for rule in sorted({h["rule"] for h in low}):
            items = [h for h in low if h["rule"] == rule]
            files = sorted({h["file"] for h in items})
            shown = ", ".join(f"`{f}`" for f in files[:8]) + (f" and {len(files) - 8} more" if len(files) > 8 else "")
            lines.append(f"- **{rule}** ({len(items)} in {len(files)} files): {RULES[rule][1]} Files: {shown}.")
    if result["parse_errors"]:
        lines += ["", "Files that could not be parsed: " + "; ".join(result["parse_errors"]) + "."]
    lines += ["", "Pattern matching finds common mistakes only. A clean result is not a clean bill of health."]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Flag risky code patterns in a FastAPI project.")
    ap.add_argument("project", help="project root to scan")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    ap.add_argument("--fail-on", choices=("high", "medium", "low"))
    ap.add_argument("--include-tests", action="store_true")
    args = ap.parse_args(argv)
    root = Path(args.project).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    result = scan(root, args.include_tests)
    sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False) if args.format == "json" else to_markdown(result))
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on.upper()]
        if any(SEVERITY_ORDER[h["severity"]] <= threshold for h in result["hits"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
