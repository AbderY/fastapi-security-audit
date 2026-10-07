#!/usr/bin/env python3
"""Inventory FastAPI routes and the evidence that each one is authenticated.

Static analysis only: the project is parsed with `ast`. Nothing is imported or
executed, so the scan runs on any checkout without installing the project's
dependencies.

For every route it reports the method, the full path (router and
include_router prefixes resolved), the handler location and how the route is
protected:

  dependency  an auth dependency at route, router, include_router or app level
  in-body     a credential is read and checked inside the handler
  optional    only optional auth was found, so anonymous callers get through
  none        no authentication evidence

It then flags the routes that deserve a human look. Findings are leads, not
verdicts: confirm each one by reading the handler.

Usage:
  python scan_routes.py PROJECT_DIR [--auth-deps NAMES] [--format md|json]
                        [--fail-on high|medium|low] [--include-tests]

Exit code: 0; 1 with --fail-on when a finding at or above that severity exists;
2 on a usage error.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

SKIP_DIRS = {
    ".git", ".hg", ".venv", "venv", "env", "node_modules", "__pycache__",
    "site-packages", "build", "dist", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".idea", ".vscode", ".claude",
}
TEST_DIRS = {"tests", "test"}

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# A dependency or helper whose name looks like authentication. Used only when
# the function's own definition is not in the project (library helpers, classes).
AUTH_NAME_RE = re.compile(
    r"auth|admin|user|current|token|jwt|session|login|verify|permission|perm|role|"
    r"guard|require|bearer|oauth|api_?key|security|principal|identity|owner|member|"
    r"manager|author|scope|credential",
    re.I,
)
OPTIONAL_RE = re.compile(r"optional|try_|_try|maybe|or_none|if_present|soft", re.I)
ROLE_RE = re.compile(r"admin|role|perm|staff|superuser|scope|owner|manager|privilege|rbac", re.I)
CRED_PARAM_RE = re.compile(
    r"^(authorization|auth|token|access_token|api_?key|x_api_key|session|"
    r"cookie|jwt|bearer|credentials?)$",
    re.I,
)
SECURITY_SCHEMES = {
    "OAuth2PasswordBearer", "OAuth2AuthorizationCodeBearer", "OAuth2", "HTTPBearer",
    "HTTPBasic", "HTTPDigest", "APIKeyHeader", "APIKeyCookie", "APIKeyQuery",
    "OpenIdConnect",
}
PUBLIC_HINT_RE = re.compile(
    r"login|logout|sign_?in|sign_?up|register|registration|otp|verify|forgot|"
    r"reset_?password|password_?reset|refresh|webhook|callback|checkout|contact|lead|"
    r"feedback|subscribe|newsletter|track|beacon|health|ping|public|capture|consent|"
    r"waitlist|early_?adopter|validate|check_?email",
    re.I,
)
# Path words that make an unauthenticated route worth a look. Matched on whole
# path segments, so "catalog" does not match "log".
CRITICAL_WORDS = {
    "admin", "internal", "debug", "users", "accounts", "customers", "clients", "leads",
    "invoices", "revenue", "revenues", "logs", "secrets", "credentials", "backup",
    "backups", "dump", "impersonate", "export", "exports", "audit", "members",
    "employees", "payroll",
}
SENSITIVE_WORDS = {
    "user", "account", "customer", "client", "lead", "invoice", "billing", "analytics",
    "stats", "statistics", "report", "reports", "settings", "config", "download",
    "downloads", "pdf", "log", "secret", "keys", "tokens", "backup",
}
BULK_FUNC_RE = re.compile(r"(^|_)(list|all|export|dump|search)(_|$)", re.I)
ID_PARAM_RE = re.compile(r"\{[^}]*(id|uuid|key|token|code)[^}:]*(:[^}]*)?\}", re.I)
RESPONSES = {"RedirectResponse", "JSONResponse", "Response", "PlainTextResponse", "HTMLResponse"}


def path_words(path: str) -> set:
    return {w for w in re.split(r"[/\-_.{}:]+", path.lower()) if w}


# --------------------------------------------------------------------------- data

@dataclass
class Dep:
    name: str
    level: str  # route, router, include, app
    where: str  # file:line


@dataclass
class RouterDef:
    module: str
    var: str
    kind: str  # "router" or "app"
    prefix: str
    deps: list
    file: str
    line: int


@dataclass
class Include:
    module: str
    parent_expr: str
    child_expr: str
    prefix: str
    deps: list
    file: str
    line: int


@dataclass
class FuncInfo:
    deps: list
    has_cred: bool
    body_auth: bool
    cred_calls: list  # functions the credential is handed to


@dataclass
class RouteDef:
    module: str
    owner_expr: str
    methods: list
    path: str
    func: str
    file: str
    line: int
    deps: list
    cred_params: list
    cred_calls: list  # functions the credential or request is handed to
    raises_401: bool
    reads_request: bool
    disabled: bool  # the handler only raises (deprecated or switched-off route)


@dataclass
class Scan:
    root: Path
    files: int = 0
    parse_errors: list = field(default_factory=list)
    routers: dict = field(default_factory=dict)  # (module, var) -> RouterDef
    includes: list = field(default_factory=list)
    routes: list = field(default_factory=list)
    funcs: dict = field(default_factory=dict)  # name -> [FuncInfo]
    schemes: dict = field(default_factory=dict)  # var name -> optional (bool)
    parsers: dict = field(default_factory=dict)  # module -> ModuleParser
    middlewares: dict = field(default_factory=dict)  # name -> Middleware
    registered_middlewares: set = field(default_factory=set)


@dataclass
class Middleware:
    name: str
    file: str
    line: int
    prefixes: list
    exact: list
    decorator: bool  # @app.middleware("http"), registered by definition


# ------------------------------------------------------------------ ast helpers

def dotted(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def last(name: str | None) -> str:
    return name.rsplit(".", 1)[-1] if name else ""


def call_name(node) -> str:
    return last(dotted(node.func)) if isinstance(node, ast.Call) else ""


def const_str(node, consts: dict) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in consts:
        return consts[node.id]
    return None


def kw(call: ast.Call, name: str):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def annotation_name(ann) -> str | None:
    if ann is None:
        return None
    if isinstance(ann, ast.Subscript):
        return annotation_name(ann.value)
    return last(dotted(ann)) or None


def dep_from_call(call, annotation=None) -> str | None:
    """Name of the dependency in Depends(x) / Security(x); None if not one."""
    if not isinstance(call, ast.Call) or call_name(call) not in ("Depends", "Security"):
        return None
    target = call.args[0] if call.args else kw(call, "dependency")
    if target is None:  # Depends() resolves to the annotated class
        return annotation_name(annotation)
    name = dotted(target)
    if name:
        return last(name)
    if isinstance(target, ast.Call):  # Depends(RoleChecker("admin"))
        return call_name(target) or None
    return None


def deps_from_list(node) -> list:
    out = []
    if isinstance(node, (ast.List, ast.Tuple)):
        for elt in node.elts:
            name = dep_from_call(elt)
            if name:
                out.append(name)
    return out


def deps_in(markers: list) -> bool:
    return any(dep_from_call(m) for m in markers)


def annotated_parts(ann) -> list | None:
    if isinstance(ann, ast.Subscript) and last(dotted(ann.value)) == "Annotated":
        sl = ann.slice
        return list(sl.elts) if isinstance(sl, ast.Tuple) else [sl]
    return None


def is_cred_marker(call: ast.Call, param: str) -> bool:
    """Header(...) / Cookie(...) carrying a credential."""
    if call_name(call) not in ("Header", "Cookie"):
        return False
    alias = kw(call, "alias")
    alias_name = alias.value if isinstance(alias, ast.Constant) and isinstance(alias.value, str) else None
    candidates = [param] + ([alias_name.replace("-", "_")] if alias_name else [])
    return any(CRED_PARAM_RE.match(c) for c in candidates)


def status_is_401_403(node) -> bool:
    if isinstance(node, ast.Constant) and node.value in (401, 403):
        return True
    name = dotted(node) or ""
    return any(tok in name for tok in ("401", "403", "UNAUTHORIZED", "FORBIDDEN"))


def raises_401_403(exc) -> bool:
    if not isinstance(exc, ast.Call):
        return False
    status = kw(exc, "status_code")
    if status is None and exc.args:
        status = exc.args[0]
    return status is not None and status_is_401_403(status)


def refers_to(expr, names: set) -> bool:
    return any(isinstance(n, ast.Name) and n.id in names for n in ast.walk(expr))


# --------------------------------------------------------------- module parser

class ModuleParser:
    def __init__(self, scan: Scan, path: Path, module: str, tree: ast.Module):
        self.scan = scan
        self.path = path
        self.module = module
        self.tree = tree
        self.rel = path.relative_to(scan.root).as_posix()
        self.imports_module: dict = {}  # alias -> module
        self.imports_symbol: dict = {}  # alias -> (module, symbol)
        self.consts: dict = {}  # module-level string constants
        self.dep_aliases: dict = {}  # CurrentUser = Annotated[..., Depends(x)]
        self.is_package = path.name == "__init__.py"

    def where(self, node) -> str:
        return f"{self.rel}:{getattr(node, 'lineno', 0)}"

    def resolve_relative(self, level: int, mod: str | None) -> str:
        parts = self.module.split(".") if self.module else []
        if not self.is_package and parts:
            parts = parts[:-1]
        if level > 1:
            parts = parts[: len(parts) - (level - 1)] if level - 1 <= len(parts) else []
        base = ".".join(parts)
        if mod:
            base = f"{base}.{mod}" if base else mod
        return base

    def parse(self):
        for node in self.tree.body:
            self._top_level(node)
        for node in ast.walk(self.tree):
            # Routers and apps built inside functions (create_app factories).
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) \
                    and call_name(node.value) in ("APIRouter", "FastAPI"):
                for t in node.targets:
                    if isinstance(t, ast.Name) and (self.module, t.id) not in self.scan.routers:
                        self._assignment(t.id, node.value, node)
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._function(node)
                if any(isinstance(d, ast.Call) and call_name(d) == "middleware" for d in node.decorator_list):
                    self._middleware(node.name, node, decorator=True)
            elif isinstance(node, ast.ClassDef):
                dispatch = next((b for b in node.body if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef))
                                 and b.name in ("dispatch", "__call__")), None)
                if dispatch and (any("Middleware" in (dotted(b) or "") for b in node.bases)
                                 or "Middleware" in node.name):
                    self._middleware(node.name, dispatch, decorator=False)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "include_router" and node.args:
                    self._include(node)
                elif node.func.attr == "add_middleware" and node.args:
                    self.scan.registered_middlewares.add(last(dotted(node.args[0])))

    def _middleware(self, name: str, fn, decorator: bool):
        """Record a middleware that reads a credential and turns callers away."""
        reads_cred = denies = False
        prefixes, exact = [], []
        for node in ast.walk(fn):
            if isinstance(node, ast.Attribute) and node.attr == "cookies":
                reads_cred = True
            if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                    and node.value.lower() in ("authorization", "x-api-key", "x-auth-token"):
                reads_cred = True
            if isinstance(node, ast.Raise) and node.exc is not None and raises_401_403(node.exc):
                denies = True
            if isinstance(node, ast.Call):
                cname = call_name(node)
                if cname in RESPONSES:
                    status = kw(node, "status_code")
                    target = node.args[0] if node.args else kw(node, "url")
                    target_text = ast.unparse(target) if target is not None else ""
                    if (status is not None and status_is_401_403(status)) or \
                            (cname == "RedirectResponse" and "login" in target_text.lower()):
                        denies = True
                if cname == "startswith" and node.args:
                    arg = node.args[0]
                    values = arg.elts if isinstance(arg, ast.Tuple) else [arg]
                    prefixes += [v for v in (const_str(x, self.consts) for x in values) if v and v.startswith("/")]
            if isinstance(node, ast.Compare) and len(node.ops) == 1:
                op, right = node.ops[0], node.comparators[0]
                if isinstance(op, ast.Eq):
                    s = const_str(right, self.consts)
                    if s and s.startswith("/"):
                        exact.append(s)
        if reads_cred and denies:
            self.scan.middlewares[name] = Middleware(
                name, self.rel, fn.lineno, sorted(set(prefixes)), sorted(set(exact)), decorator
            )

    def _top_level(self, node):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    self.imports_module[a.asname] = a.name
                else:
                    self.imports_module[a.name.split(".")[0]] = a.name.split(".")[0]
                    self.imports_module.setdefault(a.name, a.name)
        elif isinstance(node, ast.ImportFrom):
            mod = self.resolve_relative(node.level, node.module) if node.level else (node.module or "")
            for a in node.names:
                self.imports_symbol[a.asname or a.name] = (mod, a.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for t in targets:
                if isinstance(t, ast.Name) and value is not None:
                    self._assignment(t.id, value, node)
        elif isinstance(node, (ast.If, ast.Try)):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.stmt):
                    self._top_level(child)

    def _assignment(self, name: str, value, node):
        s = const_str(value, self.consts)
        if s is not None:
            self.consts[name] = s
        parts = annotated_parts(value)
        if parts:
            deps = [d for d in (dep_from_call(p, parts[0]) for p in parts[1:]) if d]
            if deps:
                self.dep_aliases[name] = deps
        if not isinstance(value, ast.Call):
            return
        cname = call_name(value)
        if cname in ("APIRouter", "FastAPI"):
            prefix = const_str(kw(value, "prefix"), self.consts) if kw(value, "prefix") is not None else ""
            deps = deps_from_list(kw(value, "dependencies"))
            self.scan.routers[(self.module, name)] = RouterDef(
                self.module, name, "app" if cname == "FastAPI" else "router",
                prefix if prefix is not None else "<dynamic>",
                [Dep(d, "app" if cname == "FastAPI" else "router", self.where(node)) for d in deps],
                self.rel, node.lineno,
            )
        elif cname in SECURITY_SCHEMES:
            auto = kw(value, "auto_error")
            optional = isinstance(auto, ast.Constant) and auto.value is False
            self.scan.schemes[name] = optional

    def _include(self, call: ast.Call):
        parent = dotted(call.func.value) or ""
        child = dotted(call.args[0]) or ""
        prefix_node = kw(call, "prefix")
        prefix = const_str(prefix_node, self.consts) if prefix_node is not None else ""
        deps = deps_from_list(kw(call, "dependencies"))
        self.scan.includes.append(Include(
            self.module, parent, child, prefix if prefix is not None else "<dynamic>",
            [Dep(d, "include", self.where(call)) for d in deps], self.rel, call.lineno,
        ))

    def _params(self, fn):
        args = fn.args
        positional = args.posonlyargs + args.args
        defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
        pairs = list(zip(positional, defaults)) + list(zip(args.kwonlyargs, args.kw_defaults))
        deps, cred, request = [], [], []
        for arg, default in pairs:
            ann = arg.annotation
            markers = []
            if isinstance(default, ast.Call):
                markers.append(default)
            parts = annotated_parts(ann)
            if parts:
                markers.extend(p for p in parts[1:] if isinstance(p, ast.Call))
            base_ann = parts[0] if parts else ann
            for m in markers:
                d = dep_from_call(m, base_ann)
                if d:
                    deps.append(d)
                elif is_cred_marker(m, arg.arg):
                    cred.append(arg.arg)
            if isinstance(ann, ast.Name) and ann.id in self.dep_aliases:
                deps.extend(self.dep_aliases[ann.id])
            ann_last = annotation_name(base_ann) or ""
            if ann_last in ("Request", "HTTPConnection", "WebSocket"):
                request.append(arg.arg)
            elif ann_last in ("HTTPAuthorizationCredentials", "HTTPBasicCredentials") \
                    or (CRED_PARAM_RE.match(arg.arg) and arg.arg not in cred and not deps_in(markers)):
                cred.append(arg.arg)
        return deps, cred, request

    def _body(self, fn, names: set):
        """Calls that receive a credential or the request, and whether 401/403 is raised."""
        calls, raises = [], False
        names = set(names)
        # Follow the credential through simple assignments: token = authorization.split()[1]
        for _ in range(2):
            for node in ast.walk(fn):
                if isinstance(node, ast.Assign) and names and refers_to(node.value, names):
                    for t in node.targets:
                        names.update(n.id for n in ast.walk(t) if isinstance(n, ast.Name))
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and names:
                cname = dotted(node.func) or call_name(node)  # keep "jwt.decode", not just "decode"
                values = list(node.args) + [k.value for k in node.keywords]
                if cname and any(refers_to(v, names) for v in values):
                    calls.append(cname)
            elif isinstance(node, ast.Raise) and node.exc is not None and raises_401_403(node.exc):
                raises = True
        return calls, raises

    def _function(self, fn):
        deps, cred, request = self._params(fn)
        calls, raises = self._body(fn, set(cred) | set(request))
        has_cred = bool(cred or request)
        body_auth = (raises and has_cred) or any(AUTH_NAME_RE.search(c) for c in calls)
        self.scan.funcs.setdefault(fn.name, []).append(
            FuncInfo(deps, has_cred, body_auth or (raises and bool(deps)), calls)
        )
        for deco in fn.decorator_list:
            if not isinstance(deco, ast.Call) or not isinstance(deco.func, ast.Attribute):
                continue
            attr = deco.func.attr
            if attr not in HTTP_METHODS and attr not in ("api_route", "websocket"):
                continue
            owner = dotted(deco.func.value) or ""
            if attr in HTTP_METHODS:
                methods = [attr.upper()]
            elif attr == "websocket":
                methods = ["WS"]
            else:
                m = kw(deco, "methods")
                methods = [e.value.upper() for e in m.elts if isinstance(e, ast.Constant)] \
                    if isinstance(m, (ast.List, ast.Tuple, ast.Set)) else ["GET"]
            path_node = deco.args[0] if deco.args else kw(deco, "path")
            path = const_str(path_node, self.consts) if path_node is not None else ""
            route_deps = [Dep(d, "route", self.where(deco)) for d in deps_from_list(kw(deco, "dependencies"))]
            route_deps += [Dep(d, "route", self.where(fn)) for d in deps]
            stmts = fn.body[1:] if fn.body and isinstance(fn.body[0], ast.Expr) \
                and isinstance(fn.body[0].value, ast.Constant) else fn.body
            disabled = bool(stmts) and all(isinstance(s, ast.Raise) for s in stmts)
            self.scan.routes.append(RouteDef(
                self.module, owner, methods, path if path is not None else "<dynamic>",
                fn.name, self.rel, fn.lineno, route_deps, cred, calls, raises, bool(request),
                disabled,
            ))


# ---------------------------------------------------------------- resolution

def module_name(path: Path, root: Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def find_module(scan: Scan, name: str) -> str | None:
    if not name:
        return None
    if name in scan.parsers:
        return name
    matches = [m for m in scan.parsers if m.endswith("." + name) or name.endswith("." + m)]
    return max(matches, key=len) if matches else None


def resolve_ref(scan: Scan, module: str, expr: str):
    """Resolve an expression like `router`, `admin.router` to a RouterDef key."""
    if not expr:
        return None
    parser = scan.parsers[module]
    parts = expr.split(".")
    if len(parts) == 1:
        if (module, expr) in scan.routers:
            return (module, expr)
        if expr in parser.imports_symbol:
            mod, sym = parser.imports_symbol[expr]
            found = find_module(scan, mod)
            if found and (found, sym) in scan.routers:
                return (found, sym)
        return None
    head, var, middle = parts[0], parts[-1], parts[1:-1]
    candidates = []
    if head in parser.imports_module:
        candidates.append(".".join([parser.imports_module[head]] + middle))
    if head in parser.imports_symbol:
        mod, sym = parser.imports_symbol[head]
        candidates.append(".".join([p for p in [mod, sym] if p] + middle))
    if expr.rsplit(".", 1)[0] in parser.imports_module:
        candidates.append(parser.imports_module[expr.rsplit(".", 1)[0]])
    for cand in candidates:
        found = find_module(scan, cand)
        if found and (found, var) in scan.routers:
            return (found, var)
    return None


def mount_contexts(scan: Scan, key, seen=frozenset()):
    """Prefixes and dependencies applied before a router's own ones."""
    router = scan.routers[key]
    if router.kind == "app":
        return [("", [], True)]
    contexts = []
    for inc in scan.includes:
        if resolve_ref(scan, inc.module, inc.child_expr) != key:
            continue
        parent = resolve_ref(scan, inc.module, inc.parent_expr)
        if parent is None or parent in seen:
            contexts.append((inc.prefix, list(inc.deps), False))
            continue
        prouter = scan.routers[parent]
        for pp, pd, resolved in mount_contexts(scan, parent, seen | {key}):
            contexts.append((pp + prouter.prefix + inc.prefix, pd + prouter.deps + inc.deps, resolved))
    return contexts or [("", [], False)]


def join_path(*parts: str) -> str:
    path = "".join(p for p in parts if p)
    path = re.sub(r"/{2,}", "/", path)
    return path or "/"


class AuthClassifier:
    """Decides whether a dependency name is authentication, and whether optional."""

    def __init__(self, scan: Scan, explicit: set):
        self.scan = scan
        self.explicit = explicit
        self.memo: dict = {}

    def check(self, name: str, depth: int = 0):
        """(is_auth, is_optional) for a dependency or helper name."""
        if name in self.memo:
            return self.memo[name]
        self.memo[name] = (False, False)  # cycle guard
        optional = bool(OPTIONAL_RE.search(name))
        if name in self.scan.schemes:
            result = (True, optional or self.scan.schemes[name])
        elif self.explicit and name in self.explicit:
            result = (True, optional)
        elif name in self.scan.funcs and depth < 6:
            auth_infos = []
            for fi in self.scan.funcs[name]:
                own = fi.body_auth and fi.has_cred
                helpers = [self.check(last(c), depth + 1) for c in fi.cred_calls if last(c) in self.scan.funcs]
                subs = [self.check(d, depth + 1) for d in fi.deps]
                found = [s for s in subs + helpers if s[0]]
                if own or found:
                    auth_infos.append(not own and all(s[1] for s in found))
            result = (bool(auth_infos), optional or (bool(auth_infos) and all(auth_infos)))
        else:
            result = (not self.explicit and bool(AUTH_NAME_RE.search(name)), optional)
        self.memo[name] = result
        return result

    def body_call(self, name: str):
        """A call that receives the credential in a handler: a known helper, or one named like auth."""
        short = last(name)
        if short in self.scan.funcs or short in self.explicit:
            return self.check(short)
        if AUTH_NAME_RE.search(name):
            return True, bool(OPTIONAL_RE.search(short))
        return False, False


# ------------------------------------------------------------------ analysis

def scan_project(root: Path, include_tests: bool = False) -> Scan:
    scan = Scan(root=root)
    for path in sorted(root.rglob("*.py")):
        rel_parts = path.relative_to(root).parts[:-1]
        if any(p in SKIP_DIRS for p in rel_parts):
            continue
        if not include_tests and any(p in TEST_DIRS for p in rel_parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
        except SyntaxError as exc:
            scan.parse_errors.append(f"{path.relative_to(root).as_posix()}: {exc.msg} (line {exc.lineno})")
            continue
        scan.files += 1
        module = module_name(path, root)
        scan.parsers[module] = ModuleParser(scan, path, module, tree)
    for parser in scan.parsers.values():
        parser.parse()
    return scan


def covering_middleware(scan: Scan, path: str):
    for mw in scan.middlewares.values():
        if not (mw.decorator or mw.name in scan.registered_middlewares):
            continue
        if path in mw.exact or any(path.startswith(p) or path + "/" == p for p in mw.prefixes):
            return mw
    return None


def analyse(scan: Scan, explicit_auth: set) -> dict:
    auth = AuthClassifier(scan, explicit_auth)
    rows, findings, reviews, unresolved = [], [], [], set()
    middleware_routes: dict = {}
    for r in scan.routes:
        key = resolve_ref(scan, r.module, r.owner_expr)
        if key is None:
            contexts, router = [("", [], False)], None
        else:
            router = scan.routers[key]
            contexts = mount_contexts(scan, key)
        for prefix, ctx_deps, resolved in contexts:
            own_prefix = router.prefix if router else ""
            own_deps = router.deps if router else []
            path = join_path(prefix, own_prefix, r.path)
            deps = ctx_deps + own_deps + r.deps
            auth_deps = [d for d in deps if auth.check(d.name)[0]]
            if not resolved and router is not None and router.kind != "app":
                unresolved.add(f"{router.file}:{router.line} `{router.var}`")
            body = {c: auth.body_call(c) for c in dict.fromkeys(r.cred_calls)}
            body_calls = [c for c, (is_auth, _) in body.items() if is_auth]
            if auth_deps:
                optional = all(auth.check(d.name)[1] for d in auth_deps)
                status = "optional" if optional else "dependency"
            elif body_calls or (r.raises_401 and (r.cred_params or r.reads_request)):
                only_optional = body_calls and all(body[c][1] for c in body_calls)
                status = "optional" if only_optional and not r.raises_401 else "in-body"
            else:
                status = "none"
            names = [d.name for d in auth_deps] + body_calls
            evidence = [f"{d.name} ({d.level}, {d.where})" for d in auth_deps]
            evidence += [f"{c}() in handler" for c in body_calls]
            if r.raises_401 and status == "in-body":
                names.append("raise 401/403")
                evidence.append("raises 401/403 in handler")
            if status == "none" and r.disabled:
                status = "disabled"
                evidence.append("handler only raises")
            if status == "none":
                mw = covering_middleware(scan, path)
                if mw:
                    status = "middleware"
                    names.append(mw.name)
                    evidence.append(f"{mw.name} middleware ({mw.file}:{mw.line})")
                    middleware_routes[mw.name] = middleware_routes.get(mw.name, 0) + len(r.methods)
            has_role = any(ROLE_RE.search(n) for n in names)
            for method in r.methods:
                row = {
                    "method": method, "path": path, "handler": r.func,
                    "file": r.file, "line": r.line, "status": status,
                    "auth": names, "evidence": evidence, "mount_resolved": resolved,
                    "id_param": bool(ID_PARAM_RE.search(path)),
                }
                rows.append(row)
                verdict = judge(row, r, has_role)
                if verdict and "severity" in verdict:
                    findings.append({**row, **verdict})
                elif verdict:
                    reviews.append({**row, **verdict})
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["file"], f["line"]))
    reviews.sort(key=lambda f: (f["review"], f["file"], f["line"]))
    used: dict = {}
    for row in rows:
        for name in row["auth"]:
            used[name] = used.get(name, 0) + 1
    middlewares = [
        {"name": mw.name, "file": mw.file, "line": mw.line, "prefixes": mw.prefixes,
         "exact": mw.exact, "routes": middleware_routes.get(mw.name, 0),
         "registered": mw.decorator or mw.name in scan.registered_middlewares}
        for mw in scan.middlewares.values()
    ]
    return {
        "root": str(scan.root), "date": date.today().isoformat(), "files": scan.files,
        "parse_errors": scan.parse_errors, "routes": rows, "findings": findings,
        "reviews": reviews, "auth_names": used, "middlewares": middlewares,
        "unresolved_routers": sorted(unresolved), "explicit_auth_deps": sorted(explicit_auth),
    }


def judge(row: dict, r: RouteDef, has_role: bool):
    """A finding ({"severity", "why"}), a review item ({"review", "why"}) or None."""
    method, path, status = row["method"], row["path"], row["status"]
    write = method in WRITE_METHODS
    public_hint = bool(PUBLIC_HINT_RE.search(f"{path} {r.func}"))
    words = path_words(path)
    critical = bool(words & CRITICAL_WORDS)
    sensitive = critical or bool(words & SENSITIVE_WORDS)
    note = "" if row["mount_resolved"] else " Router mounting not resolved: an include-level guard may exist."
    if status == "none":
        if write and public_hint:
            return {"review": "public-write", "why": "Looks public by design. Check abuse controls: rate limit, signature, input size, cost of what it triggers."}
        if write:
            return {"severity": "HIGH", "why": "Write endpoint with no authentication evidence." + note}
        if critical and not public_hint:
            return {"severity": "HIGH", "why": "Sensitive endpoint with no authentication evidence." + note}
        if r.cred_params:
            return {"severity": "MEDIUM", "why": "Takes a credential but no check was found in the handler." + note}
        if sensitive and not public_hint:
            return {"review": "public-read", "why": "Possibly sensitive data with no authentication. Check what it returns." + note}
        if BULK_FUNC_RE.search(r.func) and not public_hint:
            return {"review": "public-read", "why": "Bulk read. Check it returns no private or unpublished records." + note}
        if row["id_param"] and not public_hint:
            return {"review": "public-read", "why": "Object read by ID. Check the data is meant to be public and IDs are unguessable." + note}
        return None
    if status == "optional" and (write or sensitive):
        return {"severity": "MEDIUM", "why": "Authentication is optional. Check the handler refuses or limits anonymous callers."}
    if status == "dependency" and "admin" in words and not has_role:
        return {"severity": "MEDIUM", "why": "Admin path protected by authentication only. Check that a role or permission is enforced."}
    return None


# -------------------------------------------------------------------- output

def to_markdown(result: dict, max_public: int = 40) -> str:
    rows, findings = result["routes"], result["findings"]
    counts = {s: sum(1 for r in rows if r["status"] == s)
              for s in ("dependency", "in-body", "middleware", "optional", "disabled", "none")}
    lines = [
        "# FastAPI route scan", "",
        f"Project `{result['root']}` · {len(rows)} routes in {result['files']} files · {result['date']}", "",
        "| Protection | Routes |", "| --- | --- |",
        f"| Auth dependency | {counts['dependency']} |",
        f"| Checked in handler | {counts['in-body']} |",
        f"| Auth middleware (path match) | {counts['middleware']} |",
        f"| Optional auth only | {counts['optional']} |",
        f"| Disabled (handler only raises) | {counts['disabled']} |",
        f"| No auth evidence | {counts['none']} |", "",
    ]
    if result["auth_names"]:
        names = ", ".join(f"`{n}` ({c})" for n, c in sorted(result["auth_names"].items(), key=lambda x: -x[1]))
        lines += [f"Auth evidence found: {names}.", ""]
    lines += [f"## Findings ({len(findings)})", ""]
    if findings:
        lines += ["| # | Severity | Route | Handler | Why |", "| --- | --- | --- | --- | --- |"]
        for i, f in enumerate(findings, 1):
            lines.append(
                f"| {i} | {f['severity']} | `{f['method']} {f['path']}` | "
                f"`{f['file']}:{f['line']}` {f['handler']} | {f['why']} |"
            )
    else:
        lines.append("No route findings.")
    sections = (
        ("public-write", "Public writes to review",
         "No authentication, and the name suggests it is meant to be public (login, webhook, form)."),
        ("public-read", "Public reads to review",
         "No authentication on a listing, an object fetched by ID or a possibly sensitive path."),
    )
    for key, title, lead in sections:
        items = [r for r in result["reviews"] if r["review"] == key]
        if not items:
            continue
        lines += ["", f"## {title} ({len(items)})", "", lead, ""]
        for r in items[:max_public]:
            lines.append(f"- `{r['method']} {r['path']}` · `{r['file']}:{r['line']}` {r['handler']}: {r['why']}")
        if len(items) > max_public:
            lines.append(f"- … {len(items) - max_public} more (use --format json)")
    listed = {(f["method"], f["path"], f["file"], f["line"]) for f in findings + result["reviews"]}
    other = [r for r in rows if r["status"] == "none" and (r["method"], r["path"], r["file"], r["line"]) not in listed]
    if other:
        lines += ["", f"Other routes with no auth evidence: {len(other)} (pages, public content; listed in --format json)."]
    limits = []
    for mw in result["middlewares"]:
        scope = ", ".join(f"`{p}*`" for p in mw["prefixes"]) + (", " if mw["prefixes"] and mw["exact"] else "") \
            + ", ".join(f"`{p}`" for p in mw["exact"])
        state = "" if mw["registered"] else " It does not look registered with add_middleware."
        limits.append(
            f"Auth middleware `{mw['name']}` (`{mw['file']}:{mw['line']}`) covers {mw['routes']} routes "
            f"by path ({scope or 'no path condition found'}). Its other conditions (host, environment, "
            f"method) are not evaluated: read it once and confirm it fails closed.{state}"
        )
    if result["unresolved_routers"]:
        limits.append("Routers whose mounting was not resolved: " + ", ".join(result["unresolved_routers"]) + ".")
    if result["parse_errors"]:
        limits.append("Files that could not be parsed: " + "; ".join(result["parse_errors"]) + ".")
    limits.append("Static analysis: routes added with add_api_route, dynamic paths and auth done in "
                  "middleware without a path condition are not seen.")
    lines += ["", "## Limits", ""] + [f"- {item}" for item in limits]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Inventory FastAPI routes and their authentication.")
    ap.add_argument("project", help="project root to scan")
    ap.add_argument("--auth-deps", default="", help="comma-separated names of the project's auth dependencies")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    ap.add_argument("--fail-on", choices=("high", "medium", "low"), help="exit 1 if a finding at or above this severity exists")
    ap.add_argument("--include-tests", action="store_true", help="also scan tests/ directories")
    args = ap.parse_args(argv)
    root = Path(args.project).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    explicit = {n.strip() for n in args.auth_deps.split(",") if n.strip()}
    result = analyse(scan_project(root, args.include_tests), explicit)
    out = json.dumps(result, indent=2, ensure_ascii=False) if args.format == "json" else to_markdown(result)
    sys.stdout.reconfigure(encoding="utf-8")
    print(out)
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on.upper()]
        if any(SEVERITY_ORDER[f["severity"]] <= threshold for f in result["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
