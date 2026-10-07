#!/usr/bin/env python3
"""Claude Code PostToolUse hook: flag new FastAPI routes that change data without auth.

After each edit of a Python file, runs the route scanner on the project and
reports the HIGH findings located in the edited file. Exit code 2 sends the
message back to Claude without undoing the edit; 0 otherwise.

Install: see references/guardrail-hook.md. Optional environment variable:
FASTAPI_AUDIT_AUTH_DEPS=require_admin,get_current_user
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scan_routes  # noqa: E402


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    file_path = (payload.get("tool_input") or {}).get("file_path") or ""
    if not file_path.endswith(".py"):
        return 0
    root = Path(os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or os.getcwd()).resolve()
    try:
        rel = Path(file_path).resolve().relative_to(root).as_posix()
    except ValueError:
        return 0
    explicit = {n.strip() for n in os.environ.get("FASTAPI_AUDIT_AUTH_DEPS", "").split(",") if n.strip()}
    result = scan_routes.analyse(scan_routes.scan_project(root), explicit)
    hits = [f for f in result["findings"] if f["file"] == rel and f["severity"] == "HIGH"]
    if not hits:
        return 0
    lines = [f"{f['method']} {f['path']} ({rel}:{f['line']}): {f['why']}" for f in hits[:8]]
    print(
        "[fastapi-security] Routes without authentication evidence in the file you just edited:\n- "
        + "\n- ".join(lines)
        + "\nAdd the project's auth dependency, or confirm with the user that the route is meant to be public.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
