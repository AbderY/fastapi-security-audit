# Guardrail hook: catch unprotected routes as they are written

`scripts/route_guard_hook.py` is a Claude Code `PostToolUse` hook. After every edit of a Python file, it scans the project's routes and, if the edited file now holds a route with no authentication evidence that changes data or exposes sensitive data, it sends a short warning back to Claude. The edit is kept; Claude is asked to add the guard or confirm with the user that the route is public.

Install it only with the user's approval: it changes the project's Claude Code settings.

## Install in a project

1. Copy `scripts/route_guard_hook.py` and `scripts/scan_routes.py` into the project, for example under `.claude/hooks/`.
2. Add the hook to `.claude/settings.json` (merge with any existing `hooks` block):

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Edit|Write|MultiEdit",
        "hooks": [
          { "type": "command", "command": "python .claude/hooks/route_guard_hook.py" }
        ]
      }
    ]
  }
}
```

3. Optional: name the project's guards so the scanner does not guess, in the same settings file:

```json
{ "env": { "FASTAPI_AUDIT_AUTH_DEPS": "require_admin,get_current_user" } }
```

4. Test it: ask Claude to add a `@router.post` route without a guard to a router file. The warning should appear right after the edit.

## Behaviour

- Exit code 2 with a message on stderr when the edited file holds HIGH findings; exit 0 otherwise, silently.
- It reads the whole project, so include_router and router-level guards defined elsewhere are taken into account.
- Routes whose names look public (login, webhook, checkout, health) are not reported.
