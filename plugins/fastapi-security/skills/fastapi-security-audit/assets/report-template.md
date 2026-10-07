# Security audit: {project name}

{YYYY-MM-DD} · scope: {repository, branch or commit, environments covered} · read-only review

{One-sentence verdict: the most serious problem and how many findings per severity.}

| Severity | Count |
| --- | --- |
| Critical | {n} |
| High | {n} |
| Medium | {n} |
| Low | {n} |

## Fix first

1. {Finding title}: {why it comes first, in one sentence}.
2. {…}
3. {…}

## Findings

### {ID, e.g. C1}. {Title in plain words}

- **Severity:** {Critical | High | Medium | Low}
- **Where:** `{file}:{line}` · `{METHOD} {path}`
- **Evidence:** {what the code does, quoted briefly; never paste a secret value}
- **Impact:** {who can do what, in one sentence}
- **Fix:** {the change, as specific as the code allows}
- **Verify:** {the test or request that proves the fix, e.g. "GET without a token returns 401"}
- **Live check:** {result, or "not verified live"}

{Repeat per finding, most severe first.}

## Reviewed and accepted

| Route or item | Why it is acceptable |
| --- | --- |
| `{METHOD} {path}` | {public by design, and the abuse controls in place} |

## Not covered

- {What was out of scope or could not be checked: other services, infrastructure, dependencies, live environment, git history.}

## Method

Route inventory and pattern scan with the fastapi-security-audit skill ({n} routes, {n} files), manual review of every lead, object-level and tenant checks, checklist sections {list}.
