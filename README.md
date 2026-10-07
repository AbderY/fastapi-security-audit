# fastapi-security-audit

An [Agent Skill](https://agentskills.io) that runs a read-only security audit of a FastAPI codebase and hands you a prioritised report.

It pairs two deterministic scanners with a review procedure. The scanners find leads reliably; Claude confirms or dismisses each one by reading the code, then checks what scanners cannot: object ownership, tenant isolation, abuse controls. It never edits your code during the audit.

I built it from the audit routine I run on my own production SaaS, a multi-tenant FastAPI app with about 420 routes.

## What it checks

**Route scanner** (`scan_routes.py`): every route, its full path and how it is protected.

| Status | Meaning |
| --- | --- |
| `dependency` | An auth dependency at route, router, `include_router` or app level, followed through helper functions and `Annotated` aliases |
| `in-body` | The handler reads a credential and checks it |
| `middleware` | Covered by an auth middleware's path condition |
| `optional` | Only optional auth: anonymous callers get through |
| `disabled` | The handler only raises (deprecated route) |
| `none` | No authentication evidence |

It then flags write and sensitive routes with no auth, credentials taken but never checked, optional auth on writes, and admin paths without a role check. Public routes that look intentional (login, webhook, checkout) go to a review list instead of the findings.

**Pattern scanner** (`scan_patterns.py`): CORS wildcard with credentials, JWT without signature verification or with `none`, TLS verification off, SQL built from strings, hardcoded secrets and secret fallbacks, open redirects, unsafe YAML and pickle, `Markup()` from formatted strings, disabled autoescaping, values injected into `<script>` without `|tojson`. Secret values are never printed.

**Procedure** (`SKILL.md`): map the app, run both scanners, triage every lead, check object-level access and tenant isolation, work through a [checklist](plugins/fastapi-security/skills/fastapi-security-audit/references/checklist.md), write the report from a [template](plugins/fastapi-security/skills/fastapi-security-audit/assets/report-template.md).

**Guardrail hook** (optional): a Claude Code hook that warns as soon as a new route without auth is written. See [guardrail-hook.md](plugins/fastapi-security/skills/fastapi-security-audit/references/guardrail-hook.md).

Both scanners use only the Python standard library and parse code with `ast`: nothing from your project is imported or executed.

## Results on a real codebase

I replayed the route scanner on my SaaS before and after a security fix round, using the server backups taken just before the fixes. That round had fixed 12 access-control flaws: unauthenticated admin endpoints exposing customer data, and private content readable by ID.

| Snapshot | Known flaws surfaced | HIGH findings | Note |
| --- | --- | --- | --- |
| Before the fixes | 12 of 12 (9 as HIGH, 3 in the review list) | 25 | The other HIGH findings are public flows by design: guest checkout, forms |
| After the fixes | 1 of 12, as MEDIUM | 12 | The remaining one is an intentional optional check, correctly flagged for review |

The scanner is a lead generator, not a verdict: the procedure exists so that Claude reads each lead and explains why it is or is not a problem.

## Install

As a Claude Code plugin:

```bash
claude plugin marketplace add AbderY/fastapi-security-audit
claude plugin install fastapi-security@abdery
```

Or copy the skill folder into your personal or project skills:

```bash
git clone https://github.com/AbderY/fastapi-security-audit
cp -r fastapi-security-audit/plugins/fastapi-security/skills/fastapi-security-audit ~/.claude/skills/
```

The skill only uses the fields of the open Agent Skills standard, so it also works when uploaded to claude.ai or through the Skills API.

## Use

Ask Claude in your FastAPI project:

> Audit the security of this API.

Or invoke it directly: `/fastapi-security-audit` (`/fastapi-security:fastapi-security-audit` when installed as a plugin).

The scanners also run on their own, for example in CI:

```bash
python scan_routes.py path/to/project --auth-deps require_admin,get_current_user --fail-on high
python scan_patterns.py path/to/project --format json
```

## Limits

- Static analysis: routes added with `add_api_route`, dynamic paths and middleware without a path condition are not resolved.
- Ownership checks, business logic and abuse controls need the manual steps of the procedure.
- It does not replace a penetration test.

## Development

```bash
pip install pytest
pytest -q
```

Built with Claude Code. MIT licence.
