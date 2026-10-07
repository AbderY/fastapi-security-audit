---
name: fastapi-security-audit
description: Read-only security audit of a FastAPI or Starlette codebase. Maps every route and how it is protected (dependencies, router and include_router guards, auth middleware, checks inside handlers), flags unauthenticated write or sensitive endpoints, object access by ID without ownership checks, tenant isolation gaps, CORS, JWT, XSS, open redirects and hardcoded secrets, then writes a prioritised findings report. Use when the user asks to audit, review or harden the security of a FastAPI API, check authentication or authorization on endpoints, look for data leaks or IDOR, or prepare for a security review or pentest.
license: MIT
compatibility: Needs Python 3.10+ to run the bundled scanners (standard library only). Written for Claude Code; works in any agent that can read files and run Python.
metadata:
  author: Abderrahmane Yacoubi
  version: "0.1.0"
---

# FastAPI security audit

Audit a FastAPI codebase for access-control and common web vulnerabilities, and hand the user a report they can act on. The bundled scanners find leads fast and reliably; your job is to confirm or dismiss each one by reading the code, then look where scanners cannot.

## Ground rules

- **Read-only.** Do not edit, commit or deploy anything during the audit. The report file is the only file you create. Fixes come after, one at a time, with the user's approval.
- **No credentials, no live attacks.** Never log in, type a password or reuse a token found in the code. Touch a live environment only if the user gives the URL and allows it, and then only unauthenticated GET, HEAD or OPTIONS requests.
- **Evidence for every finding.** Cite `file:line` and say what you read. A scanner hit you have not confirmed in the code is not a finding.
- **Never copy secret values** into the report or the chat. Name the variable and the file.

## Step 1: Map the application

1. Find the entry points and the wiring: grep for `FastAPI(`, `APIRouter(`, `include_router(`, `add_middleware(`, `@app.middleware`.
2. Identify the authentication mechanism (bearer JWT, session cookie, API key) and the guard functions: the dependencies or helpers that raise 401/403. Note which ones also check a role.
3. Read each middleware that touches auth. Note its conditions: path prefixes, host, environment. A middleware often protects HTML pages but not `/api/*`, or only on one host.
4. Note the tenancy model if any: how the current organisation or tenant is resolved (host, JWT claim, header) and where it is stored.

## Step 2: Run the route scanner

```bash
python ${CLAUDE_SKILL_DIR}/scripts/scan_routes.py <project-root> --auth-deps <guard1,guard2> --format json > routes.json
python ${CLAUDE_SKILL_DIR}/scripts/scan_routes.py <project-root> --auth-deps <guard1,guard2>
```

`${CLAUDE_SKILL_DIR}` is this skill's directory; outside Claude Code, use its path. Pass the guard names from step 1 with `--auth-deps`: without them the scanner guesses from function bodies and names. The Markdown output gives the summary; the JSON lists every route with its protection status (`dependency`, `in-body`, `middleware`, `optional`, `disabled`, `none`) and evidence.

## Step 3: Triage every route lead

For each HIGH and MEDIUM finding, open the handler and decide:

- **Confirmed:** the data can be read or changed by someone who should not. Note the impact in one sentence.
- **Public by design:** say why (login, webhook with signature check, guest checkout), then check its abuse controls: rate limit, input size, signature, and the cost of what it triggers (emails, LLM calls, payments).
- **False positive:** say what protects it that the scanner missed.

Then go through the two review lists. Public reads: does any return personal data, unpublished content, internal prices or another customer's records? Public writes: does each one have abuse controls?

For routes protected only by middleware, re-read the middleware conditions once: does it fail closed on every host and environment where the app runs?

## Step 4: Object-level access and tenant isolation

Scanners cannot judge ownership. For every authenticated route that takes an ID, in the path or the body:

- Check the handler verifies the caller owns the object or belongs to its organisation. Prefer 404 over 403 for foreign objects, so IDs cannot be enumerated.
- Check visibility flags (`private`, `published`, `org`) are enforced on every read path, including export, preview, PDF and download routes. These are the routes most often forgotten.
- Check admin routes check a role, not only that someone is logged in.
- In multi-tenant code, check background tasks, webhooks and scheduled jobs set the tenant explicitly. Code running outside a request often falls back to a default tenant and reads or writes the wrong data.

## Step 5: Run the pattern scanner and the checklist

```bash
python ${CLAUDE_SKILL_DIR}/scripts/scan_patterns.py <project-root>
```

Confirm each high and medium hit. Then read [references/checklist.md](references/checklist.md) and work through the sections that apply to this app. It covers sessions and tokens, input and output, payments and webhooks, secrets and configuration, personal data, and abuse controls.

## Step 6: Live checks, only with permission

If the user gave a base URL and allowed it, confirm the main findings without credentials:

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://<host>/<path>
```

Expect 401, 403 or 404 on protected routes. Never send POST, PUT, PATCH or DELETE to a live system. Otherwise, mark findings "not verified live".

## Step 7: Write the report

Fill [assets/report-template.md](assets/report-template.md) and save it as `security-audit-<YYYY-MM-DD>.md` at the project root, unless the user names another place.

- Severity: **Critical** (data read or changed without authentication, auth bypass), **High** (cross-user or cross-tenant access, privilege escalation), **Medium** (exploitable under conditions, missing abuse controls on a costly action), **Low** (hardening).
- Each finding: evidence (`file:line`), impact in one sentence, the fix, and how to verify the fix.
- End with the top 3 to fix first and what you did not check.

In the chat, give the count per severity, the top 3, and say that nothing was changed.

## After the audit

Offer, do not do:

1. Fix one finding at a time: plan, change, add a test that calls the route without credentials and expects 401/403/404, run the tests.
2. Install the guardrail hook ([references/guardrail-hook.md](references/guardrail-hook.md)). It flags new routes without auth as they are written, so the same mistake does not come back.

## Common misses

From real audits of production FastAPI apps:

- Admin CRUD routes added later without the guard, while the older ones have it.
- Export, PDF and download routes that leak the same data as the protected main route.
- Get-by-ID routes that ignore a private or organisation visibility flag.
- Webhooks that accept unsigned payloads when the secret environment variable is missing.
- Login and OTP endpoints without rate limiting.
- Template values injected into `<script>` without `|tojson`.
- `?next=` redirects after login that are not restricted to same-origin paths.
- Long-lived JWTs that cannot be revoked, or full tokens sent in email links.
