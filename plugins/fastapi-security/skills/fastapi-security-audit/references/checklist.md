# FastAPI security checklist

Work through the sections that apply to the app. Each line is a check, followed by where to look. Record a finding only when you have read the code that proves it.

## Sessions and tokens

- JWTs are verified: signature, expiry and algorithm list (`jwt.decode(..., algorithms=["HS256"])`, never `verify_signature: False`, never `"none"`). Grep `jwt.decode`, `jose`.
- Tokens are short-lived or revocable. A 30 to 90 day token with no server-side revocation means a stolen token works until it expires. Grep `exp`, `timedelta(days=`.
- Full tokens are never sent in email links, URLs or logs. Use a short single-use code instead. Grep `?token=`, `send_email`, `logger.*token`.
- Session cookies are `HttpOnly`, `Secure` and `SameSite=Lax` or `Strict`. Grep `set_cookie(`.
- Logout clears the cookie on the server side too, and client code has one logout function, not one per page.
- State-changing forms that rely on cookies have CSRF protection (token, or `SameSite=Strict` plus an Origin check).
- Login, OTP and password-reset endpoints are rate limited per account and per IP, and say the same thing whether or not the account exists.
- Account creation is atomic: two simultaneous requests (double click, payment retry) cannot create two accounts for one email.

## Authorization

- Every route that reads personal data or changes state has an auth dependency, at route, router or `include_router` level. Middleware alone is not enough unless its path and host conditions are proven to cover the route.
- Admin routes check a role, not only a logged-in user.
- Every object fetched by ID is checked against the caller's user or organisation. Foreign objects return 404.
- Visibility flags are enforced on every read path: detail, list, export, PDF, preview, download.
- Bulk listings return only the caller's records, and are paginated.
- Multi-tenant: the tenant comes from a trusted source (host or verified claim, never a request body field) and is set explicitly in background tasks, webhooks and cron jobs.

## Input and output

- Templates: values in HTML are autoescaped; values in `<script>` use `|tojson`; `|safe` and `Markup()` only wrap trusted content.
- Redirects after login (`next`, `return_to`) only accept same-origin relative paths that start with a single `/`.
- SQL uses bound parameters; no f-strings or `%` in `execute()` or `text()`.
- File uploads check type, size and name, and are served from a separate origin or with `Content-Disposition: attachment`.
- Server-side fetches of user-supplied URLs (webhooks, link previews, imports) block internal addresses (SSRF).
- Error responses never include stack traces, SQL or file paths. Look for a catch-all exception handler returning a generic 500.
- Pydantic models reject unknown fields on write routes when mass assignment would matter (`role`, `is_admin`, `org_id`, `price`).

## Payments and webhooks

- Webhook handlers verify the provider's signature and fail with 500 when the signing secret is missing, instead of parsing the payload anyway.
- Prices, amounts and plan IDs come from the server, never from the client.
- Payment confirmation is checked with the provider's API, not trusted from a client callback.
- Webhook processing is idempotent: the same event delivered twice changes nothing the second time.

## Secrets and configuration

- No secrets in the repository, including seed scripts, test-account scripts and notebooks. Check git history if the user allows it.
- `os.getenv("SECRET", "fallback")` with a real-looking fallback silently runs with a known secret when the variable is missing.
- CORS lists explicit origins when `allow_credentials=True`.
- `FastAPI(debug=True)` and interactive docs (`/docs`, `/redoc`, `/openapi.json`) are off or protected in production.
- Security headers are set (CSP, HSTS, `X-Content-Type-Options`, `frame-ancestors`), in the app or at the edge.

## Personal data

- Logs and analytics do not store emails, tokens or full IP addresses unless needed; if they do, they are pseudonymised.
- There is a way to export and delete a user's data, and deletion reaches logs and backups within the stated retention.
- Admin screens show only the personal data the role needs.

## Abuse and cost controls

- Public endpoints that send email, generate PDFs or call paid APIs (LLMs, image generation, SMS) are rate limited and capped per user or per IP.
- Expensive operations check a quota before they run and charge only on success.
- Free trials limit the expensive actions, not only the duration.
- Inputs that drive cost (prompt length, file size, number of items) have upper bounds.
