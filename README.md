# anemone

[![scan](https://github.com/uncommon-carp/anemone/actions/workflows/scan.yml/badge.svg)](https://github.com/uncommon-carp/anemone/actions/workflows/scan.yml)

**Intentionally vulnerable API** — a scan target for [Sentinel](https://github.com/uncommon-carp/sentinel) security tooling.

> **WARNING:** Every misconfiguration is **on by default**. Do not expose this server to the internet or run it in any production environment.

---

## What it is

anemone is a single-file Express/TypeScript server with 14 deliberately misconfigured behaviors. Each one is togglable via an environment variable so you can:

1. Run a Sentinel scan and confirm the findings appear.
2. Flip the flag to fix the issue.
3. Re-scan and confirm the finding disappears.

---

## Quickstart

### Local dev

```bash
npm install
npm run dev          # starts on http://localhost:3000
```

### Docker

```bash
docker build -t anemone .
docker run -p 3000:3000 anemone

# Override flags at run time:
docker run -p 3000:3000 -e JWT_ALG=HS256 -e ADD_SECURITY_HEADERS=true anemone
```

### Running Sentinel against it

```bash
npx sentinel scan --url http://localhost:3000 --config sentinel.example.json
```

---

## CI: scanning via Weir

`.github/workflows/scan.yml` calls [Weir](https://github.com/uncommon-carp/weir)'s
reusable scan workflow. Every PR runs a scan against Anemone's default (fully
vulnerable) state — that's the actual gate.

For an on-demand scan against a specific misconfiguration profile instead of
the default state, trigger it manually with `target-env`, a JSON object of env
var overrides merged into the target container (see the table below for what
each flag controls):

```bash
gh workflow run scan.yml --repo uncommon-carp/anemone \
  -f target-env='{"CORS_STRICT":"true","EXPOSE_SWAGGER":"false","LEGACY_API":"false","GRAPHQL_INTROSPECTION":"false","JWT_ALG":"HS256","JWT_TTL_SECONDS":"3600","AUTH_REQUIRED":"true","VULNERABLE_SQL":"false","VULNERABLE_TEMPLATE":"false"}'
```

That example is a "headers only" profile — every flag except
`ADD_SECURITY_HEADERS` is remediated, so only `headers.*` findings should
appear (plus `inventory.sensitive_endpoint_exposed`, since `/debug` is always
on regardless of `EXPOSE_SWAGGER`, and the two `ratelimit.*` findings, since
Anemone has no rate-limit toggle at all — neither is fixable via env var,
by design).

---

## Environment variables

All flags default to the **vulnerable** state. Set a flag as shown in the "Fix" column to remediate that finding.

| Variable | Default | Vulnerable behavior | Fix |
|---|---|---|---|
| `PORT` | `3000` | — | — |
| `ADD_SECURITY_HEADERS` | `false` | Missing HSTS, X-Content-Type-Options, Referrer-Policy, CSP | `true` |
| `CORS_STRICT` | `false` | Reflects any `Origin` + sets `Allow-Credentials: true` | `true` |
| `CORS_WILDCARD` | `false` | `Allow-Origin: *` with `Allow-Credentials: true` (spec-invalid) | leave `false` |
| `EXPOSE_SWAGGER` | `true` | `/swagger` and `/openapi.json` publicly reachable | `false` |
| `LEGACY_API` | `true` | `/api/v1/` returns 200 after v2 is declared current | `false` |
| `GRAPHQL_INTROSPECTION` | `true` | `__schema` queries answered at `/graphql` | `false` |
| `JWT_ALG` | `none` | Tokens issued with `alg:none`, no signature | `HS256`¹ |
| `JWT_TTL_SECONDS` | `99999` | Token lifetime ~27.7 h (threshold: 24 h) | `3600` |
| `JWT_MISSING_EXP` | `false` | Set `true` to issue tokens with no `exp` claim | — |
| `AUTH_REQUIRED` | `false` | Protected endpoints accept unauthenticated requests | `true` |
| `AUTH_PRESENCE_ONLY` | `false` | With `AUTH_REQUIRED=true`, accept any `Bearer` token without validating it | leave `false` |
| `VULNERABLE_SQL` | `true` | SQL error strings reflected in 500 responses | `false` |
| `VULNERABLE_TEMPLATE` | `true` | `{{expr}}` evaluated in query params | `false` |
| `VULNERABLE_SSRF` | `true` | `/api/v2/fetch?url=` (GET query) and `POST /api/v2/webhooks` (JSON body) accept any URL without validation | `false` |
| `VULNERABLE_BOLA` | `true` | `GET /api/v2/users/:id` returns any user's record regardless of the caller's identity | `false` |
| `VULNERABLE_BUSINESS_FLOW` | `true` | `POST /api/v2/coupons/redeem` never throttles | `false` |
| `VULNERABLE_MASS_ASSIGNMENT` | `true` | `PATCH /api/v2/users/:id` merges undocumented body fields (`role`, `isAdmin`, `owner`, ...) into the record | `false` |
| `VULNERABLE_DATA_EXPOSURE` | `true` | `GET /api/v2/users/:id` includes `apiKey` in the response | `false` |

¹ Setting `JWT_ALG=HS256` clears `auth.jwt_alg_none` but the signature is still a
hardcoded stub, so the token trips `auth.jwt_weak_signature` instead. Anemone is a
deliberately vulnerable fixture — no single flag yields a fully secure token.

With `AUTH_REQUIRED=true`, protected endpoints don't just check for a `Bearer `
prefix — the token is validated against what `/api/v2/auth` issues (matching
`alg`, matching signature, unexpired `exp`), so garbage or expired tokens get
401 while issued tokens pass. Two deliberate weaknesses survive validation:
`alg:none` tokens (default) carry no signature and are freely forgeable, and
the non-`none` stub signature is a constant rather than a real HMAC, so forged
payloads still pass (this is what Sentinel's `auth.jwt_weak_signature` finding
detects — see the comment above `makeJwt()`).

Setting `AUTH_PRESENCE_ONLY=true` (only meaningful with `AUTH_REQUIRED=true`)
downgrades enforcement to a presence-only check: a missing token still gets
401, but *any* `Bearer`-prefixed string is accepted without validation. This is
the fixture for Sentinel's `auth.invalid_token_accepted` finding — it makes the
endpoint reject the no-token probe while accepting the invalid-token probe.

### BOLA fixture (`VULNERABLE_BOLA`)

`GET /api/v2/users/:id` is a Broken Object Level Authorization (OWASP API1)
fixture. Two records exist — `1` owned by `alice`, `2` owned by `bob` — each
holding sensitive fields (`email`, `apiKey`). By default the endpoint returns
whichever record is requested **regardless of the caller's identity**, so a
token for `bob` can read Alice's record. Set `VULNERABLE_BOLA=false` to enforce
ownership (the caller's JWT `sub` must own the record, else `403`).

Authenticate as a specific identity with `GET /api/v2/auth?user=alice` or
`?user=bob` (default `demo`). The meaningful config is
`AUTH_REQUIRED=true VULNERABLE_BOLA=true` — tokens are validated so the identity
is real, but object ownership is not checked. The Sentinel check that probes
this (a cross-identity BOLA probe) is `auth.bola_object_access` (Epic 5 story
5.5).

### Excessive data exposure fixture (`VULNERABLE_DATA_EXPOSURE`)

Same `GET /api/v2/users/:id` endpoint, a separate concern from BOLA above:
once a caller passes the ownership gate (or `VULNERABLE_BOLA` leaks the record
regardless), the response still includes `apiKey` — a credential that should
never be re-served on a read, even to its own owner. Default
(`VULNERABLE_DATA_EXPOSURE=true`): `apiKey` included. `=false`: `apiKey`
stripped from the response entirely. `email` stays present in both modes —
it's expected profile data, not the excessive-exposure case. This is the
target fixture for Sentinel's `inventory.excessive_data_exposure` check (Epic
5 story 5.7).

### Mass assignment fixture (`VULNERABLE_MASS_ASSIGNMENT`)

`PATCH /api/v2/users/:id` updates the caller's own record — ownership is
enforced unconditionally here (unlike the GET route above, which toggles it
via `VULNERABLE_BOLA`), so this exercises mass assignment specifically, not
BOLA. The OpenAPI request-body schema for this route only ever advertises
`email` as settable. By default (`VULNERABLE_MASS_ASSIGNMENT=true`) any other
field in the request body — `role`, `isAdmin`, `owner`, or anything else — is
merged into the stored record and persists: the server accepts more than the
spec promises. Set `VULNERABLE_MASS_ASSIGNMENT=false` to strip undocumented
fields before the merge, so only `email` can change.

`requireAuth` gates this route (respects `AUTH_REQUIRED`), so the meaningful
config is `AUTH_REQUIRED=true` with a token for the record's own identity
(`GET /api/v2/auth?user=alice`, then `PATCH /users/1`) — same authentication
pattern as the BOLA fixture. The Sentinel check that probes this
(`auth.mass_assignment_accepted`) is Epic 5 story 5.9.

### Sensitive business flow fixture (`VULNERABLE_BUSINESS_FLOW`)

`POST /api/v2/coupons/redeem` simulates a sensitive business flow (coupon
redemption) — the fixture for Sentinel's opt-in `businessFlow.sensitivePaths`
config and the ratelimit suite's third phase (`ratelimit.sensitive_flow_unthrottled`,
Epic 5 story 5.11). Unlike the rest of Anemone — which has no rate-limit
toggle at all by design, since general HTTP-layer rate limiting isn't meant
to be fixable per endpoint here — this route implements a real minimal
throttle so the "fixed" state is actually demonstrable: default
(`VULNERABLE_BUSINESS_FLOW=true`) never throttles; `=false` returns `429` with
`Retry-After` after 3 requests.

`sentinel.example.json` declares `"POST /api/v2/coupons/redeem"` under
`businessFlow.sensitivePaths` so a default scan exercises this check
end-to-end. No auth required — the flow itself is the sensitive surface, not
who's calling it.

---

## Vulnerability inventory

IDs are defined in Sentinel's [`FINDINGS.md`](https://github.com/uncommon-carp/sentinel/blob/main/FINDINGS.md)
— that file is the source of truth for severity/title/OWASP mapping. The
table below is Anemone-specific: which endpoint exercises each finding and
which env var controls it.

| Sentinel finding ID | Endpoint | Controlled by |
|---|---|---|
| `headers.missing_hsts` | all | `ADD_SECURITY_HEADERS=false` |
| `headers.missing_xcto` | all | `ADD_SECURITY_HEADERS=false` |
| `headers.missing_referrer_policy` | all | `ADD_SECURITY_HEADERS=false` |
| `cors.origin_reflection` | all | `CORS_STRICT=false` (default) |
| `cors.wildcard_with_credentials` | all | `CORS_WILDCARD=true` |
| `inventory.sensitive_endpoint_exposed` | `/swagger`, `/openapi.json`, `/graphql`, `/debug` | `EXPOSE_SWAGGER=false` (partial) |
| `inventory.stale_version_responding` | `/api/v1/` | `LEGACY_API=false` |
| `inventory.graphql_introspection_enabled` | `/graphql` | `GRAPHQL_INTROSPECTION=false` |
| `auth.jwt_alg_none` | `/api/v2/auth` | `JWT_ALG=HS256` |
| `auth.jwt_weak_signature` | `/api/v2/auth` | `JWT_ALG=HS256` (any non-`none` alg → stub signature) |
| `auth.jwt_long_ttl` | `/api/v2/auth` | `JWT_TTL_SECONDS=3600` |
| `auth.jwt_missing_exp` | `/api/v2/auth` | `JWT_MISSING_EXP=true` to trigger |
| `auth.possible_bypass_probe` | `/api/v2/users` | `AUTH_REQUIRED=true` |
| `auth.invalid_token_accepted` | `/api/v2/users` | `AUTH_REQUIRED=true` + `AUTH_PRESENCE_ONLY=true` to trigger |
| `auth.401_missing_www_authenticate` | `/api/v2/users` | `AUTH_REQUIRED=true` (triggers 401 without `WWW-Authenticate` header) |
| `injection.sql_error_disclosure` | `/api/v2/search` | `VULNERABLE_SQL=false` |
| `injection.possible_template_injection` | `/api/v2/greet` | `VULNERABLE_TEMPLATE=false` |
| `inventory.ssrf_surface` | `/api/v2/fetch?url=` (GET query, always probed); `POST /api/v2/webhooks` (JSON body, only when Sentinel runs with `inventory.ssrfActiveProbe`) | `VULNERABLE_SSRF=false` |
| `auth.bola_object_access` | `/api/v2/users/:id` | `AUTH_REQUIRED=true` + `VULNERABLE_BOLA=true` + two identities configured |
| `inventory.excessive_data_exposure` | `/api/v2/users/:id` | `VULNERABLE_DATA_EXPOSURE=false` |
| `auth.mass_assignment_accepted`² | `PATCH /api/v2/users/:id` | `AUTH_REQUIRED=true` + `VULNERABLE_MASS_ASSIGNMENT=true` to trigger, only when Sentinel runs with `auth.massAssignmentProbe` |
| `ratelimit.sensitive_flow_unthrottled` | `POST /api/v2/coupons/redeem`, only when Sentinel declares it under `businessFlow.sensitivePaths` (default `sentinel.example.json` does) | `VULNERABLE_BUSINESS_FLOW=false` |

² Epic 5 story 5.9 (not yet implemented at the time this fixture landed) — no
`FINDINGS.md` entry until that check exists.

## Endpoints

| Method | Path | Auth? | Notes |
|---|---|---|---|
| `GET` | `/` | No | `{name, version}` |
| `GET` | `/api/v2/health` | No | `{status: "ok"}` |
| `GET` | `/api/v2/users` | `requireAuth` | Returns Alice/Bob |
| `GET` | `/api/v2/users/:id` | `requireAuth` | BOLA — returns any user's full record (email, apiKey) regardless of caller; `apiKey` strippable via `VULNERABLE_DATA_EXPOSURE=false` |
| `PATCH` | `/api/v2/users/:id` | `requireAuth` + ownership | Mass assignment — merges undocumented body fields (role, isAdmin, owner, ...) into the record |
| `GET` | `/api/v2/auth` | No | Issues a JWT; `?user=alice\|bob` issues that identity (default `demo`) |
| `GET` | `/api/v2/search?q=` | No | SQL error reflection probe |
| `GET` | `/api/v2/greet?name=` | No | Template injection probe |
| `GET` | `/api/v2/fetch?url=` | No | SSRF surface — accepts a URL query param (reflects it; no real fetch) |
| `POST` | `/api/v2/webhooks` | No | SSRF surface — accepts a URL in the JSON body (reflects it; no real fetch) |
| `POST` | `/api/v2/coupons/redeem` | No | Sensitive business flow — unthrottled by default, `VULNERABLE_BUSINESS_FLOW=false` throttles after 3 requests |
| `GET` | `/api/v1/` | No | Legacy (conditional) |
| `GET` | `/api/v1/users` | No | Legacy (conditional) |
| `GET` | `/debug` | No | Full live config — always on |
| `GET` | `/openapi.json` | No | OpenAPI 3.0 spec (conditional) |
| `GET` | `/swagger` | No | Swagger stub (conditional) |
| `GET/POST` | `/graphql` | No | Introspection target (conditional) |
