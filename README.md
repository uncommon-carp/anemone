# anemone

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

## Endpoints

| Method | Path | Auth? | Notes |
|---|---|---|---|
| `GET` | `/` | No | `{name, version}` |
| `GET` | `/api/v2/health` | No | `{status: "ok"}` |
| `GET` | `/api/v2/users` | `requireAuth` | Returns Alice/Bob |
| `GET` | `/api/v2/auth` | No | Issues a JWT |
| `GET` | `/api/v2/search?q=` | No | SQL error reflection probe |
| `GET` | `/api/v2/greet?name=` | No | Template injection probe |
| `GET` | `/api/v2/fetch?url=` | No | SSRF surface — accepts a URL query param (reflects it; no real fetch) |
| `POST` | `/api/v2/webhooks` | No | SSRF surface — accepts a URL in the JSON body (reflects it; no real fetch) |
| `GET` | `/api/v1/` | No | Legacy (conditional) |
| `GET` | `/api/v1/users` | No | Legacy (conditional) |
| `GET` | `/debug` | No | Full live config — always on |
| `GET` | `/openapi.json` | No | OpenAPI 3.0 spec (conditional) |
| `GET` | `/swagger` | No | Swagger stub (conditional) |
| `GET/POST` | `/graphql` | No | Introspection target (conditional) |
