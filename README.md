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
| `JWT_ALG` | `none` | Tokens issued with `alg:none`, no signature | `HS256` |
| `JWT_TTL_SECONDS` | `99999` | Token lifetime ~27.7 h (threshold: 24 h) | `3600` |
| `JWT_MISSING_EXP` | `false` | Set `true` to issue tokens with no `exp` claim | — |
| `AUTH_REQUIRED` | `false` | Protected endpoints accept unauthenticated requests | `true` |
| `VULNERABLE_SQL` | `true` | SQL error strings reflected in 500 responses | `false` |
| `VULNERABLE_TEMPLATE` | `true` | `{{expr}}` evaluated in query params | `false` |

---

## Vulnerability inventory

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
| `jwt.alg_none` | `/api/v2/auth` | `JWT_ALG=HS256` |
| `jwt.weak_signature` | `/api/v2/auth` | when `JWT_ALG != none`, signature is hardcoded stub `c2ln` — tokens remain forgeable; set `JWT_ALG=none` to revert to the primary finding |
| `jwt.long_ttl` | `/api/v2/auth` | `JWT_TTL_SECONDS=3600` |
| `jwt.missing_exp` | `/api/v2/auth` | `JWT_MISSING_EXP=true` to trigger |
| `auth.unenforced` | `/api/v2/users` | `AUTH_REQUIRED=true` |
| `auth.401_missing_www_authenticate` | `/api/v2/users` | `AUTH_REQUIRED=true` (triggers 401 without `WWW-Authenticate` header) |
| `injection.sql_error_disclosure` | `/api/v2/search` | `VULNERABLE_SQL=false` |
| `injection.possible_template_injection` | `/api/v2/greet` | `VULNERABLE_TEMPLATE=false` |

### Note on `jwt.weak_signature`

When `JWT_ALG` is set to anything other than `none` (e.g. `HS256`), the server produces a hardcoded base64url stub (`c2ln` = `"sig"`) instead of a real HMAC signature. Tokens are still trivially forgeable — this is an intentional secondary finding that surfaces when an operator "fixes" `alg:none` without providing a real signing key.

---

## Endpoints

| Method | Path | Auth? | Notes |
|---|---|---|---|
| `GET` | `/` | No | `{name, version}` |
| `GET` | `/api/v2/health` | No | `{status: "ok"}` |
| `GET` | `/api/v2/users` | `requireAuth` | Returns Alice/Bob |
| `GET` | `/api/v2/auth` | No | Issues a JWT |
| `GET` | `/api/v2/search?q=` | No | SQL error reflection probe |
| `GET` | `/api/v2/greet?name=` | No | Template injection probe |
| `GET` | `/api/v1/` | No | Legacy (conditional) |
| `GET` | `/api/v1/users` | No | Legacy (conditional) |
| `GET` | `/debug` | No | Full live config — always on |
| `GET` | `/openapi.json` | No | OpenAPI 3.0 spec (conditional) |
| `GET` | `/swagger` | No | Swagger stub (conditional) |
| `GET/POST` | `/graphql` | No | Introspection target (conditional) |
