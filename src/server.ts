import express, { type Request, type Response, type NextFunction } from 'express';

const app = express();
app.use(express.json());

// ── Configuration ──────────────────────────────────────────────────────────────
// Flags default to the misconfigured state so Sentinel finds everything out of
// the box. Set env vars to fix individual issues and verify findings disappear.

const PORT = parseInt(process.env.PORT ?? '3000', 10);
const ADD_SECURITY_HEADERS = process.env.ADD_SECURITY_HEADERS === 'true'; // default: missing
const CORS_STRICT = process.env.CORS_STRICT === 'true'; // default: reflect origin
const CORS_WILDCARD = process.env.CORS_WILDCARD === 'true'; // default: off
const EXPOSE_SWAGGER = process.env.EXPOSE_SWAGGER !== 'false'; // default: exposed
const LEGACY_API = process.env.LEGACY_API !== 'false'; // default: alive
const GRAPHQL_INTROSPECTION = process.env.GRAPHQL_INTROSPECTION !== 'false'; // default: enabled
const JWT_ALG = process.env.JWT_ALG ?? 'none'; // default: alg:none
const JWT_TTL_SECONDS = parseInt(process.env.JWT_TTL_SECONDS ?? '99999', 10); // default: ~27h
const JWT_MISSING_EXP = process.env.JWT_MISSING_EXP === 'true'; // default: exp included
const AUTH_REQUIRED = process.env.AUTH_REQUIRED === 'true'; // default: no enforcement
const AUTH_PRESENCE_ONLY = process.env.AUTH_PRESENCE_ONLY === 'true'; // default: validate the token
const VULNERABLE_SQL = process.env.VULNERABLE_SQL !== 'false'; // default: on
const VULNERABLE_TEMPLATE = process.env.VULNERABLE_TEMPLATE !== 'false'; // default: on

// ── Security headers ───────────────────────────────────────────────────────────
// Disabled by default — triggers headers.missing_hsts, missing_xcto, missing_referrer_policy.
// Set ADD_SECURITY_HEADERS=true to add them and verify those findings disappear.

if (ADD_SECURITY_HEADERS) {
  app.use((_req: Request, res: Response, next: NextFunction) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    next();
  });
}

// ── CORS ───────────────────────────────────────────────────────────────────────
// Default: reflects any origin + sets Allow-Credentials → cors.origin_reflection.
// CORS_WILDCARD=true: uses * with credentials → cors.wildcard_with_credentials.
// CORS_STRICT=true: allows only same-host origin → no CORS findings.

app.use((req: Request, res: Response, next: NextFunction) => {
  const origin = req.headers['origin'];
  if (!origin) return next();

  if (CORS_STRICT) {
    if (origin === `http://localhost:${PORT}`) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
  } else if (CORS_WILDCARD) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  next();
});

// ── JWT helper ─────────────────────────────────────────────────────────────────
// auth.jwt_alg_none — default: JWT_ALG='none', no signature, freely forgeable.
// When JWT_ALG is set to anything other than 'none' (e.g. HS256), the signature is a
//   hardcoded stub (base64url of the literal string 'sig' → 'c2ln') rather than a real
//   HMAC signature. Tokens remain trivially forgeable even after "fixing" alg:none —
//   intentional, but there's no dedicated Sentinel finding ID for this behavior yet.

function b64u(obj: object): string {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

// Signature shared by issuance (makeJwt) and validation (verifyJwt): empty for
// alg:none, the hardcoded stub otherwise.
const JWT_SIG = JWT_ALG === 'none' ? '' : Buffer.from('sig').toString('base64url');

function makeJwt(): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: JWT_ALG, typ: 'JWT' };
  const payload: { sub: string; iat: number; exp?: number } = { sub: 'demo', iat: now };
  if (!JWT_MISSING_EXP) payload.exp = now + JWT_TTL_SECONDS;
  return `${b64u(header)}.${b64u(payload)}.${JWT_SIG}`;
}

// Validates a token against what makeJwt() issues: well-formed three-part JWT,
// alg matching the configured JWT_ALG, matching signature, and unexpired exp.
// Deliberate weaknesses that survive validation:
// - alg:none (default): the empty signature binds nothing, so any payload with
//   an alg:none header passes — that IS the alg:none vulnerability.
// - Stub signature (JWT_ALG != none): the signature is a constant, not an HMAC
//   over the payload, so forged payloads still pass (known gap — Epic 5, 5.1).
// - Missing exp is accepted, so the JWT_MISSING_EXP misconfiguration still works.
function verifyJwt(token: string): boolean {
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString('utf8'));
    payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'));
  } catch {
    return false;
  }
  if (typeof header !== 'object' || header === null) return false;
  if (typeof payload !== 'object' || payload === null) return false;
  if ((header as Record<string, unknown>).alg !== JWT_ALG) return false;
  if (parts[2] !== JWT_SIG) return false;
  const exp = (payload as Record<string, unknown>).exp;
  if (exp !== undefined) {
    if (typeof exp !== 'number') return false;
    if (exp <= Math.floor(Date.now() / 1000)) return false;
  }
  return true;
}

// ── Auth middleware ────────────────────────────────────────────────────────────
// When AUTH_REQUIRED=true, the bearer token is actually validated via verifyJwt()
// — a garbage or expired token gets 401 while a token from /api/v2/auth passes,
// which is what makes Sentinel's valid-vs-invalid-vs-no-token enforcement probe
// meaningful. 401s deliberately omit WWW-Authenticate
// (triggers auth.401_missing_www_authenticate if Sentinel probes without credentials).
//
// AUTH_PRESENCE_ONLY=true downgrades this to a presence-only check: any
// Bearer-prefixed string is accepted, validation is skipped. This is the
// pre-validation behavior, kept behind a flag as the fixture for Sentinel's
// auth.invalid_token_accepted finding — the endpoint rejects a missing token
// (401) but accepts an invalid one (200).

function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!AUTH_REQUIRED) return next();
  const authorization = req.headers['authorization'];
  if (!authorization?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Unauthorized', reason: 'missing bearer token' });
    return;
  }
  if (!AUTH_PRESENCE_ONLY && !verifyJwt(authorization.slice('Bearer '.length))) {
    res.status(401).json({ error: 'Unauthorized', reason: 'invalid or expired token' });
    return;
  }
  next();
}

// ── Template expression evaluator ─────────────────────────────────────────────
// Handles simple arithmetic only (e.g. {{7*7}} → 49). No eval, no execution.
// Non-arithmetic expressions return a fake template engine error to simulate
// the response pattern of a real SSTI vulnerability.

function safeEval(expr: string): string {
  const match = expr.trim().match(/^(-?\d+(?:\.\d+)?)\s*([+\-*/])\s*(-?\d+(?:\.\d+)?)$/);
  if (!match) {
    return `[TemplateError: unknown identifier '${expr.trim()}']`;
  }
  const [, a, op, b] = match;
  const x = parseFloat(a),
    y = parseFloat(b);
  switch (op) {
    case '+':
      return String(x + y);
    case '-':
      return String(x - y);
    case '*':
      return String(x * y);
    case '/':
      return y !== 0 ? String(x / y) : `[TemplateError: division by zero]`;
    default:
      return `[TemplateError: unknown operator '${op}']`;
  }
}

// ── Routes ─────────────────────────────────────────────────────────────────────

app.get('/', (_req: Request, res: Response) => {
  res.json({ name: 'sentinel-vulnerable-api', version: '2.0.0' });
});

app.get('/api/v2/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', version: 'v2' });
});

app.get('/api/v2/users', requireAuth, (_req: Request, res: Response) => {
  res.json({
    users: [
      { id: 1, name: 'Alice' },
      { id: 2, name: 'Bob' }
    ]
  });
});

// Auth probe endpoint — returns a JWT in the body.
// The auth suite inspects this response, triggering JWT findings based on config.
app.get('/api/v2/auth', (_req: Request, res: Response) => {
  res.json({ token: makeJwt(), user: 'demo' });
});

// ── Injection: SQL error reflection ───────────────────────────────────────────
// Triggers injection.sql_error_disclosure when a SQL-like payload is sent to ?q=.
// Set VULNERABLE_SQL=false to disable.

if (VULNERABLE_SQL) {
  app.get('/api/v2/search', (req: Request, res: Response) => {
    const q = String(req.query.q ?? '');
    if (q.includes("'") || q.includes('"')) {
      return res.status(500).json({ error: `sql syntax error near '${q}'` });
    }
    res.json({ results: [] });
  });
}

// ── Injection: Template expression evaluation ──────────────────────────────────
// Triggers injection.possible_template_injection when {{expr}} is sent to ?name=.
// Evaluates simple arithmetic expressions (e.g. {{7*7}} → 49) safely.
// Non-arithmetic expressions return a fake TemplateError to simulate SSTI behavior.
// Set VULNERABLE_TEMPLATE=false to disable.

if (VULNERABLE_TEMPLATE) {
  app.get('/api/v2/greet', (req: Request, res: Response) => {
    const name = String(req.query.name ?? 'world');
    const rendered = name.replace(/\{\{([^}]+)\}\}/g, (_, expr: string) => safeEval(expr));
    res.json({ message: `Hello, ${rendered}!` });
  });
}

// ── Legacy endpoint ────────────────────────────────────────────────────────────
// Triggers inventory.stale_version_responding when the OpenAPI spec declares v2
// and this endpoint (version < 2) still responds 200.
// Set LEGACY_API=false to disable.

if (LEGACY_API) {
  app.get('/api/v1/', (_req: Request, res: Response) => {
    res.json({ version: 'v1', _warning: 'deprecated' });
  });
  app.get('/api/v1/users', (_req: Request, res: Response) => {
    res.json({ users: [{ id: 1, name: 'Alice' }], _warning: 'deprecated' });
  });
}

// ── Debug endpoint ─────────────────────────────────────────────────────────────
// Always exposed — triggers inventory.sensitive_endpoint_exposed.
// Conveniently shows the active server config for verification.

app.get('/debug', (_req: Request, res: Response) => {
  res.json({
    config: {
      ADD_SECURITY_HEADERS,
      CORS_STRICT,
      CORS_WILDCARD,
      EXPOSE_SWAGGER,
      LEGACY_API,
      GRAPHQL_INTROSPECTION,
      JWT_ALG,
      JWT_TTL_SECONDS,
      JWT_MISSING_EXP,
      AUTH_REQUIRED,
      AUTH_PRESENCE_ONLY,
      VULNERABLE_SQL,
      VULNERABLE_TEMPLATE
    }
  });
});

// ── Swagger / OpenAPI ──────────────────────────────────────────────────────────
// Triggers inventory.sensitive_endpoint_exposed (/swagger, /openapi.json).
// The OpenAPI spec declares servers[0] as /api/v2, enabling the stale-version check.
// Set EXPOSE_SWAGGER=false to disable both.

if (EXPOSE_SWAGGER) {
  app.get('/openapi.json', (_req: Request, res: Response) => {
    res.json({
      openapi: '3.0.0',
      info: { title: 'Vulnerable API', version: '2.0.0' },
      servers: [{ url: `http://localhost:${PORT}/api/v2` }],
      paths: {
        '/health': { get: { summary: 'Health check', responses: { 200: { description: 'OK' } } } },
        '/users': { get: { summary: 'List users', responses: { 200: { description: 'OK' } } } },
        '/auth': { get: { summary: 'Get auth token', responses: { 200: { description: 'OK' } } } },
        '/search': {
          get: {
            summary: 'Search',
            parameters: [{ name: 'q', in: 'query', schema: { type: 'string' } }],
            responses: { 200: { description: 'OK' } }
          }
        },
        '/greet': {
          get: {
            summary: 'Greet user',
            parameters: [{ name: 'name', in: 'query', schema: { type: 'string' } }],
            responses: { 200: { description: 'OK' } }
          }
        }
      }
    });
  });

  app.get('/swagger', (_req: Request, res: Response) => {
    res.type('html').send('<html><body><h1>Swagger UI (dev fixture)</h1></body></html>');
  });
}

// ── GraphQL ────────────────────────────────────────────────────────────────────
// GET /graphql → 200  triggers inventory.sensitive_endpoint_exposed.
// POST /graphql with __schema query triggers inventory.graphql_introspection_enabled.
// Set GRAPHQL_INTROSPECTION=false to disable both.

if (GRAPHQL_INTROSPECTION) {
  app.get('/graphql', (_req: Request, res: Response) => {
    res.json({ message: 'GraphQL endpoint — use POST for queries.' });
  });

  app.post('/graphql', (req: Request, res: Response) => {
    const query: string = req.body?.query ?? '';
    if (query.includes('__schema')) {
      res.json({ data: { __schema: { queryType: { name: 'Query' } } } });
    } else {
      res.status(400).json({ errors: [{ message: 'Unknown query' }] });
    }
  });
}

// ── Start ──────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  const mark = (active: boolean) => (active ? '[✓]' : '[ ]');
  console.warn('');
  console.warn('!!! WARNING: INTENTIONALLY VULNERABLE SERVER !!!');
  console.warn('This server is a security scan target. ALL vulnerabilities');
  console.warn('are ENABLED by default. Do not expose it to the internet.');
  console.warn('');
  console.log(`\nVulnerable API  →  http://localhost:${PORT}\n`);
  console.log('Misconfigurations  ([✓] = active, will trigger a Sentinel finding)');
  console.log(
    `  ${mark(!ADD_SECURITY_HEADERS)} Missing security headers       ADD_SECURITY_HEADERS=true        to fix`
  );
  console.log(
    `  ${mark(!CORS_STRICT && !CORS_WILDCARD)} CORS reflects arbitrary origin  CORS_STRICT=true                 to fix`
  );
  console.log(
    `  ${mark(CORS_WILDCARD)}  CORS wildcard + credentials    CORS_WILDCARD=true               to trigger`
  );
  console.log(
    `  ${mark(EXPOSE_SWAGGER)} Swagger / OpenAPI exposed      EXPOSE_SWAGGER=false             to hide`
  );
  console.log(
    `  ${mark(LEGACY_API)} Legacy /api/v1/ responding     LEGACY_API=false                 to disable`
  );
  console.log(
    `  ${mark(GRAPHQL_INTROSPECTION)} GraphQL introspection enabled  GRAPHQL_INTROSPECTION=false      to disable`
  );
  console.log(
    `  ${mark(JWT_ALG === 'none')} JWT alg:none                   JWT_ALG=HS256                    to fix`
  );
  console.log(
    `  ${mark(JWT_ALG !== 'none')} JWT fake signature (stub sig)  JWT_ALG=none                     to revert`
  );
  console.log(
    `  ${mark(JWT_TTL_SECONDS > 86400)} JWT long TTL (${Math.round(JWT_TTL_SECONDS / 3600)}h)            JWT_TTL_SECONDS=3600             to shorten`
  );
  console.log(
    `  ${mark(JWT_MISSING_EXP)} JWT missing exp claim          JWT_MISSING_EXP=true             to trigger`
  );
  console.log(
    `  ${mark(!AUTH_REQUIRED)} Auth enforcement disabled      AUTH_REQUIRED=true               to enforce`
  );
  console.log(
    `  ${mark(AUTH_REQUIRED && AUTH_PRESENCE_ONLY)} Token presence-only (no verify) AUTH_PRESENCE_ONLY=true          to trigger`
  );
  console.log(
    `  ${mark(VULNERABLE_SQL)} SQL error reflection           VULNERABLE_SQL=false             to disable`
  );
  console.log(
    `  ${mark(VULNERABLE_TEMPLATE)} Template expression eval       VULNERABLE_TEMPLATE=false        to disable`
  );
  console.log('');
  console.log(`Run against this target:`);
  console.log(
    `  npx sentinel scan --url http://localhost:${PORT} --config sentinel.example.json\n`
  );
});
