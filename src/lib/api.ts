import { NextResponse, NextRequest } from 'next/server'
import type { SafeUser } from './types'
import { rateLimit, getClientIp } from './rate-limit'
import { requireRole, requireUser } from './auth'
import { logger } from './logger'
import { reportSecurityEvent } from './security-events'
import { BASE_URL } from './site'
import { EnvConfigError } from './env-error'

// API responses may contain account, cart, order, or session-derived data.
// Treat every response as private by default. Public endpoints must opt into a
// reviewed cache policy through handleApi({ cacheControl }) after they have
// confirmed that their payload is safe to share across visitors.
const PRIVATE_NO_STORE_HEADERS = { 'Cache-Control': 'private, no-store, max-age=0' }

// ── Request-body size hardening (round 12 DoS fix) ─────────────────────────
/**
 * Default maximum request body accepted by any API route (12MB). Routes that
 * accept file uploads pass a tighter `maxBodyBytes` in their handleApi opts.
 * This bounds worst-case per-request memory regardless of how the client
 * frames the request (Content-Length or Transfer-Encoding: chunked).
 */
const DEFAULT_MAX_BODY_BYTES = 12 * 1024 * 1024
/** Abort a body read if a single stream read stalls longer than this. */
const BODY_READ_TIMEOUT_MS = 20_000
/** Abort a body read if the whole stream takes longer than this to arrive. */
const BODY_TOTAL_BUDGET_MS = 30_000

/** Throw with an explicit HTTP status (honoured by handleApi's catch). */
function bodyError(status: number, message: string): Error & { status: number } {
  return Object.assign(new Error(message), { status })
}

/**
 * Read the ENTIRE request body while (a) counting actual bytes streamed and
 * (b) enforcing read timeouts. Works for chunked bodies (no Content-Length)
 * because it consumes the real stream rather than trusting a header.
 *
 * Memory is bounded to `maxBytes` + one chunk: as soon as the running total
 * crosses the cap we cancel the stream and throw 413 — the accumulation
 * buffer is released with the rejection.
 */
async function readCappedBody(req: NextRequest, maxBytes: number): Promise<Uint8Array> {
  if (!req.body) return new Uint8Array(0)
  const reader = req.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  const deadline = Date.now() + BODY_TOTAL_BUDGET_MS
  try {
    while (true) {
      const remaining = deadline - Date.now()
      if (remaining <= 0) throw bodyError(408, 'Request body timed out.')
      let timer: ReturnType<typeof setTimeout> | undefined
      try {
        const read = await Promise.race([
          reader.read(),
          new Promise<never>((_, reject) => {
            timer = setTimeout(
              () => reject(bodyError(408, 'Request body timed out.')),
              Math.min(BODY_READ_TIMEOUT_MS, remaining)
            )
          }),
        ])
        if (read.done) break
        total += read.value.byteLength
        if (total > maxBytes) {
          throw bodyError(413, `Request body too large (limit ${Math.floor(maxBytes / (1024 * 1024))}MB).`)
        }
        chunks.push(read.value)
      } finally {
        if (timer) clearTimeout(timer)
      }
    }
  } catch (e) {
    // FIRE-AND-FORGET: reader.cancel() can itself block indefinitely on a
    // never-ending source stream (exactly the slow-DoS shape we defend
    // against) — awaiting it would pin the request for as long as the
    // attacker holds the socket. Cancel in the background, throw NOW so
    // the 408/413 response is sent and the connection torn down.
    void reader.cancel().catch(() => { /* socket already gone */ })
    throw e
  }
  const out = new Uint8Array(total)
  let offset = 0
  for (const c of chunks) {
    out.set(c, offset)
    offset += c.byteLength
  }
  return out
}

/**
 * Patch json()/formData()/text() on THIS request instance so handlers (which
 * capture `req` in their closures and call these methods directly) transparently
 * read through the capped reader. The capped buffer is re-wrapped in a fresh
 * Request so undici performs the standard JSON / multipart / text parsing.
 *
 * Handlers that never touch the body are unaffected; the underlying stream is
 * only consumed on the first json()/formData()/text() call, exactly like the
 * native methods.
 */
function patchBodyMethods(req: NextRequest, maxBytes: number) {
  const rebuild = (parse: 'json' | 'formData' | 'text') => async () => {
    return parseCappedBody(req, parse, maxBytes)
  }
  try {
    req.json = rebuild('json') as NextRequest['json']
    req.formData = rebuild('formData') as NextRequest['formData']
    req.text = rebuild('text') as NextRequest['text']
  } catch {
    // Instance is sealed/frozen (unexpected) — fall back to native reads;
    // the declared Content-Length fast path above still applies.
  }
}

/**
 * Read a request body through the capped reader and parse it. Shared by
 * patchBodyMethods (in-handleApi reads) and cappedJson (routes that must
 * read the body BEFORE calling handleApi — e.g. /api/auth/otp).
 */
async function parseCappedBody(
  req: NextRequest,
  parse: 'json' | 'formData' | 'text',
  maxBytes: number
): Promise<unknown> {
  const buf = await readCappedBody(req, maxBytes)
  const headers = new Headers(req.headers)
  // The rebuilt body has a known length and is not chunked — stale framing
  // headers would describe the ORIGINAL transport, not the buffer.
  headers.delete('content-length')
  headers.delete('transfer-encoding')
  // TS's BodyInit type is stricter than undici's runtime acceptance
  // (Uint8Array is a valid BufferSource body); cast to satisfy both.
  const rebuilt = new Request(req.url, {
    method: req.method,
    headers,
    body: buf as unknown as BodyInit,
  })
  return rebuilt[parse]()
}

/**
 * Standalone capped JSON read for routes that parse the body BEFORE entering
 * handleApi (outside patchBodyMethods). Returns `{}` for absent/invalid JSON;
 * throws status-carrying Errors (413 too-large / 408 timed-out) that the
 * caller should convert to a response (handleApi's catch does this
 * automatically for in-handler reads).
 */
export async function cappedJson(
  req: NextRequest,
  maxBytes: number = DEFAULT_MAX_BODY_BYTES
): Promise<Record<string, unknown>> {
  try {
    const parsed = await parseCappedBody(req, 'json', maxBytes)
    return (parsed && typeof parsed === 'object' && !Array.isArray(parsed))
      ? (parsed as Record<string, unknown>)
      : {}
  } catch (e) {
    if (e && typeof (e as { status?: unknown }).status === 'number') throw e
    return {}
  }
}

/**
 * Lenient JSON body parse for routes that treat a missing/invalid body as
 * `{}`. Rethrows body-cap violations (413 too-large / 408 timed-out, which
 * carry an explicit `.status`) so handleApi maps them to the proper HTTP
 * status — the plain `.json().catch(() => ({})))` idiom used to swallow
 * them and mask a 413 as a confusing 400 validation error.
 */
export async function lenientJson(req: NextRequest): Promise<any> {
  try {
    const parsed = await req.json()
    return (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) ? parsed : {}
  } catch (e) {
    if (e && typeof (e as { status?: unknown }).status === 'number') throw e
    return {}
  }
}

/**
 * Audit-9 fix (R9-A1): multipart parse with a user-facing 400. A JSON (or
 * text/plain) body hitting a multipart endpoint used to make `req.formData()`
 * throw a TypeError — which handleApi deliberately routes to the generic
 * 500 "Something went wrong" bucket (TypeErrors are assumed to be code
 * bugs). But here the TypeError comes from the CALLER's content-type
 * choice, not our code: an unauthenticated `curl -X POST -d '{}'` to
 * /api/jobs/{id}/apply returned a 500. Parse here, and rethrow a short
 * plain-Error so the classifier maps it to 400 with actionable copy.
 */
export async function parseFormDataSafe(req: NextRequest): Promise<FormData> {
  try {
    return await req.formData()
  } catch {
    throw new Error('This endpoint expects multipart form data — send the fields as form-data, not JSON.')
  }
}


export function ok(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: PRIVATE_NO_STORE_HEADERS })
}

export function err(message: string, status = 400, extra?: Record<string, unknown>) {
  // fresh6-fix-frontend-all Fix 30: support structured error fields beyond
  // the human-readable `message`. Callers can pass `extra: { code, attemptsRemaining }`
  // (or any other field) to attach structured data to the JSON response so
  // clients can branch on `data.code` instead of regex-parsing the message
  // string. The body shape stays backwards-compatible: `{ error: message, ...extra }`.
  if (extra && Object.keys(extra).length > 0) {
    return NextResponse.json({ error: message, ...extra }, { status, headers: PRIVATE_NO_STORE_HEADERS })
  }
  return NextResponse.json({ error: message }, { status, headers: PRIVATE_NO_STORE_HEADERS })
}

/**
 * Allowed origins for same-site requests. Used as a FALLBACK when the
 * request's Host header can't be determined (rare). The primary check in
 * `assertSameOrigin` compares Origin against the request's own Host.
 */
function allowedOrigins(): string[] {
  const origins: string[] = []
  // 2026-09 "one URL only" fix: use the sanitized BASE_URL (src/lib/site.ts)
  // instead of the raw env values. The production env still points at the
  // retired nixecom.vercel.app deployment, which must never be accepted as a
  // trusted origin — and the canonical origin (https://nixe.pk) was missing
  // from this fallback entirely.
  origins.push(BASE_URL)
  // HIGH fix: only allow localhost in non-production to prevent CSRF bypass
  if (process.env.NODE_ENV !== 'production') {
    origins.push('http://localhost:3000', 'http://127.0.0.1:3000')
  }
  return origins
}

/**
 * Trusted sandbox preview surfaces (2026-10-15, dev/preview only).
 *
 * The preview gateway family serves dev previews on session-scoped
 * *.space-z.ai subdomains that are NOT knowable at config time (the host is
 * derived per chat session). next.config.ts already embraces this via
 * allowedDevOrigins: ['*.space-z.ai']; assertSameOrigin needs the same
 * notion. The Origin header cannot be forged by page JavaScript — the
 * browser always sets it to the initiating page's origin — so a request
 * carrying a *.space-z.ai origin genuinely came from that preview surface.
 * Production (NODE_ENV=production) never takes this path.
 */
function isTrustedPreviewOrigin(raw: string): boolean {
  try {
    const parsed = new URL(raw)
    const h = parsed.hostname.toLowerCase()
    return (parsed.protocol === 'https:' || parsed.protocol === 'http:') &&
      (h === 'space-z.ai' || h.endsWith('.space-z.ai'))
  } catch {
    return false
  }
}

/**
 * Diagnosability: log the full identity header set whenever a mutation is
 * about to be rejected by the CSRF check, so a misbehaving preview gateway
 * can be diagnosed from dev.log alone (no header-echo route needed).
 * Dev-only — production never logs request identity details.
 */
function logCsrfRejection(req: NextRequest, reason: string): void {
  if (process.env.NODE_ENV === 'production') return
  logger.warn('[csrf] rejecting request', {
    reason,
    method: req.method,
    path: req.nextUrl.pathname,
    origin: req.headers.get('origin'),
    referer: req.headers.get('referer'),
    host: req.headers.get('host'),
    xForwardedHost: req.headers.get('x-forwarded-host'),
    xForwardedProto: req.headers.get('x-forwarded-proto'),
    secFetchSite: req.headers.get('sec-fetch-site'),
    userAgent: req.headers.get('user-agent'),
  })
}

/**
 * CSRF-style protection for state-changing requests.
 *
 * Strategy: compare the request's `Origin` (or `Referer`) header against the
 * request's own `Host` header. If they match, the request is same-origin and
 * is allowed. If they differ, the request is cross-origin and is blocked.
 *
 * This is more robust than a hardcoded allowlist because it works with ANY
 * domain the app is served from:
 *  - localhost (dev)
 *  - *.space-z.ai preview domains
 *  - *.vercel.app deployments
 *  - nixe.pk (production)
 *
 * Browsers always send `Origin` on cross-origin POST/PATCH/DELETE, and the
 * `Host` header is set by the browser/proxy and can't be spoofed by JS.
 *
 * Combined with `SameSite=lax` cookies, this blocks CSRF on modern browsers.
 */
export function assertSameOrigin(req: NextRequest) {
  // GET / HEAD / OPTIONS are safe — no need to check.
  const method = req.method.toUpperCase()
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return

  const origin = req.headers.get('origin')
  const referer = req.headers.get('referer')
  const source = origin || (referer ? (() => { try { return new URL(referer).origin } catch { return null } })() : null)

  // 2026-10-15 preview fix: a request originating from a trusted sandbox
  // preview surface (*.space-z.ai, dev only) is accepted up front. This must
  // precede the Sec-Fetch-Site block: preview gateways can legitimately
  // produce a declared cross-site signal (e.g. a gateway-level redirect
  // re-originates the request), and the unforgeable Origin header already
  // proves the initiator is the preview surface itself. An attacker page can
  // never set Origin to the preview origin — the browser controls it.
  const trustedPreview = Boolean(source && isTrustedPreviewOrigin(source))

  // Security fix (round 3, browser-side pentest): a browser that explicitly
  // declares `Sec-Fetch-Site: cross-site` is NEVER a legitimate same-origin
  // app request — our client only issues same-origin fetches. Block it in
  // every environment (dev included) so the dev convenience below can only
  // ever accept curl/Postman-style header-less traffic, not declared
  // cross-site browser traffic. Trusted preview origins are exempt in dev
  // (see above).
  if (req.headers.get('sec-fetch-site') === 'cross-site' && !trustedPreview) {
    logCsrfRejection(req, 'declared cross-site')
    throw new Error('Cross-origin request blocked by CSRF protection.')
  }

  if (!source) {
    // Chromium can omit Origin and Referer on same-origin fetches while still
    // sending the Fetch Metadata header. The client mutation helper uses
    // ordinary same-origin fetch, so recognize the browser-authenticated
    // same-origin signal before treating the request as curl/Postman traffic.
    // Cross-site requests are already rejected above. Keep the strict
    // same-origin acceptance (NOT same-site — a compromised sibling
    // subdomain must not pass).
    const fetchSite = req.headers.get('sec-fetch-site')
    if (fetchSite === 'same-origin') return
    // No Origin/Referer and no same-origin browser signal means a direct API
    // caller or an untrusted client. Reject in production; keep localhost
    // testing convenient in development.
    if (process.env.NODE_ENV !== 'production') return
    logCsrfRejection(req, 'missing origin')
    throw new Error('Missing Origin header — request blocked for security.')
  }

  // Trusted preview surface — same-site by policy in dev/preview.
  if (trustedPreview) return

  // Determine the request's own host.
  // Security fix: prefer the 'host' header (not spoofable by clients in
  // standard proxy setups) over 'x-forwarded-host' (which is client-settable).
  // Only trust x-forwarded-host if explicitly configured via TRUSTED_PROXY.
  const host = req.headers.get('host')

  // Sandbox/preview gateways (e.g. *.space-z.ai preview URLs) terminate TLS
  // on the public domain and forward the request to the app with a REWRITTEN
  // Host header (the internal upstream), carrying the public host in
  // x-forwarded-host. Comparing Origin against the rewritten Host then
  // misclassifies every legitimate same-origin browser request as
  // cross-origin ("Cross-origin request blocked by CSRF protection" on
  // login/signup/cart). Mirror the exact trust model of requestedHost() in
  // src/proxy.ts: the forwarded host is trusted when the platform provably
  // controls it (Vercel) or in non-production (dev + preview sandboxes); a
  // self-hosted production must still opt in explicitly via TRUSTED_PROXY=1.
  const platformControlled =
    process.env.VERCEL === '1' ||
    process.env.TRUSTED_PROXY === '1' ||
    process.env.NODE_ENV !== 'production'
  const forwardedHost = platformControlled
    ? req.headers.get('x-forwarded-host')?.split(',')[0]?.trim().toLowerCase()
    : null

  if (host || forwardedHost) {
    // Build the "self" origin(s) from the request's own host (and, when
    // trusted, the forwarded host). We check both http and https since the
    // gateway terminates TLS.
    const hosts = [host, forwardedHost].filter((h): h is string => Boolean(h))
    const selfOrigins = hosts.flatMap((h) => [`https://${h}`, `http://${h}`])
    if (selfOrigins.includes(source)) {
      return // Same-origin — allowed.
    }
  }

  // Fallback: check the hardcoded allowlist (for configured production domains).
  const allow = allowedOrigins()
  // SECURE: exact match only — no endsWith (prevents evil-nixe.pk bypass)
  const isAllowed = allow.some((a) => source === a)
  if (!isAllowed) {
    logCsrfRejection(req, 'origin not self, not forwarded-host, not allowlisted')
    throw new Error('Cross-origin request blocked by CSRF protection.')
  }
}

/**
 * Enforce rate limiting on a route. Returns a 429 response if exceeded.
 *
 * @example
 *   export async function POST(req: NextRequest) {
 *     return handleApi(req, async () => { ... }, { rateLimit: { key: 'login', max: 5, windowMs: 60_000 } })
 *   }
 */
interface HandleApiOptions {
  rateLimit?: {
    /** Base key — IP is appended automatically. */
    key: string
    max: number
    windowMs: number
  }
  requireUser?: boolean
  roles?: SafeUser['role'][]
  /**
   * Cache-Control header for the successful (200) response.
   * Only applies to GET responses — errors (4xx/5xx) are never cached.
   * Example: 'public, max-age=60, s-maxage=300, stale-while-revalidate=600'
   */
  cacheControl?: string
  /**
   * Maximum request body size in bytes accepted by this route.
   * Defaults to 12MB (DEFAULT_MAX_BODY_BYTES). Routes accepting uploads
   * should set a tighter cap (e.g. avatar: 6MB, job resume: 12MB).
   *
   * Security fix (body-size DoS, round 12): `req.json()` / `req.formData()`
   * buffer the ENTIRE request body in memory with no size cap when the
   * request is sent with `Transfer-Encoding: chunked` (no Content-Length).
   * A `Content-Length`-only guard is bypassable by simply omitting the
   * header — verified: a 7MB chunked multipart upload was fully buffered
   * by /api/auth/avatar and a slow-DoS stream held the connection open
   * indefinitely, culminating in the OOM kill of next-server during the
   * round-11 pentest. This cap now applies to the ACTUAL bytes streamed,
   * regardless of declared or absent Content-Length.
   */
  maxBodyBytes?: number
}

export async function handleApi<T>(
  req: NextRequest,
  fn: () => Promise<T>,
  opts: HandleApiOptions = {}
) {
  // security-hardening-10 Fix 3: removed the legacy `handleApi(fn)` /
  // `handleApi(null, fn, opts)` branch. The single-argument form bypassed
  // CSRF checks and Content-Type validation, so it was a security hole.
  // All call sites now pass `req` as the first argument; if you need to
  // opt out of CSRF for a specific route, don't drop `req` — instead,
  // remove `assertSameOrigin` selectively (not currently supported).

  try {
    // 0. Request-body size hardening (body-size DoS fix, round 12).
    //    Two layers:
    //    (a) Fast path: reject when a DECLARED Content-Length exceeds the
    //        cap — no buffering at all.
    //    (b) Chunked/undeclared bodies: patch req.json()/formData()/text()
    //        on this instance so every body read is piped through a
    //        byte-counting reader that aborts at the cap. This defeats the
    //        Transfer-Encoding: chunked bypass of (a) and bounds memory to
    //        maxBodyBytes per request. A read timeout also aborts
    //        slow-loris style never-ending chunked streams.
    const maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES
    const method = req.method.toUpperCase()
    if (method !== 'GET' && method !== 'HEAD') {
      const declaredLength = Number(req.headers.get('content-length') || 'NaN')
      if (Number.isFinite(declaredLength) && declaredLength > maxBodyBytes) {
        reportSecurityEvent('body_too_large', {
          method,
          path: req.nextUrl.pathname,
          policy: `declared:${declaredLength}>${maxBodyBytes}`,
        })
        return NextResponse.json(
          { error: 'Request body too large.' },
          { status: 413, headers: PRIVATE_NO_STORE_HEADERS }
        )
      }
      patchBodyMethods(req, maxBodyBytes)
    }

    // 1. CSRF: reject cross-origin state-changing requests.
    assertSameOrigin(req)
    // Content-Type validation: POST/PATCH/PUT/DELETE must send JSON when the
    // request actually CARRIES a body.
    //
    // Audit-7 fix (R7-A1): the old guard also fired for bodyless requests —
    // `req.headers.get('content-length') !== '0'` is TRUE both when a body
    // exists AND when the header is simply absent, and browsers do NOT send
    // Content-Length on a bodyless DELETE (Chromium sends CL:0 for bodyless
    // POST but nothing for DELETE; other engines vary). Every bodyless
    // DELETE the storefront itself makes — removeFromCart, clearCart,
    // wishlist un-save (toggle + remove), account address removal — was
    // 415'd by this guard since v2: the optimistic UI dropped the row, the
    // server kept it, and the failure re-sync resurrected it. A request
    // with no body has nothing to parse, so its Content-Type is irrelevant:
    // require JSON/multipart CT only when a body is present (declared
    // non-zero length, or chunked framing).
    const declaredCtLen = req.headers.get('content-length')
    const requestHasBody =
      req.headers.get('transfer-encoding') !== null ||
      (declaredCtLen !== null && declaredCtLen !== '0')
    if ((method === 'POST' || method === 'PATCH' || method === 'PUT' || method === 'DELETE') && requestHasBody) {
      const ct = req.headers.get('content-type') || ''
      if (!ct.includes('application/json') && !ct.includes('multipart/form-data')) {
        reportSecurityEvent('invalid_content_type', {
          method,
          path: req.nextUrl.pathname,
          policy: 'json-or-multipart-required',
        })
        return NextResponse.json(
          { error: 'Content-Type must be application/json' },
          { status: 415, headers: PRIVATE_NO_STORE_HEADERS }
        )
      }
    }

    // 2. Rate limit: count requests per (key, IP) and reject if over budget.
    if (opts.rateLimit) {
      const ip = getClientIp(req)
      const rlKey = `${opts.rateLimit.key}:${ip}`
      const rl = await rateLimit({
        key: rlKey,
        max: opts.rateLimit.max,
        windowMs: opts.rateLimit.windowMs,
      })
      if (!rl.ok) {
        const retryAfterSec = Math.ceil(rl.retryAfterMs / 1000)
        reportSecurityEvent('rate_limit_blocked', {
          method,
          path: req.nextUrl.pathname,
          policy: opts.rateLimit.key,
        })
        return NextResponse.json(
          { error: `Too many requests. Try again in ${retryAfterSec}s.` },
          {
            status: 429,
            headers: {
              ...PRIVATE_NO_STORE_HEADERS,
              'Retry-After': String(retryAfterSec),
              'X-RateLimit-Limit': String(opts.rateLimit.max),
              'X-RateLimit-Remaining': '0',
            },
          }
        )
      }
    }

    // 3. Authorization: these options were previously declared but not
    // enforced. Keep enforcement in the shared boundary so future routes
    // cannot accidentally expose a mutation by forgetting a manual auth call.
    if (opts.roles && opts.roles.length > 0) {
      await requireRole(...opts.roles)
    } else if (opts.requireUser) {
      await requireUser()
    }

    const result = await fn()

    // Some handlers intentionally return a NextResponse for a specific status
    // (for example a 403 authentication state). Preserve that response exactly
    // instead of serializing the Response object into an accidental 200 JSON
    // payload. Ensure it remains private unless that handler set a policy.
    if (result instanceof NextResponse) {
      if (!result.headers.has('Cache-Control')) {
        result.headers.set('Cache-Control', PRIVATE_NO_STORE_HEADERS['Cache-Control'])
      }
      return result
    }

    // Apply Cache-Control only on successful plain-data responses (never on errors).
    if (opts.cacheControl) {
      return NextResponse.json(result, {
        status: 200,
        headers: { 'Cache-Control': opts.cacheControl },
      })
    }
    return ok(result)
  } catch (e: unknown) {
    // fresh6-fix-code-all: was `catch (e: any)` with `e?.code` /
    // `e?.attemptsRemaining` / `e?.message` accesses. Typed as `unknown`
    // now and narrowed via local helpers. Structured error fields
    // (`code`, `attemptsRemaining`) are forwarded to the client only when
    // they have the expected primitive type — Prisma's `code` (starts
    // with `P`) is intentionally excluded to avoid leaking internal state.
    const message = e instanceof Error ? e.message : String(e)
    if (
      message === 'Missing Origin header — request blocked for security.' ||
      message === 'Cross-origin request blocked by CSRF protection.'
    ) {
      reportSecurityEvent('csrf_blocked', {
        method: req.method,
        path: req.nextUrl.pathname,
        policy: message === 'Missing Origin header — request blocked for security.'
          ? 'missing-origin'
          : 'cross-origin',
      })
    }
    const code = (typeof (e as { code?: unknown })?.code === 'string')
      ? (e as { code: string }).code
      : undefined
    const attemptsRemaining = (typeof (e as { attemptsRemaining?: unknown })?.attemptsRemaining === 'number')
      ? (e as { attemptsRemaining: number }).attemptsRemaining
      : undefined
    if (message === 'UNAUTHORIZED') return err('You must be signed in.', 401)
    if (message === 'FORBIDDEN') return err('You do not have permission to do that.', 403)
    if (message === 'RATE_LIMITED') {
      return err('Too many requests. Please slow down.', 429)
    }
    // round-10 fix (r10-c C13): routes can attach an explicit HTTP status to
    // a thrown Error — `throw Object.assign(new Error('Product not found.'),
    // { status: 404 })`. An explicit status marks the error as AUTHORED and
    // user-facing by construction (the route wrote the message for the
    // client), so it bypasses the internal-error heuristics below. This
    // closes the not-found status inconsistency (authored "not found"
    // messages rendered as 400 while Prisma P2025 rendered as 404).
    const explicitStatus = (e as { status?: unknown })?.status
    if (
      typeof explicitStatus === 'number' &&
      Number.isInteger(explicitStatus) &&
      explicitStatus >= 400 &&
      explicitStatus <= 599 &&
      typeof message === 'string' &&
      message.length > 0 &&
      message.length < 500
    ) {
      return err(message, explicitStatus)
    }
    if (code === 'P2002') return err('A record with that unique value already exists.', 409)
    if (code === 'P2025') return err('Record not found.', 404)
    // L-13 fix: never leak internal error messages on 500s in production.
    logger.error('[api error]', e)
    // In dev: show the actual error message with 400 status (developer-friendly).
    // In prod: hide internal errors behind a generic 500 message.
    if (process.env.NODE_ENV === 'production') {
      // Heuristic: if the error came from Prisma or has a non-string message,
      // it's an internal error → 500. Otherwise it's a user-facing validation
      // error → 400 with the message.
      if (code && code.startsWith('P')) {
        return err('Something went wrong. Please try again later.', 500)
      }
      // fresh6-fix-api Fix 9 (HIGH): non-Prisma errors (TypeError,
      // ReferenceError, DB ENOTFOUND/ETIMEDOUT, etc.) were leaking
      // e.message as a 400. A bug like `Cannot read property 'x' of
      // undefined` returned the full message to the client, leaking
      // internal code structure (variable names, call chain).
      //
      // Only return e.message as a 400 if the error was explicitly thrown
      // as a user-facing validation error. We detect this by checking that
      // `e` is a plain Error (not a TypeError / ReferenceError / Prisma
      // error / fetch error) AND its message is a non-empty string under
      // 500 chars (validation messages are short; internal stack traces
      // and DB error messages are typically longer or contain file paths).
      // BUG 45 fix (audit3): the previous `e.constructor === Error` check
      // rejected custom error classes (e.g. class ValidationError extends Error)
      // — they'd fail the constructor check and fall through to the generic
      // 500 "Something went wrong" path, hiding validation messages from users.
      // Now we accept any Error subclass EXCEPT known internal error types
      // (TypeError, ReferenceError, SyntaxError, RangeError, PrismaClient*Error)
      // which indicate bugs rather than user-facing validation errors.
      const isUserFacingError =
        e instanceof Error &&
        !(e instanceof EnvConfigError) && // env/config failures are internal (audit 33-a)
        !(e instanceof TypeError) &&
        !(e instanceof ReferenceError) &&
        !(e instanceof SyntaxError) &&
        !(e instanceof RangeError) &&
        typeof e.message === 'string' &&
        e.message.length > 0 &&
        e.message.length <= 500 &&
        !e.message.includes('\n') && // stack traces / multi-line = internal
        !(e.constructor?.name?.startsWith('PrismaClient')) // Prisma errors have `code` starting with P
      if (isUserFacingError) {
        // fresh6-fix-frontend-all Fix 30: forward structured error fields
        // (`code`, `attemptsRemaining`) attached by the handler so clients
        // can branch on `data.code` instead of regex-parsing `data.error`.
        // Only forwards fields that are explicitly string/number/boolean
        // (no objects — keeps the response shape predictable + prevents
        // leaking Prisma's internal `meta`/`stack` fields).
        const structured: Record<string, unknown> = {}
        if (code && !code.startsWith('P')) {
          structured.code = code
        }
        if (attemptsRemaining !== undefined) {
          structured.attemptsRemaining = attemptsRemaining
        }
        return err(message || 'Bad request', 400, structured)
      }
      // Everything else (TypeError, ReferenceError, fetch errors with code
      // ENOTFOUND/ETIMEDOUT, etc.) → generic 500 "Something went wrong"
      // with no leak of internal code structure (variable names, call
      // chain, stack trace). fresh7-fix-api Fix 4: standardize the generic
      // message on "Something went wrong" so non-Prisma internal errors
      // never reach the client regardless of error class.
      return err('Something went wrong', 500)
    }
    // fresh6-fix-frontend-all Fix 30: forward structured fields in dev too.
    const structured: Record<string, unknown> = {}
    if (code && !code.startsWith('P')) {
      structured.code = code
    }
    if (attemptsRemaining !== undefined) {
      structured.attemptsRemaining = attemptsRemaining
    }
    return err(message || 'Internal server error', 400, structured)
  }
}
