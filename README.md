# NIXE OTP Workflow — Legacy Gmail-SMTP (nodemailer) → Resend REST API

This repository contains **only the files that changed** to move the entire OTP/email workflow from Gmail SMTP (`nodemailer`) to the **Resend REST API** — not the full app codebase.

The implementation is production-verified end-to-end: real temp-mail inbox delivery, signup / reset / 2FA-login / admin-unlock OTP codes, lockouts, rate caps, and Resend dashboard logs all confirmed working.

---

## Repository map

| Path in this repo | Action in your project |
|---|---|
| `src/lib/resend.ts` | **ADD** — new Resend REST client (plain `fetch`, zero dependencies) |
| `src/lib/email.ts` | **OVERWRITE** — all OTP + transactional mail now via Resend; public exports unchanged |
| `src/lib/api.ts` | **OVERWRITE** — CSRF: trust preview-gateway forwarded hosts (dev only) |
| `src/lib/db.ts` | **OVERWRITE** — Postgres advisory-lock fix in `withKeyLock()` |
| `src/app/forgot-password/forgot-password-client.tsx` | **OVERWRITE** — 6-digit reset-code UX copy |
| `reference/src/lib/otp.ts` | **READ ONLY** — unchanged OTP core (hashing, expiry, lockout, caps) |
| `reference/src/app/api/auth/otp/route.ts` | **READ ONLY** — `POST /api/auth/otp` (`send`/`verify`) |
| `reference/src/app/api/auth/route.ts` | **READ ONLY** — signup / login / 2FA / reset-password endpoints |
| `patches/` | The 4 exact upstream commits (`git am patches/*.patch`) |
| `PROMPT.md` | Ready-to-paste instructions for an AI coding agent |
| `ENV-SETUP.txt` | Environment variables to add and delete |

---

## 1) Email delivery — OLD vs NEW

### OLD — Gmail SMTP via nodemailer (REMOVED)

```ts
// src/lib/email.ts (before)
import nodemailer from 'nodemailer'
import type { Transporter, SendMailOptions } from 'nodemailer'

const EMAIL_USER = process.env.EMAIL_USER || ''
const EMAIL_PASS = process.env.EMAIL_PASS || ''
const SMTP_HOST = process.env.SMTP_HOST || ''
const SMTP_PORT = Number(process.env.SMTP_PORT || '587')
const SMTP_SECURE = process.env.SMTP_SECURE === 'true'
const SMTP_REQUIRE_TLS = process.env.SMTP_REQUIRE_TLS === 'true'
const FROM_NAME = process.env.EMAIL_FROM_NAME || 'NIXE'
const FROM_EMAIL = process.env.EMAIL_FROM || EMAIL_USER

let transporter: Transporter | null = null

function getTransporter(): Transporter | null {
  if (!EMAIL_USER || !EMAIL_PASS) return null
  if (!transporter) {
    transporter = nodemailer.createTransport({
      // service: 'gmail'  (or SMTP_HOST/port/secure config)
      auth: { user: EMAIL_USER, pass: EMAIL_PASS },
      // bound timeouts so an SMTP outage cannot hang auth requests
    })
  }
  return transporter
}

export async function sendOtpEmail(to, code, type): Promise<boolean> {
  const transport = getTransporter()
  if (!transport) {
    throw new Error('Email service not configured. Add EMAIL_USER and EMAIL_PASS to .env')
  }
  // ... build subject / html / text ...
  await transport.sendMail(mailOptions)          // ← SMTP send
  return true
}
```

### NEW — Resend REST API (ADDED: `src/lib/resend.ts`)

```ts
// src/lib/resend.ts (new file — plain fetch, NO SDK, no new dependencies)
const RESEND_API_KEY = process.env.RESEND_API_KEY || ''
const RESEND_FROM = process.env.RESEND_FROM || 'NIXE <onboarding@resend.dev>'
const RESEND_REPLY_TO = process.env.RESEND_REPLY_TO || ''

export const isResendConfigured = Boolean(RESEND_API_KEY)

function safeHeader(value: string): string { /* strips CR/LF — header-injection guard */ }

export async function sendViaResend(opts: ResendSendOptions): Promise<{ id: string }> {
  if (!RESEND_API_KEY) {
    throw new Error('Email service not configured. Add RESEND_API_KEY to .env')
  }
  const payload: Record<string, unknown> = {
    from: safeHeader(RESEND_FROM),
    to: opts.to,
    subject: opts.subject,
    html: opts.html,
    text: opts.text,
    // attachments: [{ filename, content: <base64>, content_id }] → inline CID,
    // exactly like nodemailer's `cid:` option (used for the NIXE logo)
  }
  if (RESEND_REPLY_TO) payload.reply_to = safeHeader(RESEND_REPLY_TO)

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
    // bound timeout — mirrors the old SMTP socket-timeout behaviour
  })
  // non-2xx → throws with Resend's error message
}
```

### The OTP send path in `email.ts` — OLD vs NEW

```ts
// OLD (SMTP):
const transport = getTransporter()
if (!transport) {
  throw new Error('Email service not configured. Add EMAIL_USER and EMAIL_PASS to .env')
}
// ...
await transport.sendMail(mailOptions)
return true
```

```ts
// NEW (Resend):
if (!isResendConfigured) {
  throw new Error('Email service not configured. Add RESEND_API_KEY to .env')
}
// ... same templates, same 6-digit code, same subjects ...
const safeTo = sanitizeHeader(to)
const safeSubject = sanitizeHeader(subject)

// delivered via the Resend REST API. The attachments entry carries
// content_id: 'nixelogo' — identical inline-CID behaviour to nodemailer's cid:
await sendViaResend({
  to: safeTo,
  subject: safeSubject,
  html,
  text,
  attachments: logoBuffer
    ? [{ filename: 'nixe-logo.png', content: logoBuffer.toString('base64'), content_id: 'nixelogo' }]
    : undefined,
})
return true
```

**What stayed the same:** `sendOtpEmail()` signature and every export (`isEmailConfigured`, `sendAlreadyRegisteredEmail`, `sendOrderConfirmationEmail`, `sendContactEmail`, `sendSellerVerificationEmail`, `sendJobApplicationEmail`) — so zero call-site changes. All other transactional senders now also deliver through `sendViaResend()`.

---

## 2) CSRF — OLD vs NEW (`src/lib/api.ts`)

Preview gateways terminate TLS on the public domain and forward requests with a **rewritten Host header**, carrying the public host in `x-forwarded-host`. Comparing Origin against the rewritten Host misclassified every legitimate same-origin request as cross-origin ("Cross-origin request blocked by CSRF protection" on login/signup).

```ts
// OLD:
const host = req.headers.get('host')
if (host) {
  const selfOrigins = [`https://${host}`, `http://${host}`]
  if (selfOrigins.includes(source)) return // Same-origin — allowed.
}
```

```ts
// NEW:
const platformControlled =
  process.env.VERCEL === '1' ||
  process.env.TRUSTED_PROXY === '1' ||
  process.env.NODE_ENV !== 'production'
const forwardedHost = platformControlled
  ? req.headers.get('x-forwarded-host')?.split(',')[0]?.trim().toLowerCase()
  : null

if (host || forwardedHost) {
  const hosts = [host, forwardedHost].filter((h): h is string => Boolean(h))
  const selfOrigins = hosts.flatMap((h) => [`https://${h}`, `http://${h}`])
  if (selfOrigins.includes(source)) return // Same-origin — allowed.
}
// ...
if (!isAllowed) {
  logCsrfRejection(req, 'origin not self, not forwarded-host, not allowlisted')
  throw new Error('Cross-origin request blocked by CSRF protection.')
}
```

Forwarded hosts are trusted only when the platform provably controls them (Vercel) or in non-production (dev + preview sandboxes). Self-hosted production must still opt in via `TRUSTED_PROXY=1`.

---

## 3) Postgres advisory lock — OLD vs NEW (`src/lib/db.ts`)

`pg_advisory_xact_lock()` returns `void`; Prisma's `$queryRaw` cannot deserialize a void column and throws `Failed to deserialize column of type 'void'` — which 500'd every `withKeyLock()` caller on Postgres: **login lockout accounting, OTP issuance caps, bait-row lockouts**.

```ts
// OLD (breaks on Postgres + Prisma 7 driver adapters):
return db.$transaction(async (tx) => {
  await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${key})::bigint)`
  return fn(tx)
})
```

```ts
// NEW ($executeRaw runs the statement and skips result-column deserialization):
return db.$transaction(async (tx) => {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${key})::bigint)`
  return fn(tx)
})
```

---

## 4) Forgot-password UX — OLD vs NEW copy

| OLD | NEW |
|---|---|
| "Enter the email tied to your account and we'll send you a secure **reset link**." | "Enter the email tied to your account and we'll **email you a 6-digit reset code**." |
| "We sent a 6-digit reset code to **{email}**. It expires in 10 minutes." | "**If an account exists for** {email}, a 6-digit reset code is on its way. It expires in 10 minutes." (no account-enumeration leak) |
| — | NEW hint: "No email after a few minutes? Check your spam folder, request a new code below, or start over with the correct address." + a **start-over** link button that clears the code entry |

---

## 5) Environment variables — OLD vs NEW

| OLD (DELETE everywhere) | NEW (ADD) |
|---|---|
| `EMAIL_USER` | `RESEND_API_KEY="re_..."` |
| `EMAIL_PASS` | `RESEND_FROM="NIXE <onboarding@resend.dev>"` — sandbox delivers only to your own Resend account email; verify a domain at resend.com for real users |
| `EMAIL_FROM`, `EMAIL_FROM_NAME` | `RESEND_REPLY_TO=""` (optional) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_REQUIRE_TLS` | — |

Also remove from `package.json`: `nodemailer`, `@types/nodemailer`.

## 6) Purge checklist for the old code

```bash
npm uninstall nodemailer @types/nodemailer        # or: remove from package.json + install
grep -rn "nodemailer\|EMAIL_PASS\|EMAIL_USER\|SMTP_\|Transporter" src/
# → must return ZERO hits after integration
```

## 7) Integration

Hand `PROMPT.md` to your AI coding agent — it contains the step-by-step integration, what NOT to change, and an 8-step verification checklist (real-inbox delivery, single-use codes, 5-attempt lockout, 2FA, delivery-failure auto-invalidation).

## OTP semantics preserved by this migration (do not change)

6-digit codes (`crypto.randomInt`) · 10-minute expiry · single-use, stored **hashed** · 5 failed verifies → 15-minute lock · 3 sends/10 min per (email, type) · 6 sends/10 min aggregate per email · OTP row auto-invalidated when the email fails to send.
