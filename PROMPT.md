# TASK — Replace legacy OTP/SMTP email delivery with Resend REST API (verified working implementation)

## ROLE

You are a senior Next.js/TypeScript engineer. You are integrating a **battle-tested, production-verified email/OTP package** into this codebase. Follow the steps below EXACTLY and in order. Do not improvise beyond the stated scope, do not refactor unrelated code, and do not "improve" the shipped files — they are verified working end-to-end (real inbox delivery + full auth E2E). If something in this repo already matches the package, keep the package version.

## CONTEXT

- Stack: Next.js 16 App Router + React 19 + TypeScript, Tailwind, Prisma 7 with driver adapters (`src/lib/db.ts` auto-branches: `postgres://` → `@prisma/adapter-pg`, `file:` → `@prisma/adapter-libsql`).
- Current state of this repo: all emails (OTP + transactional) are sent through **Gmail SMTP via `nodemailer`** (env vars `EMAIL_USER`, `EMAIL_PASS`, `SMTP_*`). This is the legacy mechanism you must **completely wipe**.
- Goal state: **all email delivery via Resend** (https://resend.com) using a plain `fetch` call to `POST https://api.resend.com/emails` with a Bearer key. **No SDK, no new dependencies.**
- The OTP verification core (code hashing, expiry, attempt limits, lockout) is already correct and must NOT change.

## FILE MAP — every file in this repository

Copy each file from THIS repo into the target project at the **same relative path**. `README.md` documents the old-vs-new code in detail.

| File in this repo | Action in your project |
|---|---|
| `src/lib/resend.ts` | COPY to `src/lib/resend.ts` — **new file** |
| `src/lib/email.ts` | OVERWRITE `src/lib/email.ts` — all templates + delivery via Resend; **exports identical**, zero call-site refactors |
| `src/lib/api.ts` | OVERWRITE `src/lib/api.ts` — CSRF: `assertSameOrigin()`, dev-only `isTrustedPreviewOrigin()` for preview proxies, `logCsrfRejection()` |
| `src/lib/db.ts` | OVERWRITE `src/lib/db.ts` — Prisma 7 driver-adapter client + Postgres advisory-lock fix (STEP 4) |
| `src/app/forgot-password/forgot-password-client.tsx` | OVERWRITE `src/app/forgot-password/forgot-password-client.tsx` — 6-digit reset-code UX |
| `reference/src/lib/otp.ts` | DO NOT COPY — context only: OTP core (6-digit, 10-min expiry, hashed single-use, 5 attempts → 15-min lock, send caps) |
| `reference/src/app/api/auth/otp/route.ts` | DO NOT COPY — context only: `POST /api/auth/otp` (`{action:'send'\|'verify', email, type:'signup'\|'reset'\|'login'\|'unlock'}`) |
| `reference/src/app/api/auth/route.ts` | DO NOT COPY — context only: `POST /api/auth` (signup / login / login-otp 2FA / reset-password / logout / toggle-2fa) |
| `patches/patch-0001…0004` | optional: `git am patches/*.patch` — the exact 4 upstream commits |
| `ENV-SETUP.txt` | env vars to add/remove |

## STEP 1 — Copy the files

```
cp src/lib/resend.ts        <your-project>/src/lib/resend.ts        # new file
cp src/lib/email.ts         <your-project>/src/lib/email.ts
cp src/lib/api.ts           <your-project>/src/lib/api.ts
cp src/lib/db.ts            <your-project>/src/lib/db.ts
cp src/app/forgot-password/forgot-password-client.tsx <your-project>/src/app/forgot-password/forgot-password-client.tsx
```

## STEP 2 — Environment variables

Add to `.env` and document in `.env.example`:

```
RESEND_API_KEY="re_xxxxxxxxxxxxxxxxxxxx"        # resend.com → API Keys → Create API Key
RESEND_FROM="NIXE <onboarding@resend.dev>"      # sandbox sender; OR a verified-domain sender, e.g. "NIXE <noreply@yourdomain.com>"
RESEND_REPLY_TO=""                              # optional reply-to address
```

**Critical Resend behavior to know:** `onboarding@resend.dev` only delivers to the email address that owns the Resend account (sandbox mode). For arbitrary recipients (real users), verify a domain at resend.com → Domains and use `RESEND_FROM="Name <noreply@thatdomain>"`.

DELETE these legacy SMTP variables from `.env` / `.env.example` and from any deployment settings:

```
EMAIL_USER  EMAIL_PASS  EMAIL_FROM  EMAIL_FROM_NAME
SMTP_HOST   SMTP_PORT   SMTP_SECURE  SMTP_REQUIRE_TLS
```

## STEP 3 — Purge the legacy OTP/SMTP mechanism completely

1. `package.json`: remove `nodemailer` and `@types/nodemailer` from dependencies, then reinstall (`npm install` / `bun install`).
2. Find every leftover: `grep -rn "nodemailer\|EMAIL_PASS\|EMAIL_USER\|SMTP_\|Transporter" src/` — delete or migrate each hit. After this step the grep must return **zero** results in `src/`.
3. If your copy has a separate legacy mailer module (e.g. `src/lib/mailer.ts`, `src/lib/smtp.ts`) or a duplicate/older OTP sender inside `email.ts`, delete it once you confirm nothing imports it.
4. Do **NOT** delete `src/lib/otp.ts`, `src/app/api/auth/otp/route.ts`, or `src/app/api/auth/route.ts` — they are the verified OTP core this package depends on.
5. If your copy's `src/lib/email.ts` diverged (extra templates), port the extra templates into the shipped `email.ts` using `sendViaResend()` — do NOT resurrect nodemailer for them.

## STEP 4 — Postgres advisory-lock fix inside the shipped `db.ts`

If you merge `db.ts` manually instead of overwriting, preserve this fix: the `withKeyLock()` Postgres branch must use **`$executeRaw`** (not `$queryRaw`) for `SELECT pg_advisory_xact_lock(...)`. On Prisma 7 + driver adapters, `$queryRaw` on that lock throws `Failed to deserialize column of type 'void'`, which silently breaks login lockout, OTP rate caps, and any other keyed critical section. This was a latent production bug — do not regress it.

## STEP 5 — CSRF notes inside the shipped `api.ts`

`assertSameOrigin()` enforces same-origin on all mutating API routes. `isTrustedPreviewOrigin()` additionally trusts preview-sandbox origins **in development only**. `logCsrfRejection()` records rejected cross-origin attempts. Keep all three when merging; do not loosen origin checks beyond this.

## WHAT NOT TO CHANGE — OTP semantics (already hardened & verified)

- 6-digit codes (`crypto.randomInt`), 10-minute expiry, single-use, stored **hashed**.
- Verify attempts: 5 failures → 15-minute lock per code. Send caps: 3 per (email, type) per 10 min, 6 aggregate per email per 10 min.
- **Delivery-failure auto-invalidation:** if the Resend call fails, the just-issued OTP row is invalidated so users never receive a dead code.
- OTP types: `signup | reset | login | unlock`. Endpoints and body shapes exactly as in the reference files.
- Prisma schema: **no changes required** — the OTP/User/Session models already exist.

## VERIFICATION CHECKLIST (run all, in order)

1. Build/dev boots with zero TypeScript errors; `grep -rn "nodemailer" src/` → empty; no SMTP env vars referenced.
2. `POST /api/auth/otp {"action":"send","email":"you@example.com","type":"signup"}` → `{"ok":true,...}` and the email **actually arrives** in a real inbox (also confirm in resend.com → Logs).
3. `POST /api/auth/otp {"action":"verify",...,"code":"123456"}` → `{"ok":true}`; a second verify with the same code fails (single-use).
4. Wrong code ×5 → locked with a clear message; correct code after lock window works again.
5. Forgot-password E2E: send reset OTP → verify → `POST /api/auth {"action":"reset-password",...}` → log in with the new password.
6. 2FA E2E: `toggle-2fa` on → login returns a `twoFactorChallenge` → `login-otp` with the emailed code → session cookie set.
7. Signup with an already-registered email → `sendAlreadyRegisteredEmail` still sends via Resend (no user enumeration leak).
8. Temporarily break `RESEND_API_KEY` → send OTP must fail gracefully AND auto-invalidate the OTP row (no dead codes), then restore the key.

## CONSTRAINTS

- No new dependencies (plain `fetch`; never add the Resend SDK).
- Keep TypeScript strict-mode clean; keep `safeHeader()` on every header-bound value.
- Do not touch anything outside email/OTP/CSRF/db-client scope.
- Report a summary of: files overwritten, leftovers deleted, grep results, and the verification checklist outcomes.
