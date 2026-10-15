import { NextRequest, NextResponse } from 'next/server'
import { logger } from '@/lib/logger'
import { db } from '@/lib/db'
import { handleApi, cappedJson } from '@/lib/api'
import { checkOtp, createOtp, ensureOtpSchemaReady } from '@/lib/otp'
import { sendOtpEmail, sendAlreadyRegisteredEmail, isEmailConfigured } from '@/lib/email'
import { validateEmail } from '@/lib/validate'
import { rateLimit } from '@/lib/rate-limit'
// BUG 41+42 fix (audit3): removed runPendingMigrations + withSelfHeal imports.
// Migrations run at deploy time (postinstall), never per-request. The previous
// code called runPendingMigrations() on every OTP send, adding 100-500ms
// latency and risking DB lock contention under load.

/**
 * OTP API — sends REAL verification codes via email.
 *
 * POST /api/auth/otp
 * Body: { action: 'send' | 'verify', email, type: 'signup'|'reset'|'login'|'unlock' }
 *
 * Security:
 *  - Code is generated with crypto.randomInt (CSPRNG)
 *  - Code is sent ONLY via email — NEVER returned in the response (C-6 fix)
 *  - Code is also logged to the server console (operator-only, for recovery)
 *  - Rate-limited: 30 requests per 10 min per IP (combined send+verify route
 *    limit below), plus 3 issued codes per 10 min per (email, type) and an
 *    aggregate 6 codes per 10 min per email across all types (lib/otp.ts)
 *  - Verify has a much higher rate limit (30/10min) so it's never blocked by sends
 *  - Type allowlist enforced
 *  - Email validated strictly
 */

const ALLOWED_TYPES = ['signup', 'reset', 'login', 'unlock'] as const
type OtpType = (typeof ALLOWED_TYPES)[number]

export async function POST(req: NextRequest) {
  // Read body once — through the capped reader (body-size DoS fix, round 12:
  // this route parses BEFORE handleApi patches req.json(), so it needs the
  // standalone capped read). Cap violations become proper 413/408 responses.
  let body: Record<string, unknown> = {}
  try {
    body = await cappedJson(req)
  } catch (e) {
    const status = (e as { status?: unknown })?.status
    if (typeof status === 'number') {
      return NextResponse.json(
        { error: e instanceof Error ? e.message : 'Request body rejected.' },
        { status, headers: { 'Cache-Control': 'private, no-store, max-age=0' } }
      )
    }
    /* empty body */
  }
  const action = body?.action

  // BUG 15: in production, if email is not configured, refuse to send OTPs
  // and return a clear 503 error. Do NOT pretend the email was sent — that
  // would mislead users into waiting for a code that never arrives.
  // In non-production (dev/test), still proceed so local development works
  // (the devCode is returned in the response further down).
  if (
    action === 'send' &&
    !isEmailConfigured &&
    process.env.NODE_ENV === 'production'
  ) {
    return NextResponse.json(
      { error: 'Email service not configured. Please contact support at support@nixe.pk.' },
      {
        status: 503,
        headers: { 'Cache-Control': 'private, no-store, max-age=0' },
      }
    )
  }

  // Use a high combined rate limit for the route (applies to both send & verify)
  // and a stricter per-email+type limit for sends inside the handler.
  // The verify action only attempts tracking inside checkOtp().
  return handleApi(
    req,
    async () => {
      const { type } = body

      const email = validateEmail(body.email as string)
      if (!type || !(ALLOWED_TYPES as readonly string[]).includes(type as string)) {
        throw new Error('Invalid request.')
      }
      const otpType = type as OtpType

      if (action === 'send') {
        // The rate-limit count touches OtpCode before createOtp can run its
        // readiness guard. Ensure the table exists first so a first-time 2FA
        // code request cannot fail with a generic database error.
        await ensureOtpSchemaReady()

        // Per-email+type rate limit: 3 issued codes per 10 min. Failed
        // verification marker rows are deliberately excluded: those rows track
        // incorrect guesses, not email deliveries. Counting them here could
        // strand a legitimate user after a typo because the very recovery
        // action (requesting a fresh code) became unavailable.
        const recent = await db.otpCode.count({
          where: {
            email,
            type: otpType,
            createdAt: { gt: new Date(Date.now() - 10 * 60 * 1000) },
            NOT: { code: { startsWith: '__failed_attempt__' } },
          },
        })
        if (recent >= 3) {
          throw new Error(
            'Too many codes requested. Please wait a few minutes before requesting another.'
          )
        }

        // BUG 41 fix (audit3): removed runPendingMigrations() — migrations run at
        // deploy time (postinstall), never per-request. The previous call added
        // 100-500ms latency to every OTP send and risked DB lock contention.

        // For login 2FA: only generate OTP if the user has 2FA enabled, but
        // do NOT reveal 2FA status in the response. The same generic message
        // is returned whether or not an OTP was actually sent.
        // Fix 4 (fresh4-fix-api): unify login OTP response to avoid leaking 2FA status.
        let suppressOtp = false
        if (otpType === 'login') {
          const user = await db.user.findUnique({ where: { email } })
          if (!user || !user.twoFactorOn) {
            suppressOtp = true
          }
        }

        // For unlock: only generate OTP if the account is an admin with
        // security questions that is currently locked, but do NOT reveal any
        // of those states (admin / has-SQ / is-locked) in the response.
        // Fix 3 (fresh4-fix-api): unify unlock OTP response to avoid leaking admin status.
        if (otpType === 'unlock') {
          const user = await db.user.findUnique({ where: { email } })
          if (
            !user ||
            user.role !== 'ADMIN' ||
            !user.securityQuestions ||
            !user.securityLockUntil ||
            user.securityLockUntil < new Date()
          ) {
            suppressOtp = true
          }
        }

        // For reset: check if email exists
        // auth-deep-audit-fix Bug 6: do NOT generate (or send) an OTP for
        // emails that have no account. Previously the code generated AND
        // emailed the OTP regardless — which meant an attacker could spam
        // arbitrary inboxes with "reset your NIXE password" emails for
        // accounts that don't even exist on the site (email-bombing +
        // confusing recipients). The per-(email,type) rate limit (3/10min)
        // blunts but doesn't eliminate this. Now we suppress generation for
        // non-existent users and return the same generic "code sent"
        // message either way — so the response is identical regardless of
        // whether the account exists (no enumeration), but no email is
        // actually delivered to inboxes that have no account. This mirrors
        // the existing suppression already in place for 'login' and
        // 'unlock' types above.
        if (otpType === 'reset') {
          const user = await db.user.findUnique({ where: { email } })
          if (!user) {
            suppressOtp = true
          }
        }

        // 2026-09-09 audit fix (M2): signup OTP suppressed for registered emails.
        // 2026-09-10 re-audit fix (M2 residual): the mailbox owner now gets a
        // short "you already have an account — sign in or reset your password"
        // email instead of silence. Previously a user who forgot they had an
        // account requested a signup code, got the generic "code sent"
        // response, never received anything, and every code they typed failed
        // (the old "email already registered" hint was unreachable without a
        // valid code). The helpful email goes ONLY to the registered inbox (no
        // response difference → no enumeration), and both the suppressed and
        // non-suppressed paths now hit SMTP, closing most of the timing delta
        // the 2026-09-09 fix left open. Delivery is best-effort: a failure must
        // not surface (it would distinguish registered from unknown emails).
        if (otpType === 'signup') {
          const user = await db.user.findUnique({ where: { email } })
          if (user) {
            suppressOtp = true
            if (isEmailConfigured) {
              // 2026-09-10 audit fix (round 3, A-M1): the already-registered
              // notice is a REAL email delivery, but it never creates an
              // OtpCode row — so the per-(email,type) quota above never
              // counted it. An attacker could hit this suppressed path on
              // every request (the only cap was the per-IP route limit,
              // ~30/10min ≈ 4,320 notices/day to any registered inbox, and
              // unbounded with IP rotation). The notice now has its own
              // KV-backed per-email budget (3/10min, matching the real-send
              // quota); when exhausted, the notice is silently skipped — the
              // response stays identical either way (no enumeration).
              const notice = await rateLimit({
                key: `otp-notice:${email}`,
                max: 3,
                windowMs: 10 * 60_000,
              })
              if (notice.ok) {
                try {
                  await sendAlreadyRegisteredEmail(email)
                } catch (mailErr) {
                  logger.error('[otp] already-registered notice send failed:', mailErr instanceof Error ? mailErr.name : 'unknown')
                }
              }
            }
          }
        }

        // Generate OTP code (only when not suppressed).
        if (!suppressOtp) {
          const issuedOtp = await createOtp(email, otpType)
          const otpCode = issuedOtp.code

          // Log the OTP code to the server console ONLY in development.
          // In production, OTP codes are delivered ONLY via email —
          // logging them would expose them to anyone with Vercel log access.
          if (process.env.NODE_ENV !== 'production') {
            logger.info(
              `\n\x1b[36m📧 [OTP] ${email} (${otpType}): ${otpCode}\x1b[0m\n`
            )
          }

          // Send real email if SMTP is configured. Do not claim success if
          // delivery fails: invalidate this exact code so a retry cannot leave
          // multiple usable records or strand the user with a code they never
          // received. The error log contains only bounded provider metadata.
          if (isEmailConfigured) {
            try {
              await sendOtpEmail(email, otpCode, otpType)
            } catch (mailErr) {
              try {
                await db.otpCode.updateMany({ where: { id: issuedOtp.id, used: false }, data: { used: true } })
              } catch (cleanupErr) {
                logger.error('[otp] failed to invalidate undelivered code:', cleanupErr instanceof Error ? cleanupErr.name : 'unknown')
              }
              logger.error('[otp] email send failed:', mailErr instanceof Error ? mailErr.name : 'unknown')
              throw new Error('We could not deliver the verification code. Please try again shortly.')
            }
          }
        }

        // fresh6-fix-api Fix 2 (CRITICAL): `devCode` was returned in the JSON
        // response body on any non-production deployment (NODE_ENV !==
        // 'production'). Vercel preview/staging deployments set NODE_ENV to
        // 'development' (or unset it), so the live OTP for ANY email was
        // readable in the response body — an attacker could hit /api/auth/otp
        // for victim@example.com, read devCode, then call /api/auth
        // action=reset-password to take over the account with NO email access.
        //
        // Fix: NEVER return the OTP in the response body, regardless of
        // NODE_ENV. Dev convenience is provided ONLY via the console.log
        // above (server logs are operator-only). The response is identical
        // for dev/staging/prod so there's no leak vector.

        // Generic responses for login & unlock — do NOT reveal account state.
        if (otpType === 'login') {
          return {
            ok: true,
            message: 'If this account exists, an OTP has been sent to your email.',
          }
        }
        if (otpType === 'unlock') {
          return {
            ok: true,
            message: 'If this account exists and is locked, an OTP has been sent.',
          }
        }
        return {
          ok: true,
          message: `Verification code sent to ${email}. Check your inbox.`,
        }
      }

      if (action === 'verify') {
        if (!body.code) throw new Error('Verification code is required')

        // ── BUG 15 fix: OTP brute-force prevention ─────────────────────────
        // A 6-digit code has only 1M combinations. Without per-code attempt
        // tracking, an attacker who can fire many verify requests could
        // brute-force it in ~500K attempts on average. We track failed
        // attempts on the ACTIVE OTP row (per email+type) and, once the
        // counter reaches 5, invalidate the code (mark used=true) so the
        // user MUST request a new one. This caps an attacker at 5 guesses
        // per issued code — far below the ~500K needed to brute-force.
        //
        // Audit run-2 rework (newsletter-unsubscribe-verify-lockout +
        // auth-lockout-nonautomic-count-then-insert): the old pre-check ran
        // BEFORE checkOtp and refused even VALID codes whenever the row
        // counter reached 5 — the same victim-lock pattern fixed in
        // checkOtp. The accounting now runs only on a FAILED verification
        // (checkOtp itself is valid-code-first, so a correct code always
        // proceeds), and both the increment and the invalidation are
        // atomic conditional statements (spend-first) instead of
        // read-then-write.
        let activeOtp: { id: string; failedAttempts: number } | null = null
        try {
          activeOtp = await db.otpCode.findFirst({
            where: {
              email,
              type: otpType,
              used: false,
              expiresAt: { gt: new Date() },
            },
            orderBy: { createdAt: 'desc' },
            select: { id: true, failedAttempts: true },
          })
        } catch {
          // If the failedAttempts column doesn't exist yet (pre-migration
          // DB), skip the row-level accounting — the bait-row lockout
          // inside checkOtp() still provides brute-force protection.
          activeOtp = null
        }

        try {
          await checkOtp(email, otpType, String(body.code))
        } catch (e) {
          // ── BUG 15 fix (increment on failure) ──────────────────────────
          // The verify failed. Atomically claim one failure slot on the
          // active OTP row (conditional increment below 5), and invalidate
          // the code once the threshold is reached — the conditional
          // updateMany pair is race-safe under concurrent wrong guesses,
          // unlike the old read-then-write.
          //
          // We only increment if there IS an active OTP — if checkOtp
          // threw because there's no active OTP at all (e.g. user never
          // requested a code, or it expired), there's nothing to track.
          if (activeOtp) {
            try {
              await db.otpCode.updateMany({
                where: { id: activeOtp.id, failedAttempts: { lt: 5 } },
                data: { failedAttempts: { increment: 1 } },
              })
              // Invalidate at the threshold — force a fresh code. The
              // conditional where makes this idempotent: it only fires
              // when the counter has actually reached 5 on an unused row.
              await db.otpCode.updateMany({
                where: { id: activeOtp.id, failedAttempts: { gte: 5 }, used: false },
                data: { used: true },
              })
            } catch {
              // Non-fatal: the bait-row mechanism inside checkOtp still
              // recorded the failure for the per-(email,type) lockout.
            }
          }
          throw e
        }
        return { ok: true, message: 'Verification successful' }
      }

      throw new Error('Invalid action. Use "send" or "verify".')
    },
    {
      // Single route-level rate limit for both send and verify.
      // Generous enough that normal usage never hits it.
      // Brute-force is caught inside checkOtp (per-email lockout).
      rateLimit: { key: 'otp', max: 30, windowMs: 10 * 60 * 1000 },
    }
  )
}
// Force redeploy Wed Jul 29 12:08:14 UTC 2026
// redeploy 1785328849
