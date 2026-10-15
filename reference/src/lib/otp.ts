import { db, withKeyLock } from '@/lib/db'
import crypto from 'crypto'
import { logger } from '@/lib/logger'
import { ensureRlsEnabled } from '@/lib/migrate'
// BUG 42 fix (audit3): removed withSelfHeal import — migrations run at deploy
// time, not per-request. Self-heal added migration overhead to every OTP op.

/**
 * OTP (One-Time Password) utilities for email verification and password reset.
 *
 * Security properties (after hardening):
 *  - 6-digit code generated with crypto.randomInt (CSPRNG, not Math.random)
 *  - Valid for 10 minutes (was 30 — shorter window = less brute-force surface)
 *  - Single-use (marked as used after successful verification)
 *  - Locked after 5 failed verify attempts per (email, type) — H-4 fix
 *  - Codes are hashed at rest (HMAC-SHA256) so DB dump doesn't leak plaintext codes
 */

const OTP_EXPIRY_MINUTES = 10
const OTP_LENGTH = 6
const OTP_MAX_VERIFY_ATTEMPTS = 5
const OTP_LOCK_MINUTES = 15

let otpSchemaReady: Promise<void> | null = null

/**
 * OTP is a critical auth dependency, but this project’s production build only
 * generates Prisma Client and does not apply migrations. Ensure the small OTP
 * table/index contract exists once per runtime before issuing a code. The DDL
 * is idempotent, uses no user input, and supports both SQLite/libSQL and
 * PostgreSQL deployments. A failed attempt resets the guard so a later request
 * can retry after a transient database outage.
 */
export async function ensureOtpSchemaReady(): Promise<void> {
  if (!otpSchemaReady) {
    otpSchemaReady = (async () => {
      const databaseUrl = process.env.DATABASE_URL || ''
      const dateType = databaseUrl.startsWith('file:') || databaseUrl.startsWith('libsql:') ? 'DATETIME' : 'TIMESTAMP(3)'
      await db.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS "OtpCode" ("id" TEXT NOT NULL, "email" TEXT NOT NULL, "code" TEXT NOT NULL, "type" TEXT NOT NULL, "expiresAt" ${dateType} NOT NULL, "used" BOOLEAN NOT NULL DEFAULT false, "usedAt" ${dateType}, "createdAt" ${dateType} NOT NULL DEFAULT CURRENT_TIMESTAMP, "failedAttempts" INTEGER NOT NULL DEFAULT 0, CONSTRAINT "OtpCode_pkey" PRIMARY KEY ("id"))`)
      await db.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS "OtpCode_email_type_idx" ON "OtpCode"("email", "type")`)
      await db.$executeRawUnsafe(`CREATE INDEX IF NOT EXISTS "OtpCode_expiresAt_idx" ON "OtpCode"("expiresAt")`)
      try {
        await db.$executeRawUnsafe(`ALTER TABLE "OtpCode" ADD COLUMN "usedAt" ${dateType}`)
      } catch {
        // The column already exists on current schemas or was created above.
      }
      try {
        await db.$executeRawUnsafe(`ALTER TABLE "OtpCode" ADD COLUMN "failedAttempts" INTEGER NOT NULL DEFAULT 0`)
      } catch {
        // The column already exists on current schemas or was created above.
      }
      // 2026-10-04: deny-by-default RLS (Supabase PostgREST/anon surface —
      // see migrate.ts ensureRlsEnabled; never throws).
      await ensureRlsEnabled('OtpCode')
    })().catch((error) => {
      otpSchemaReady = null
      logger.error('[otp] schema readiness failed:', error instanceof Error ? error.message : String(error))
      throw new Error('Unable to issue a verification code right now. Please try again shortly.')
    })
  }
  return otpSchemaReady
}

// ─── Hash the OTP code at rest with a server secret ───────────────────────────
// If the DB leaks, attackers can't read OTPs in-flight.
// Security fix: reuse resolveJwtSecret() from auth-core so that production
// fails fast if JWT_SECRET is missing (instead of silently falling back to a
// hardcoded dev secret that could allow offline OTP forgery).
import { resolveJwtSecret } from '@/lib/auth-core'

function otpHmacSecret(): string {
  return resolveJwtSecret() + ':otp-salt'
}

function hashOtp(code: string): string {
  return crypto.createHmac('sha256', otpHmacSecret()).update(code).digest('hex')
}

/** Generate a random 6-digit OTP code using a CSPRNG (C-9 fix). */
export function generateOtp(): string {
  // crypto.randomInt(min, max) returns a uniform integer in [min, max).
  return String(crypto.randomInt(100000, 1000000)).padStart(OTP_LENGTH, '0')
}

/** Create an OTP record and return its plaintext code plus internal row id. */
export async function createOtp(
  email: string,
  type: 'signup' | 'reset' | 'login' | 'unlock' | 'unsubscribe' | 'subscribe'
): Promise<{ id: string; code: string }> {
  await ensureOtpSchemaReady()
  const code = generateOtp()
  const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000)
  const normalizedEmail = email.toLowerCase()

  // Security audit run-2 (auth-lockout-nonautomic-count-then-insert,
  // issuance-cap variant): the aggregate per-email cap, the prior-code
  // invalidation, and the create were separate auto-commit statements, so
  // concurrent sends all counted the same sub-threshold total and overshot
  // the 6/10min cap (and could leave two simultaneously valid codes when
  // the invalidation raced the create). The whole issue sequence now runs
  // under a per-email advisory lock (see withKeyLock in db.ts), so each
  // concurrent send serializes against the previous one's committed rows.
  return withKeyLock(`otp-issue:${normalizedEmail}`, async (tx) => {
    // 2026-09-10 audit fix (round 3, A-L1): aggregate per-email cap across ALL
    // OTP types. The per-(email,type) quotas (3/10min) are deliberately scoped
    // so one type's quota can't strand another type's recovery flow — but
    // nothing bounded the SUM, so stacking 'subscribe' + 'unsubscribe' +
    // 'signup'/'reset' deliveries let a single IP mail-bomb an arbitrary inbox
    // with 9-15 codes per 10 minutes. 6 issued codes per 10 min per inbox is
    // comfortably above any legitimate multi-flow usage (signup resend + login
    // 2FA + newsletter confirm) while capping the abuse ceiling.
    const recentAll = await tx.otpCode.count({
      where: {
        email: normalizedEmail,
        createdAt: { gt: new Date(Date.now() - 10 * 60 * 1000) },
        NOT: { code: { startsWith: '__failed_attempt__' } },
      },
    })
    if (recentAll >= 6) {
      throw new Error('Too many codes requested for this email address. Please wait a few minutes before trying again.')
    }

    // Invalidate any prior unused OTPs for this email+type so only the newest one works.
    // RA6-LIB-005 fix: log the error instead of silently swallowing it. The
    // previous `.catch(() => {})` hid DB failures from logs — if the
    // invalidation updateMany failed (DB hiccup, connection drop), the prior
    // OTPs remained valid (used=false, not expired) for the full 10-minute
    // window, allowing an attacker who intercepted a prior OTP to still use
    // it after the user requested a new one. If invalidation fails, abort the
    // resend rather than leaving two usable codes in the database.
    try {
      await tx.otpCode.updateMany({
        where: { email: normalizedEmail, type, used: false },
        data: { used: true },
      })
    } catch (err: unknown) {
      // Do not create a replacement code when the old code could not be
      // invalidated. Otherwise two codes remain valid at once and a stale
      // intercepted code can still authenticate after a resend.
      logger.error('[otp] failed to invalidate prior OTPs:', err instanceof Error ? err.message : String(err))
      throw new Error('Unable to issue a verification code right now. Please try again.')
    }

    const record = await tx.otpCode.create({
      data: {
        email: normalizedEmail,
        code: hashOtp(code), // store hash, not plaintext
        type,
        expiresAt,
      },
      select: { id: true },
    })

    return { id: record.id, code }
  })
}

/**
 * Check if an OTP code is valid WITHOUT consuming it.
 * Tracks failed attempts and locks after OTP_MAX_VERIFY_ATTEMPTS.
 * Throws a descriptive (but not user-enumerable) error on failure.
 */
export async function checkOtp(
  email: string,
  type: 'signup' | 'reset' | 'login' | 'unlock' | 'unsubscribe' | 'subscribe',
  code: string
): Promise<boolean> {
  // Verification may be reached from a fresh tab, a retried request, or a
  // serverless instance that did not handle the preceding send request. Make
  // the verification path self-sufficient instead of assuming send already
  // initialized the OTP table.
  await ensureOtpSchemaReady()
  const normalizedEmail = email.toLowerCase()
  const expectedHash = hashOtp(String(code))

  // Security audit run-2 — two fixes to the failed-verify accounting:
  //
  // (1) newsletter-unsubscribe-verify-lockout.email-keyed-bait-accounting:
  //     the bait budget is keyed ONLY to (email,type), and the unsubscribe
  //     verify branch is fully anonymous — five attacker-chosen wrong codes
  //     locked the MAILBOX OWNER's verification for rolling 15-minute windows
  //     ("refuse even valid codes during lock" made the victim's correct code
  //     useless). A correct code is proof of mailbox control: the lookup now
  //     runs FIRST and valid codes always proceed; the lockout only governs
  //     wrong guesses, which is what it exists to bound.
  // (2) auth-lockout-nonautomic-count-then-insert (bait variant): the count,
  //     threshold, and bait insert were separate auto-commit statements, so
  //     concurrent wrong-guess waves shared a stale sub-threshold count. The
  //     whole wrong-guess sequence now runs under a per-(email,type)
  //     advisory lock (see withKeyLock in db.ts) — each wave member
  //     serializes against the previous one's committed bait row.
  return withKeyLock(`otp-verify:${normalizedEmail}:${type}`, async (tx) => {
    const record = await tx.otpCode.findFirst({
      where: {
        email: normalizedEmail,
        type,
        code: expectedHash,
        used: false,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    })

    if (record) return true

    // H-4 fix: count recent failed attempts (last 15 min) for this email+type.
    // RA5-LIB-004 fix: filter the count to only "bait" rows (failed-verification
    // markers, created below). Legitimate `createOtp` requests are excluded —
    // after 3 OTP sends + 2 failed verifications = 5 rows, the 3rd verification
    // attempt (even with the CORRECT code) was blocked by the old count; a user
    // who requested 5 OTPs across a 15-minute window (e.g. delayed emails) was
    // locked out without making a single wrong guess.
    const since = new Date(Date.now() - OTP_LOCK_MINUTES * 60 * 1000)
    const recentAttempts = await tx.otpCode.count({
      where: {
        email: normalizedEmail,
        type,
        createdAt: { gt: since },
        code: { startsWith: '__failed_attempt__' },
      },
    })

    // Each failed verify creates a "bait" row (below), so 5+ bait rows =
    // brute force. (Legitimate OTP sends create rows with hashed codes —
    // they're excluded from this count.)
    if (recentAttempts >= OTP_MAX_VERIFY_ATTEMPTS) {
      throw new Error('Too many attempts. Please wait a few minutes and try again.')
    }

    // Track the failed attempt by creating a short-lived "bait" row.
    // This increments the recentAttempts count for future checkOtp calls,
    // so repeated wrong guesses eventually trigger the lockout above.
    // (Without this, an attacker could try unlimited codes against a
    // single issued OTP without being locked out.)
    await tx.otpCode.create({
      data: {
        email: normalizedEmail,
        type,
        code: '__failed_attempt__' + Date.now(),
        expiresAt: new Date(Date.now() + OTP_LOCK_MINUTES * 60 * 1000),
        used: true,
      },
    })
    throw new Error('Invalid or expired verification code. Please request a new code.')
  })
}

/**
 * Verify an OTP code and mark it as used (consume it).
 * Use this AFTER the action (signup, password reset) is complete.
 */
export async function consumeOtp(
  email: string,
  type: 'signup' | 'reset' | 'login' | 'unlock' | 'unsubscribe' | 'subscribe',
  code: string,
  tx?: any
): Promise<boolean> {
  // Transactional callers already ran checkOtp before opening their
  // transaction. Non-transactional callers still get a safe schema guard.
  if (!tx) await ensureOtpSchemaReady()
  const client = tx || db
  const normalizedEmail = email.toLowerCase()
  const expectedHash = hashOtp(String(code))

  const record = await client.otpCode.findFirst({
    where: {
      email: normalizedEmail,
      type,
      code: expectedHash,
      used: false,
      expiresAt: { gt: new Date() },
    },
    orderBy: { createdAt: 'desc' },
  })

  if (!record) {
    // CRITICAL fix (audit-2d-sec #4): throw on missing record instead of
    // silently succeeding. Previously this returned `true`, which created a
    // TOCTOU replay window — under two parallel requests with the same OTP,
    // request A's transaction consumes the row and request B's findFirst
    // returns null, but consumeOtp returned `true` so B's transaction also
    // committed, defeating the single-use guarantee. Throwing here makes the
    // surrounding transaction roll back so only one of the two requests can
    // succeed.
    throw new Error('Invalid or expired OTP')
  }

  // Atomic consume: only one concurrent caller can flip `used:false` → `true`.
  // The findFirst above is informational only; this updateMany is the source of
  // truth — under READ COMMITTED, two parallel requests that both passed
  // findFirst will still only see one updateMany succeed (count === 1) because
  // the second one's `where: { used: false }` no longer matches.
  const result = await client.otpCode.updateMany({
    where: { id: record.id, used: false },
    data: { used: true, usedAt: new Date() },
  })
  if (result.count === 0) {
    throw new Error('OTP already consumed or not found')
  }

  return true
}

// 2026-09-09 audit fix (L9): removed dead export cleanupExpiredOtps() —
// zero callers repo-wide (expired-OTP retention is owned by the daily cron
// route /api/cron/cleanup-test-accounts, which sweeps OtpCode inline).
