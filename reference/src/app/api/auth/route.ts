import { NextRequest } from 'next/server'
import crypto from 'crypto'
import { logger } from '@/lib/logger'
import type { Role } from '@/lib/types';
import { db, withKeyLock } from '@/lib/db'
import {
  hashPassword,
  setSessionCookie,
  setSessionCookieFromToken,
  createSessionRecord,
  getSessionUser,
  requireUser,
  clearSession,
  getCurrentSessionToken,
  toSafeUser,
  purgeUserSessionsFromCache,
  ensureAuthSchemaReady,
  getAuthUser,
  getChallengeState,
  bumpChallengeTokenVersion,
  markChallengeConsumed,
  isChallengeJtiConsumed,
} from '@/lib/auth'
import {
  verifyPassword,
  signSecurityChallenge,
  verifySecurityChallenge,
  signTwoFactorChallenge,
  verifyTwoFactorChallenge,
  hashSecurityAnswer,
  verifySecurityAnswer,
  hashSessionToken,
} from '@/lib/auth-core'
import { handleApi, lenientJson } from '@/lib/api'
import { rateLimit, getClientIp } from '@/lib/rate-limit'
import { cleanStr, sanitizeText, validateEmail, validatePassword, validatePhone, isTestEmail } from '@/lib/validate'
import { checkOtp, consumeOtp } from '@/lib/otp'

import {
  scheduleTestAccountDeletion,
  cancelScheduledDeletion,
} from '@/lib/test-account'
// FIX 1+6: Removed withSelfHeal + runPendingMigrations imports — these were
// called on every login/signup, causing DB race conditions and overhead.
// Migrations now run only at deploy time (postinstall script).
import { mergeGuestCartIntoUserCart, readGuestCartCookie, clearGuestCartCookie } from '@/lib/cart'

// Generic "no account" message — M-1 fix: don't enumerate accounts.
const NO_ACCOUNT = 'No account found with that email.' // acceptable for password reset (user requested it)

function isDeletedAccountRecord(user: { name?: string | null; isBanned?: boolean | null }): boolean {
  return user.name === 'Deleted account' && user.isBanned === true
}

async function quarantineLegacyDeletedAccount(tx: any, userId: string): Promise<void> {
  await tx.user.update({
    where: { id: userId },
    data: {
      email: `deleted-${userId}@deleted.invalid`,
      name: 'Deleted account',
      phone: null,
      avatarUrl: null,
      firebaseUid: null,
      isBanned: true,
      securityAttempts: 0,
      securityLockUntil: null,
    },
  })
  await tx.session.deleteMany({ where: { userId } })
}

function signupFailure(error: unknown): Error {
  const code = typeof (error as { code?: unknown })?.code === 'string'
    ? (error as { code: string }).code
    : undefined
  if (code === 'P2002') {
    return Object.assign(
      new Error('This account or one of its details already exists. Please sign in or try different details.'),
      { code: 'ACCOUNT_ALREADY_EXISTS' },
    )
  }
  logger.error('[auth] signup transaction failed:', {
    name: error instanceof Error ? error.name : 'UnknownError',
    code,
  })
  return new Error('We could not create your account right now. Please try again shortly.')
}

// fresh5-fix-api Fix 1 + security-hardening-10 Fix 2: per-account login
// lockout for non-admin credential stuffing. After MAX_LOGIN_ATTEMPTS failed
// passwords for the same email, the account is locked for LOCK_DURATION. Each
// login attempt — success or failure — is recorded in a `LoginAttempt` Prisma
// model so the lockout check works across all serverless instances. Admin
// accounts additionally have a DB-backed security-question lockout
// (securityAttempts/securityLockUntil); this covers the more common
// wrong-password case for every account type.
const MAX_LOGIN_ATTEMPTS = 5
const LOCK_DURATION = 15 * 60 * 1000 // 15 minutes
/**
 * Count the failed login attempts for `email` in the last LOCK_DURATION ms.
 * Used to enforce the per-account lockout below.
 */
async function countRecentFailedAttempts(email: string): Promise<number> {
  const since = new Date(Date.now() - LOCK_DURATION)
  try {
    return await db.loginAttempt.count({
      where: {
        email,
        succeeded: false,
        attemptedAt: { gte: since },
      },
    })
  } catch (e: any) {
    // If the LoginAttempt table doesn't exist yet (e.g. on a fresh DB
    // before db:push has run), the count query will throw. Fail open
    // (return 0) so the user can still attempt to log in — the per-IP
    // rate limit at the route layer still blunts brute force.
    logger.info('[auth] loginAttempt count failed (non-fatal):', e?.message)
    return 0
  }
}

/**
 * Record a login attempt. `succeeded` indicates whether the password was
 * correct. Failures are recorded before the password check (so we can count
 * them); successes are recorded after (and we clear prior failures).
 */
async function recordLoginAttempt(email: string, succeeded: boolean): Promise<void> {
  try {
    await db.loginAttempt.create({ data: { email, succeeded } })
  } catch (e: any) {
    // Non-fatal: if the table is missing or the write fails, we still
    // proceed with the login flow. The per-IP rate limit still applies.
    logger.info('[auth] loginAttempt create failed (non-fatal):', e?.message)
  }
}

/**
 * Spend-first per-account lockout claim (security audit run-2,
 * auth-lockout-nonautomic-count-then-insert).
 *
 * The old sequence — COUNT failed attempts → threshold check → INSERT the
 * failure row only AFTER the password evaluation — was three separate
 * auto-commit statements. A concurrent wave whose COUNTs all executed before
 * any INSERT committed each observed the same sub-threshold count, so every
 * member was admitted with a full bcrypt evaluation: the failed-guess budget
 * per email per 15-minute window exceeded MAX_LOGIN_ATTEMPTS by roughly the
 * wave size (run-1 lead, re-verified in run-2).
 *
 * This claim generalizes the race-safe spend-first pattern the same file
 * already uses for verify-security: under a per-email advisory lock
 * (withKeyLock), count recent failures and — when still below the threshold —
 * INSERT the failure row as the claim BEFORE the expensive bcrypt evaluation
 * runs outside the lock. Concurrent requests for the same email serialize:
 * each one's count includes the previous one's committed claim, so the 6th+
 * attempt in any window is refused. The claim row is deleted again by
 * clearFailedLoginAttempts() on a successful login.
 *
 * Fail-open on unexpected DB errors (same posture as the old count helper:
 * the per-IP rate limit still applies, and ensureAuthSchemaReady at the
 * login entry makes the table-missing case unreachable).
 */
async function claimLoginAttempt(email: string): Promise<number> {
  try {
    return await withKeyLock(`login-attempt:${email}`, async (tx) => {
      const since = new Date(Date.now() - LOCK_DURATION)
      const count = await tx.loginAttempt.count({
        where: { email, succeeded: false, attemptedAt: { gte: since } },
      })
      if (count >= MAX_LOGIN_ATTEMPTS) return count
      await tx.loginAttempt.create({ data: { email, succeeded: false } })
      return count + 1
    })
  } catch (e: any) {
    logger.info('[auth] loginAttempt claim failed (non-fatal):', e?.message)
    return 0
  }
}

/**
 * Clear all prior failed login attempts for `email`. Called after a
 * successful login so a user who typos their password a few times then
 * gets it right doesn't carry a partial failure count.
 */
async function clearFailedLoginAttempts(email: string): Promise<void> {
  try {
    await db.loginAttempt.deleteMany({
      where: { email, succeeded: false },
    })
  } catch (e: any) {
    logger.info('[auth] loginAttempt deleteMany failed (non-fatal):', e?.message)
  }
}

// 2026-09-09 audit fix (L9): removed dead export cleanupOldLoginAttempts() —
// zero callers repo-wide (LoginAttempt retention is owned by the daily cron
// route /api/cron/cleanup-test-accounts).

export async function GET(req: NextRequest) {
  return handleApi(req, async () => {
    const u = await getSessionUser()
    // BUG 12: adminSignupEnabled is now always false — admin accounts can
    // only be created via /api/admin/create (token-gated) or CLI, never via
    // the public signup endpoint.
    return { user: u, adminSignupEnabled: false }
  }, {
    // 2026-09-09 audit fix (L8): throttle the `me` endpoint (3+ DB round-trips
    // per call) — mirrors the addresses GET rate-limit option.
    rateLimit: { key: 'auth-me', max: 60, windowMs: 60_000 },
  })
}

export async function POST(req: NextRequest) {
  return handleApi(req, async () => {
    const body = await lenientJson(req)
    const { action } = body

    // R4-A1 (round-4 audit, 2026-09-21): per-action rate limiting. The
    // previous route-level `auth-action` bucket (10/15min/IP) counted EVERY
    // POST to this endpoint — including the read-only `get-security-questions`
    // action that fires automatically on every account-dashboard mount, and
    // routine `update-profile` / `logout` calls. Normal dashboard usage could
    // exhaust the shared budget and then lock the user out of `login` /
    // `login-otp` for 15 minutes. Sensitive actions keep the strict 10/15min
    // budget; routine actions get a generous 60/15min bucket. handleApi maps
    // the RATE_LIMITED message to HTTP 429.
    const clientIp = getClientIp(req)
    const rlOpts = ROUTINE_AUTH_ACTIONS.has(action)
      ? { key: `auth-routine:${clientIp}`, max: 60, windowMs: 15 * 60_000 }
      : { key: `auth-action:${clientIp}`, max: 10, windowMs: 15 * 60_000 }
    const rl = await rateLimit(rlOpts)
    if (!rl.ok) {
      throw new Error('RATE_LIMITED')
    }

    // ─── SIGNUP ────────────────────────────────────────────────────────────────
    if (action === 'signup') {
      const email = validateEmail(body.email)
      const password = validatePassword(body.password)
      const name = cleanStr(body.name, 100)
      if (!name) throw new Error('Name is required.')
      if (!body.otpCode) throw new Error('Email verification code is required.')

      // Public signup is intentionally customer-only. Seller access is granted
      // later by an existing administrator through the protected admin users
      // workflow, which creates the seller workspace and applies approval state.
      // Reject hidden or legacy client payloads instead of silently accepting
      // an attempted seller registration.
      if (body.becomeSeller === true || body.role === 'SELLER') {
        throw new Error('Seller accounts are created by an administrator after customer signup.')
      }
      // Admin accounts are provisioned only through protected admin workflows.
      if (body.becomeAdmin || body.role === 'ADMIN') {
        throw new Error('Admin registration is not available from public signup. Please contact an existing administrator.')
      }
      // Check the OTP code is valid (without consuming it)
      await checkOtp(email, 'signup', String(body.otpCode))

      // FIX 1+6: Removed runPendingMigrations() and withSelfHeal() from
      // per-request auth flow. Migrations should only run at deploy time
      // (postinstall script). Self-heal adds overhead to every query.
      const existing = await db.user.findUnique({ where: { email } })
      // Do not reveal duplicate-account state until the requester has proved
      // control of this mailbox with a valid signup OTP. Before this point the
      // send endpoint and all validation failures remain generic, preventing
      // account enumeration. After OTP proof, an actionable recovery message
      // is safe and avoids trapping a legitimate existing user in signup.
      if (existing && !isDeletedAccountRecord(existing)) {
        throw Object.assign(
          new Error('This email is already registered. Please sign in or reset your password.'),
          { code: 'ACCOUNT_ALREADY_EXISTS' },
        )
      }

      const role: Role = 'CUSTOMER'
      const userIsTestAccount = isTestEmail(email)

      // Wrap customer creation + OTP consumption in a transaction. Seller
      // records are created only by the protected admin role-transition flow.
      // This keeps public signup simple and prevents sensitive seller onboarding
      // data from entering the public registration path.
      let user: any
      try {
        user = await db.$transaction(async (tx) => {
          // A previous deletion release could have anonymized the account but
          // left its original email on the tombstone row. Release that unique
          // value inside the same transaction immediately before creating the
          // new account. Only the explicit Deleted account marker qualifies;
          // active or merely banned users can never be reclaimed this way.
          const duplicate = await tx.user.findUnique({ where: { email } })
          if (duplicate) {
            if (!isDeletedAccountRecord(duplicate)) {
              throw Object.assign(new Error('This email is already registered. Please sign in or reset your password.'), { code: 'ACCOUNT_ALREADY_EXISTS' })
            }
            await quarantineLegacyDeletedAccount(tx, duplicate.id)
          }
          const u = await tx.user.create({
            data: {
              email,
              passwordHash: hashPassword(password),
              name,
              role,
              emailVerified: true,
              isTestAccount: userIsTestAccount,
            },
          })
          // Consume the OTP code INSIDE the transaction.
          await consumeOtp(email, 'signup', String(body.otpCode), tx)
          return u
        })
      } catch (error: unknown) {
        throw signupFailure(error)
      }

      try {
        await setSessionCookie(user.id, user.role as Role)
        await mergeGuestCartIfAny(user.id)
        return { user: toSafeUser(user) }
      } catch (error: unknown) {
        logger.error('[auth] signup session creation failed:', {
          name: error instanceof Error ? error.name : 'UnknownError',
        })
        throw new Error('Your account was created, but automatic sign-in is temporarily unavailable. Please sign in with your new credentials.')
      }
    }

    // ─── LOGIN ────────────────────────────────────────────────────────────────
    if (action === 'login') {
      // FIX 1+2+3: Removed runPendingMigrations(), cleanupExpiredTestAccounts(),
      // and cleanupOldLoginAttempts() from the per-request login flow.
      // These were causing DB race conditions, locks, and performance
      // degradation on EVERY login. Migrations run at deploy time (postinstall).
      // Cleanups are handled by the daily cron job (/api/cron/cleanup-test-accounts).

      const email = validateEmail(body.email)
      const password = String(body.password || '')

      // Prepare the persistent session/lockout tables before auth reads. This
      // keeps fresh production deployments from silently skipping the shared
      // LoginAttempt lockout because the table has not been applied yet.
      await ensureAuthSchemaReady()

      // FIX 6: Removed withSelfHeal wrapper — adds overhead to every query.
      // Self-healing should happen once at startup, not per-request.
      const user = await getAuthUser({ email })
      // FIX A1 (timing attack): run verifyPassword against a dummy hash when
      // the user doesn't exist, so the response time is identical whether
      // the email is registered or not. Also move isBanned check AFTER
      // password verification so banned status isn't leaked via timing.
      // CRITICAL FIX: the previous DUMMY_HASH was not a valid bcrypt hash
      // (bcryptjs returns false in 0ms instead of ~250ms), making the timing
      // attack mitigation completely useless. Using a real pre-computed
      // 12-round bcrypt hash so the comparison takes the same time as a real
      // password check.
      const DUMMY_HASH = '$2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy' // valid 12-round hash of "dummy"
      // Security audit fix (33-d #4): Firebase-managed accounts store a
      // placeholder (not a bcrypt hash) in passwordHash — bcrypt.compareSync
      // rejects it in ~0ms vs ~250ms for a real hash, giving a remote timing
      // oracle that reveals which known emails are Firebase-managed. Compare
      // against the dummy hash for those accounts so every login costs the
      // same ~250ms whether the account is password-based, Firebase-managed,
      // or non-existent.
      const passwordValid = user
        ? (
            user.passwordHash && user.passwordHash.startsWith('firebase-managed:')
              ? verifyPassword(password, DUMMY_HASH) // equal-cost dummy bcrypt
              : verifyPassword(password, user.passwordHash)
          )
        : verifyPassword(password, DUMMY_HASH) // equal-cost dummy bcrypt

      // BUG 1 fix (bug-audit): the previous code threw on `!user || !passwordValid`
      // BEFORE recording the failed attempt — making `recordLoginAttempt(email, false)`
      // dead code. The lockout counter never incremented, so brute-force protection
      // was completely disabled. Restructured: only throw immediately for non-existent
      // users (dummy hash already ran for timing safety). Wrong passwords fall through
      // to the lockout check + failure recording below.

      // fresh5-fix-api Fix 1 + audit run-2 spend-first rework: per-account
      // login lockout. claimLoginAttempt() counts recent failures AND inserts
      // the failure row for this attempt atomically under a per-email advisory
      // lock BEFORE the password evaluation below — a concurrent wave can no
      // longer share a stale sub-threshold count (see the helper's comment).
      //
      // security-hardening-10 Fix 2: the lockout state lives in the
      // LoginAttempt table, so it is shared across all serverless instances.
      //
      // 2026-09-10 re-audit fix (L1 complete): this lockout check runs BEFORE
      // the `!user` throw below, so registered and unknown emails hit the same
      // threshold with the same message — the enumeration oracle is closed.
      const recentFailures = await claimLoginAttempt(email)
      if (recentFailures >= MAX_LOGIN_ATTEMPTS) {
        throw new Error('Too many failed attempts. Try again in 15 minutes.')
      }

      if (!user) {
        // 2026-09-09 audit fix (L1): the claim above already recorded the
        // failure for UNKNOWN emails too, so the lockout fires at the same
        // count with the same message for registered and unknown emails
        // (closes the account-existence oracle). The dummy bcrypt compare
        // above keeps the timing path safe.
        throw new Error('Email or password is incorrect.')
      }

      // BUG 1 fix (bug-audit): NOW check the password — the failure row was
      // already claimed by claimLoginAttempt() above (spend-first), so a wrong
      // password needs no additional insert here.
      if (!passwordValid) {
        throw new Error('Email or password is incorrect.')
      }

      // L4 fix (2026 audit): the admin security-question lockout message
      // previously fired BEFORE the password validity check — so an attacker
      // probing a locked admin account with a WRONG password learned that the
      // account exists AND is an admin (distinct error text). It now runs only
      // after the password is proven correct: locked admins still see the
      // lock message, but wrong passwords get the same generic error as any
      // other account (no admin email enumeration).
      //
      // 2026-09-10 audit fix (round 3, D-M1): a locked ADMIN with security
      // questions now FALLS THROUGH to the security-question challenge below
      // instead of throwing. Previously the throw was the only outcome, but
      // the client's ONLY entry into the security view (which contains the
      // unlock-OTP section) is the `needSecurityAnswer` response — so after a
      // page reload (SPA state gone) a legitimately-locked admin could never
      // reach the unlock flow and had to wait out the full 24h lock despite
      // holding both the password and the mailbox. Falling through renders
      // the security view; answering while locked still throws the honest
      // "locked" error from verify-security, and the unlock-OTP section in
      // the same view is the documented recovery path.
      if (
        user.securityLockUntil &&
        user.securityLockUntil > new Date() &&
        !(user.role === 'ADMIN' && user.securityQuestions)
      ) {
        const hoursLeft = Math.ceil((user.securityLockUntil.getTime() - Date.now()) / 3600000)
        throw new Error(
          `Account locked. Try again in ${hoursLeft} hour(s) or reset via OTP.`
        )
      }

      // Password is correct — check banned status AFTER password verification
      // so banned status isn't leaked via timing (same response time whether
      // the account is banned or not, since verifyPassword always runs).
      if (user.isBanned) throw new Error('This account has been suspended.')

      // fresh5-fix-api Fix 1: password verified — clear the counter so a
      // subsequent legitimate login isn't blocked by an old failed-attempt
      // streak (e.g. user typos password 4 times, then gets it right).
      // security-hardening-10 Fix 2: also record the successful attempt +
      // delete prior failed rows.
      await recordLoginAttempt(email, true)
      await clearFailedLoginAttempts(email)
      // UI-001 fix (comprehensive-audit): pass the `remember` flag from the
      // client to setSessionCookie so "Keep me signed in" extends the session
      // to 30 days instead of the default 7 days.
      const remember = body.remember === true

      // If admin has security questions set, issue an opaque challenge token
      // and DON'T set the cookie yet. The client must verify the answer.
      // (C-4 / H-8 fix: don't return question text — only the challenge.)
      //
      // fresh3-fix-api Fix 6: `needSecurityAnswer` is ONLY ever included in
      // the response for ADMIN accounts — the outer `if` gates on
      // `user.role === 'ADMIN'`. Non-admin users fall through to the 2FA /
      // normal login path below and never see this field, so the response
      // shape for non-admins doesn't reveal admin-account status. (Admins
      // without security questions also fall through, so an attacker with a
      // stolen password can't distinguish "admin without questions" from
      // "non-admin" — the only leak is "admin WITH questions", which is
      // unavoidable since the client must render the security-question UI.)
      if (user.role === 'ADMIN' && user.securityQuestions) {
        try {
          let questions: Array<{ question: string; answer: string }> = []
          try {
            questions = JSON.parse(user.securityQuestions)
          } catch {}
          if (Array.isArray(questions) && questions.length > 0) {
            const questionIndex = Math.floor(Math.random() * questions.length)

            // round-8 bugfix (#17): snapshot the user's challenge tokenVersion
            // into the JWT so verify-security can reject challenges that were
            // issued before a password reset/change or security-question
            // change invalidated them.
            const challengeState = await getChallengeState(user.id)

            // M-1: don't leak whether this is the admin or not. If the admin
            // has security questions set, return a generic "security check"
            // challenge — the UI knows what to render.
            // C-4: issue an opaque JWT token, not a raw userId.
            // RA-8 fix (reaudit): use actual remaining attempts instead of
            // hardcoded 3. If the admin already failed before, they should
            // see the real remaining count.
            const remaining = Math.max(0, 3 - (user.securityAttempts || 0))
            const challenge = signSecurityChallenge({
              userId: user.id,
              questionIndex,
              attemptsRemaining: remaining,
              remember,
              tv: challengeState.tokenVersion,
            })

            return {
              needSecurityAnswer: true,
              securityChallenge: challenge,
              // auth-deep-audit-fix Bug 3: return the question TEXT so the
              // admin can actually answer it. The previous "fresh6-fix-api
              // Fix 20" change removed this field to prevent an attacker with
              // the admin password from enumerating all questions by retrying
              // login. That concern is moot because:
              //   (a) the attacker already needs the password to reach this
              //       branch — at that point they can already log in (modulo
              //       the security answer), so enumerating 3 questions is the
              //       least of the admin's problems;
              //   (b) the route-level rate limit (10/15min/IP) plus the
              //       3-wrong-answers → 24h lock makes brute force infeasible;
              //   (c) WITHOUT the question text, the legitimate admin CANNOT
              //       answer the question — the flow was completely broken.
              // The separate GET /api/auth/security-question endpoint that
              // the old comment promised was never implemented, leaving the
              // admin with no way to see the question. Returning the text
              // here is the simplest correct fix.
              securityQuestion: questions[questionIndex].question,
              questionIndex,
              attemptsRemaining: remaining,
            }
          }
        } catch {
          // Malformed JSON → fall through to normal login.
        }
      }

      // If 2FA is enabled, don't set a cookie yet. Return a purpose-bound,
      // short-lived challenge so a later OTP completion can prove it follows a
      // successful password check for this exact account.
      if (user.twoFactorOn) {
        // round-8 bugfix (#17): snapshot tokenVersion (see the admin security
        // challenge above) so a password reset/change or security-question
        // change invalidates outstanding 2FA challenges too.
        const challengeState = await getChallengeState(user.id)
        return {
          needTwoFactor: true,
          twoFactorChallenge: signTwoFactorChallenge({
            userId: user.id,
            role: user.role as Role,
            remember,
            tv: challengeState.tokenVersion,
          }),
        }
      }

      // Cancel any pending test-account deletion (user signed back in
      // during the 10-minute grace period).
      if (user.isTestAccount && user.scheduledDeletionAt) {
        await cancelScheduledDeletion(user.id)
      }
      // UI-001 fix: pass `remember` to extend session for "Keep me signed in".
      await setSessionCookie(user.id, user.role as Role, remember)
      // BUG 1 fix: merge any guest cart items into the user's cart now
      // that they're authenticated. Combines quantities for identical
      // variations, deletes the guest cart, and clears the cookie.
      await mergeGuestCartIfAny(user.id)
      return { user: toSafeUser(user) }
    }

    // ─── VERIFY-SECURITY (admin security question answer) ───────────────────────
    if (action === 'verify-security') {
      const { securityChallenge, securityAnswer } = body
      if (!securityChallenge || !securityAnswer) {
        throw new Error('Security challenge and answer are required.')
      }

      // C-4 fix: verify the opaque challenge token. The client never sees the
      // userId — they only see the token.
      const challenge = verifySecurityChallenge(String(securityChallenge))
      if (!challenge) {
        throw new Error('Security challenge expired or invalid. Please start again.')
      }

      const user = await getAuthUser({ id: challenge.userId })
      if (!user) throw new Error('Security challenge expired or invalid. Please start again.')

      // auth-deep-audit-fix Bug 1: a banned admin must not be able to complete
      // the security-question flow and obtain a fresh session. Previously the
      // verify-security path only checked `securityLockUntil` and skipped the
      // `isBanned` check that the regular login path enforces — so an admin
      // who was banned AFTER a challenge token was issued could still answer
      // their security question and get logged in. Mirrors the same check
      // that exists on the login action (line ~170).
      if (user.isBanned) throw new Error('This account has been suspended.')

      // Check lock
      if (user.securityLockUntil && user.securityLockUntil > new Date()) {
        const hoursLeft = Math.ceil((user.securityLockUntil.getTime() - Date.now()) / 3600000)
        throw new Error(
          `Account locked. Try again in ${hoursLeft} hour(s) or unlock via OTP.`
        )
      }

      // round-8 bugfix (#17): reject challenges whose tokenVersion doesn't
      // match the user's live challenge state. A password reset/change or
      // security-question change bumps the version — every challenge issued
      // BEFORE that change dies instantly instead of surviving its 10-minute
      // JWT TTL. Challenges minted before this field existed decode with
      // tv === undefined and are treated as version 0.
      await ensureAuthSchemaReady()
      const challengeState = await getChallengeState(user.id)
      const challengeTv = typeof challenge.tv === 'number' ? challenge.tv : 0
      if (challengeTv !== challengeState.tokenVersion) {
        throw new Error('Security challenge expired or invalid. Please start again.')
      }

      // Parse questions from JSON
      let questions: Array<{ question: string; answer: string }> = []
      try {
        questions = JSON.parse(user.securityQuestions || '[]')
      } catch {}

      if (questions.length === 0) throw new Error('No security questions found.')

      const askedQ = questions[challenge.questionIndex]
      if (!askedQ) throw new Error('Invalid question.')

      // ── round-8 bugfix (#3): spend an attempt BEFORE checking the answer ──
      // The previous order (verify answer → increment on wrong) let a burst
      // of concurrent wrong answers ALL pass the lock check (read before any
      // increment landed), ALL get their answer verified, and only then bump
      // the counter — so an attacker got N answer-checks for a 3-attempt
      // budget. Spending first via one atomic conditional update bounds the
      // TOTAL number of answer-checks to exactly 3 per lock period no matter
      // the concurrency: the increment only fires while attempts < 3 AND the
      // account isn't locked, and a request whose spend matches 0 rows is
      // rejected WITHOUT its answer being checked. A correct answer simply
      // resets the counter below, so honest admins are unaffected.
      const spend = await db.user.updateMany({
        where: {
          id: user.id,
          securityAttempts: { lt: 3 },
          OR: [{ securityLockUntil: null }, { securityLockUntil: { lte: new Date() } }],
        },
        data: { securityAttempts: { increment: 1 } },
      })
      if (spend.count === 0) {
        // No attempt could be spent: either the counter is exhausted (a
        // concurrent burst already used all 3) or a lock engaged between the
        // top-of-handler read and this write. Re-read to give the honest
        // message, engage the 24h lock if this request is the one that
        // observed the exhausted counter, and never check the answer.
        const fresh = await db.user.findUnique({
          where: { id: user.id },
          select: { securityAttempts: true, securityLockUntil: true },
        })
        const lockedNow =
          !!fresh?.securityLockUntil && fresh.securityLockUntil > new Date()
        if (!lockedNow && (fresh?.securityAttempts ?? 3) >= 3) {
          const lockUntil = new Date(Date.now() + 24 * 60 * 60 * 1000)
          await db.user.update({
            where: { id: user.id },
            data: { securityLockUntil: lockUntil, securityAttempts: 0 },
          })
          await db.session.deleteMany({ where: { userId: user.id } }).catch(() => {})
          purgeUserSessionsFromCache(user.id)
        }
        if (lockedNow || (fresh?.securityAttempts ?? 3) >= 3) {
          const e: any = new Error(
            'Wrong answer. 3/3 attempts used. Account locked for 24 hours. Unlock via OTP below.'
          )
          e.code = 'SECURITY_LOCKED'
          e.attemptsRemaining = 0
          throw e
        }
        // Transient state (e.g. an unlock-OTP raced us and reset the
        // counter between the spend and the re-read) — generic retry.
        const e: any = new Error('Wrong answer. Please try again.')
        e.code = 'SECURITY_WRONG_ANSWER'
        e.attemptsRemaining = Math.max(0, 3 - (fresh?.securityAttempts ?? 3))
        throw e
      }
      const afterSpend = await db.user.findUnique({
        where: { id: user.id },
        select: { securityAttempts: true },
      })
      const attempts = afterSpend?.securityAttempts ?? 3
      const remaining = 3 - attempts

      // H-3 fix: use constant-time HMAC verification.
      // Supports both old plaintext answers (legacy) and new hashed answers.
      let isCorrect = false
      if (/^[a-f0-9]{64}$/.test(askedQ.answer)) {
        // New format: HMAC-SHA256 hash.
        isCorrect = verifySecurityAnswer(String(securityAnswer), askedQ.answer)
      } else {
        // Legacy format: plaintext. round-8 bugfix (#10): compare in
        // constant time. The old `===` short-circuits on the first
        // differing byte, leaking answer prefixes through response timing.
        // Pad both sides to the longer length so timingSafeEqual never
        // throws and the comparison cost is independent of where (and
        // whether) the strings differ. Correct answers still require exact
        // length + byte equality; the padded comparison alone would accept
        // NUL-padded collisions, hence the explicit length gate.
        const a = Buffer.from(askedQ.answer.toLowerCase().trim(), 'utf8')
        const b = Buffer.from(String(securityAnswer).toLowerCase().trim(), 'utf8')
        const maxLen = Math.max(a.length, b.length)
        const aPadded = Buffer.concat([a, Buffer.alloc(maxLen - a.length)])
        const bPadded = Buffer.concat([b, Buffer.alloc(maxLen - b.length)])
        // Always run the comparison (constant work) even when lengths differ.
        const paddedEqual = crypto.timingSafeEqual(aPadded, bPadded)
        isCorrect = a.length === b.length && paddedEqual
      }

      if (!isCorrect) {
        if (remaining <= 0) {
          // Lock the account for 24 hours after 3 wrong attempts
          const lockUntil = new Date(Date.now() + 24 * 60 * 60 * 1000)
          await db.user.update({
            where: { id: user.id },
            data: { securityLockUntil: lockUntil, securityAttempts: 0 },
          })
          // FIX: kill all active sessions for this user so they can't
          // keep using the admin panel while locked out
          await db.session.deleteMany({ where: { userId: user.id } }).catch(() => {})
          // RA3-1 fix (reaudit3): purge all cached sessions for this user
          // so the 10s in-memory cache doesn't keep serving a locked-out admin.
          purgeUserSessionsFromCache(user.id)
          // fresh6-fix-frontend-all Fix 30: attach a structured error code +
          // `attemptsRemaining` field to the thrown error so the client can
          // branch on `code` instead of parsing the human-readable message
          // string with a regex. The `err()` wrapper in lib/api.ts reads
          // `e.message` only, so we encode the structured payload as JSON in
          // the message and the client extracts it via `e.code` /
          // `e.attemptsRemaining`. The error message stays human-readable
          // for legacy clients that still parse the string.
          const e: any = new Error(
            'Wrong answer. 3/3 attempts used. Account locked for 24 hours. Unlock via OTP below.'
          )
          e.code = 'SECURITY_LOCKED'
          e.attemptsRemaining = 0
          throw e
        } else {
          const e: any = new Error(
            `Wrong answer. ${remaining} attempt(s) remaining before lock.`
          )
          e.code = 'SECURITY_WRONG_ANSWER'
          e.attemptsRemaining = remaining
          throw e
        }
      }

      // Correct answer — reset attempts, set session.
      // If the answer was legacy plaintext, migrate it to a hash now.
      const updateData: any = { securityAttempts: 0 }
      if (!/^[a-f0-9]{64}$/.test(askedQ.answer)) {
        askedQ.answer = hashSecurityAnswer(String(securityAnswer))
        updateData.securityQuestions = JSON.stringify(questions)
      }
      await db.user.update({ where: { id: user.id }, data: updateData })

      // An admin security answer is an additional gate, not a substitute for
      // configured 2FA. Previously this branch minted a session directly and
      // accidentally bypassed 2FA whenever both protections were enabled.
      if (user.twoFactorOn) {
        // round-8 bugfix (#17): carry the current tokenVersion so the 2FA
        // continuation inherits the same invalidation semantics.
        const state2fa = await getChallengeState(user.id)
        return {
          needTwoFactor: true,
          twoFactorChallenge: signTwoFactorChallenge({
            userId: user.id,
            role: user.role as Role,
            // 2026-09-10 audit fix (round 3, A-L5): use the `remember` value
            // captured at password-login time (carried by the signed
            // challenge) — NOT a fresh client-supplied body value. The direct
            // session path below already used `challenge.remember`; the 2FA
            // continuation path could previously mint a 30-day session even
            // when "keep me signed in" was unchecked at login.
            remember: challenge.remember === true,
            tv: state2fa.tokenVersion,
          }),
        }
      }

      await setSessionCookie(user.id, user.role as Role, challenge.remember)
      // AUTH-006 fix (comprehensive-audit): merge guest cart for admin login
      // flows (verify-security, unlock-security) — all other login paths
      // already do this. Without it, an admin's guest-cart items are orphaned.
      await mergeGuestCartIfAny(user.id)
      return { user: toSafeUser(user) }
    }

    // ─── UNLOCK-SECURITY (admin account unlock via OTP) ─────────────────────────
    if (action === 'unlock-security') {
      const email = validateEmail(body.email)
      if (!body.otpCode) throw new Error('Verification code is required.')

      const user = await getAuthUser({ email })
      // FIX: don't reveal whether the email exists / is admin / is locked.
      // Return the same generic message regardless of state to prevent
      // admin email enumeration.
      if (!user || user.role !== 'ADMIN') {
        throw new Error('If this account is locked, an OTP has been sent to the registered email.')
      }

      // fresh7-fix-api Fix 30: re-verify the target is ADMIN + currently
      // locked + has security questions before clearing the lock. Previously
      // any user who passed the OTP check (e.g. via a leaked 'unlock' OTP
      // for a non-admin account, or a CSRF-style flow) could clear the
      // securityQuestions/securityLockUntil fields on any account, including
      // ones that were never locked or that didn't have security questions
      // in the first place. Now we refuse to clear the lock unless ALL three
      // preconditions hold, so a misuse of the unlock flow can't wipe an
      // admin's security configuration or alter non-admin accounts.
      // FIX: role already checked above with generic error — this redundant
      // check is removed to prevent information leakage.
      // BUG 12 fix (bug-audit): information leakage. The previous code used
      // DIFFERENT error messages for each failure path:
      //   - "This account has been suspended."     → email is a banned admin
      //   - "This account is not currently locked." → email is an unlocked admin
      //   - "This account has no security questions" → email is a locked admin w/o questions
      // An attacker could enumerate admin emails by observing which message they
      // got. Now ALL failure paths use the SAME generic message as the
      // "not admin / doesn't exist" branch above, so no information leaks.
      const UNLOCK_GENERIC = 'If this account is locked, an OTP has been sent to the registered email.'
      if (user.isBanned) {
        throw new Error(UNLOCK_GENERIC)
      }
      const isLocked =
        !!user.securityLockUntil && user.securityLockUntil > new Date()
      const hasQuestions = (() => {
        if (!user.securityQuestions) return false
        try {
          const parsed = JSON.parse(user.securityQuestions)
          return Array.isArray(parsed) && parsed.length > 0
        } catch {
          return false
        }
      })()
      if (!isLocked || !hasQuestions) {
        throw new Error(UNLOCK_GENERIC)
      }

      // C-3 fix: use a dedicated 'unlock' OTP type, separate from 'login',
      // so a leaked login OTP can't unlock an admin account.
      await checkOtp(email, 'unlock', String(body.otpCode))

      // fresh3-fix-api Fix 9: wrap the lock clear + OTP consume in a single
      // transaction. Previously these were two separate DB calls — if the
      // process crashed between them, the lock was already cleared but the
      // OTP was still valid, creating a replay window where the same OTP
      // could be reused to unlock the account again. Wrapping both in a
      // $transaction makes them atomic: either both succeed, or neither.
      await db.$transaction(async (tx) => {
        // Clear the lock and reset attempts
        await tx.user.update({
          where: { id: user.id },
          data: { securityLockUntil: null, securityAttempts: 0 },
        })
        await consumeOtp(email, 'unlock', String(body.otpCode), tx)
      })
      // 2026-09-09 audit fix (M1): a valid unlock OTP must not mint a session
      // directly when 2FA is on — mirror the login flow's needTwoFactor gate so
      // the route's password-first invariant (password, then 2FA) always holds.
      if (user.twoFactorOn) {
        // round-8 bugfix (#17): carry the current tokenVersion (see login).
        // ensureAuthSchemaReady is memoized; it guarantees the
        // AuthChallengeState table exists before the read.
        await ensureAuthSchemaReady()
        const state2fa = await getChallengeState(user.id)
        return {
          needTwoFactor: true,
          twoFactorChallenge: signTwoFactorChallenge({
            userId: user.id,
            role: user.role as Role,
            remember: body.remember === true,
            tv: state2fa.tokenVersion,
          }),
        }
      }
      await setSessionCookie(user.id, user.role as Role, body.remember === true)
      // AUTH-006 fix: merge guest cart for unlock-security flow too.
      await mergeGuestCartIfAny(user.id)
      return { user: toSafeUser(user) }
    }

    // ─── LOGIN-OTP (2FA login verification) ─────────────────────────────────────
    if (action === 'login-otp') {
      if (!body.otpCode) throw new Error('Verification code is required.')

      // A valid mailbox OTP alone is not sufficient to create a session. It
      // must be paired with the short-lived challenge returned only after a
      // successful password check (or an admin security-answer check).
      const challenge = verifyTwoFactorChallenge(String(body.twoFactorChallenge || ''))
      if (!challenge) {
        throw new Error('Your sign-in verification has expired. Please enter your password again.')
      }

      const user = await getAuthUser({ id: challenge.userId })
      if (!user || user.isBanned || !user.twoFactorOn || user.role !== challenge.role) {
        throw new Error('Your sign-in verification is no longer valid. Please start again.')
      }

      // ── round-8 bugfix (#17): challenge-version check ───────────────────
      // A password reset/change or security-question change bumps the user's
      // tokenVersion — every 2FA challenge issued BEFORE that change is now
      // dead, even inside its 10-minute JWT TTL. Previously an attacker (or
      // a startled user) holding a pre-reset challenge could still finish
      // the 2FA step and mint a session after the reset.
      // ensureAuthSchemaReady is memoized and guarantees the
      // AuthChallengeState table exists before the read.
      await ensureAuthSchemaReady()
      const challengeState = await getChallengeState(user.id)
      const challengeTv = typeof challenge.tv === 'number' ? challenge.tv : 0
      if (challengeTv !== challengeState.tokenVersion) {
        throw new Error('Your sign-in verification has expired. Please enter your password again.')
      }

      // ── round-8 bugfix (#18): single-use challenge ──────────────────────
      // The challenge token is a JWT with a 10-minute TTL but had no
      // one-time-use tracking — a token exfiltrated via logs/XSS could be
      // replayed repeatedly within its TTL to brute-force OTPs.
      // round-9 bugfix: the replay check now consults the permanent
      // ConsumedChallengeJti table (UNIQUE jti) instead of the single
      // per-user slot, which a second 2FA login inside the TTL could
      // overwrite — re-arming replay of the first, already-consumed
      // challenge. Consumption is re-verified atomically inside the
      // transaction below.
      if (challenge.jti && (await isChallengeJtiConsumed(challenge.jti))) {
        throw new Error('Your sign-in verification has already been used. Please enter your password again.')
      }

      // Verify the OTP against the account encoded in the signed challenge,
      // never against email/password fields supplied by the browser.
      await checkOtp(user.email, 'login', String(body.otpCode))

      // Consume the OTP and create the matching session atomically. The
      // remembered-session choice is stored in the challenge, preventing the
      // client from extending a session by altering the second request.
      const challengeJti = typeof challenge.jti === 'string' ? challenge.jti : null
      const { token, expires } = await db.$transaction(async (tx) => {
        await consumeOtp(user.email, 'login', String(body.otpCode), tx)
        // #18 (cont.): mark the challenge consumed IN the same transaction as
        // the session creation. markChallengeConsumed throws when another
        // request already consumed this exact jti — the transaction rolls
        // back, so a concurrent replay cannot mint a second session even if
        // both passed the up-front check simultaneously.
        if (challengeJti) {
          await markChallengeConsumed(user.id, challengeJti, tx)
        }
        return createSessionRecord(user.id, user.role as Role, tx, challenge.remember)
      })

      // Cancel any pending test-account deletion (user signed back in).
      if (user.isTestAccount && user.scheduledDeletionAt) {
        await cancelScheduledDeletion(user.id)
      }
      await setSessionCookieFromToken(token, expires)
      await mergeGuestCartIfAny(user.id)
      return { user: toSafeUser(user) }
    }

    // L-1 fix: removed the duplicate (dead) login-otp block from before.

    if (action === 'logout') {
      // If the user is a test account, schedule their account for
      // deletion in 10 minutes. They can sign back in during that
      // window to cancel it.
      const currentUser = await getSessionUser()
      if (currentUser?.id) {
        await scheduleTestAccountDeletion(currentUser.id)
      }
      await clearSession()
      return { ok: true }
    }

    if (action === 'update-profile') {
      const u = await requireUser()
      const { name, phone, avatarUrl } = body
      const data: Record<string, string | null> = {}
      if (typeof name === 'string' && name.trim().length > 0) {
        const cleaned = cleanStr(name, 100)
        if (cleaned) data.name = cleaned
      }
      if (typeof phone === 'string') {
        const cleaned = cleanStr(phone, 30)
        // SECURITY: validatePhone throws on invalid input. Previously the
        // route only cleaned the phone (trim + cap) but accepted any
        // garbage string — letting users store XSS payloads or invalid
        // contact info that would later break SMS/WhatsApp integrations.
        // Allow empty string (clears the phone) but reject malformed.
        if (cleaned) {
          validatePhone(cleaned) // throws on invalid
        }
        data.phone = cleaned || null
      }
      // Only update avatarUrl if a non-empty value is provided, OR if
      // the client explicitly sends null (to remove the avatar).
      // Empty string '' is treated as "not provided" so that updating
      // name/phone doesn't accidentally delete the avatar.
      if (typeof avatarUrl === 'string' && avatarUrl.trim().length > 0) {
        // L2 fix: use availUrl() to enforce http(s)/data: protocol on avatar URLs
        // (previously used cleanStr only, allowing javascript: URLs — low impact
        // since <img src> doesn't execute JS, but still best practice).
        data.avatarUrl = availUrl(avatarUrl.trim())
      } else if (avatarUrl === null) {
        data.avatarUrl = null // explicit removal
      }
      if (Object.keys(data).length === 0) {
        throw new Error('No fields provided to update')
      }
      const updated = await db.user.update({
        where: { id: u.id },
        data,
        include: { seller: true },
      })
      return { user: toSafeUser(updated) }
    }

    if (action === 'change-password') {
      const u = await requireUser()
      const currentPassword = String(body.currentPassword || '')
      const newPassword = validatePassword(body.newPassword)

      const fullUser = await db.user.findUnique({ where: { id: u.id } })
      if (!fullUser) throw new Error('UNAUTHORIZED')
      if (!verifyPassword(currentPassword, fullUser.passwordHash)) {
        throw new Error('Current password is incorrect')
      }

      // HIGH fix: wrap password update + session invalidation in a transaction
      // so stolen JWTs can't survive a password change on transient DB failure.
      // BUG 95 fix (audit5): hash the password BEFORE the transaction. bcrypt
      // takes 100ms+ and holding the DB transaction open during hashing wastes
      // a connection. Now the CPU-intensive work happens outside the tx.
      const newHash = hashPassword(newPassword)
      await db.$transaction(async (tx) => {
        await tx.user.update({
          where: { id: u.id },
          data: { passwordHash: newHash },
        })
        await tx.session.deleteMany({ where: { userId: u.id } })
        // round-8 bugfix (#17): invalidate every outstanding security-question
        // / 2FA challenge token — a challenge issued before this password
        // change must not survive its 10-minute TTL.
        await bumpChallengeTokenVersion(u.id, tx)
        // HIGH fix (audit-2d-sec #8): invalidate any active reset-type OTPs
        // for this user so a previously-obtained OTP can't be replayed to
        // silently re-set the password after the user changes it themselves.
        // BUG 3 fix (audit2): scope to type: 'reset' ONLY. The previous
        // `where: { email, used: false }` (no type filter) invalidated ALL
        // unused OTPs — signup, login, unlock — breaking multi-device flows
        // (e.g. user changes password on Device A while Device B is mid-signup,
        // Device B's OTP becomes invalid). Only 'reset' OTPs are security-
        // sensitive after a password change.
        await tx.otpCode.updateMany({
          where: { email: u.email, used: false, type: 'reset' },
          data: { used: true },
        })
      })
      // RA3-1 fix (reaudit3): purge all cached sessions for this user.
      // The transaction above deleted all DB sessions (line 737), but the
      // in-memory sessionCache still held entries for up to 10s — a stolen
      // cookie could survive a password change for 10s.
      purgeUserSessionsFromCache(u.id)
      await setSessionCookie(u.id, u.role as Role, body.remember === true)
      return { ok: true }
    }

    // ─── RESET-PASSWORD ─────────────────────────────────────────────────────────
    if (action === 'reset-password') {
      const email = validateEmail(body.email)
      if (!body.otpCode) throw new Error('Verification code is required.')
      const newPassword = validatePassword(body.newPassword)

      // Check the OTP code is valid (without consuming it)
      await checkOtp(email, 'reset', String(body.otpCode))

      const user = await db.user.findUnique({ where: { email } })
      if (!user) throw new Error(NO_ACCOUNT)

      // round-8 bugfix (#17): the transaction below bumps the challenge
      // tokenVersion on AuthChallengeState. This flow is unauthenticated
      // (OTP-gated), so requireUser→getSessionUser hasn't run the memoized
      // schema readiness guard for us — run it explicitly so the bump can
      // never fail on a missing table.
      await ensureAuthSchemaReady()

      // HIGH fix: wrap password update + session invalidation + OTP consume
      // in a transaction so OTP can't be replayed on partial failure.
      // BUG 95 fix (audit5): hash password BEFORE the transaction (same fix
      // as change-password above — bcrypt is CPU-intensive, don't hold the
      // DB connection open during hashing).
      const newHash = hashPassword(newPassword)
      await db.$transaction(async (tx) => {
        await tx.user.update({
          where: { id: user.id },
          data: {
            passwordHash: newHash,
            // 2026-09-10 audit fix (round 3, D-M1): a successful OTP-verified
            // password reset also clears the admin security-question lockout.
            // The login error message has always said "...or reset via OTP",
            // but reset-password never cleared securityLockUntil — the hint
            // was false and a locked admin who reset their password still
            // couldn't sign in. Mailbox ownership (the reset OTP) is the SAME
            // proof the dedicated unlock-security flow requires, so clearing
            // the lock here is consistent with that flow's trust model.
            // securityLockUntil only ever exists on admin accounts, so this
            // is a no-op for regular users.
            securityLockUntil: null,
            securityAttempts: 0,
          },
        })
        await tx.session.deleteMany({ where: { userId: user.id } })
        // round-8 bugfix (#17): invalidate every outstanding security-question
        // / 2FA challenge token — a pre-reset challenge must not be completable
        // for the remainder of its 10-minute TTL after the password changed.
        await bumpChallengeTokenVersion(user.id, tx)
        await consumeOtp(email, 'reset', String(body.otpCode), tx)
      })
      // RA3-1 fix (reaudit3): purge all cached sessions so a stolen cookie
      // can't survive a password reset for the 10s cache TTL.
      purgeUserSessionsFromCache(user.id)

      return { ok: true, message: 'Password reset successfully' }
    }

    // ─── SET-SECURITY-QUESTIONS (admin only) ────────────────────────────────────
    if (action === 'set-security-questions') {
      const u = await requireUser()
      if (u.role !== 'ADMIN') throw new Error('FORBIDDEN')

      // 2026-09-09 audit fix (M3): password re-auth (mirrors toggle-2fa) before
      // mutating the admin security gate — an ADMIN session cookie alone must
      // not suffice to rewrite the security questions.
      const password = String(body.password || '')
      if (!password) throw new Error('Password is required to change security questions.')
      const fullUser = await getAuthUser({ id: u.id })
      if (!fullUser) throw new Error('UNAUTHORIZED')
      if (!verifyPassword(password, fullUser.passwordHash)) {
        throw new Error('Current password is incorrect.')
      }

      const { questions } = body
      if (!Array.isArray(questions) || questions.length === 0) {
        throw new Error('At least one question is required')
      }
      if (questions.length > 5) {
        throw new Error('You can configure up to five security questions.')
      }

      // Validate each question as an object before reading its fields. This
      // prevents malformed JSON such as [null] from becoming a production 500.
      const cleaned: Array<{ question: string; answer: string }> = []
      for (const value of questions) {
        if (!value || typeof value !== 'object') {
          throw new Error('Each security question must be an object.')
        }
        const q = value as Record<string, unknown>
        const question = sanitizeText(q.question, 200)
        const answer = cleanStr(q.answer, 100)
        if (question.length < 5) {
          throw new Error('Each question must be at least 5 characters.')
        }
        if (answer.length < 2) {
          throw new Error('Each answer must be at least 2 characters.')
        }
        // H-3 fix: hash the answer with HMAC-SHA256 (constant-time verify).
        cleaned.push({ question, answer: hashSecurityAnswer(answer) })
      }

      // Changing the admin security gate is a sensitive account change. Keep
      // this browser's valid session, but revoke other sessions so a stolen
      // device token cannot outlive the new security configuration.
      const currentSessionToken = await getCurrentSessionToken()
      await db.$transaction(async (tx) => {
        await tx.user.update({
          where: { id: u.id },
          data: {
            securityQuestions: JSON.stringify(cleaned),
            // RA-6 fix (reaudit): reset stale failed-attempt counter and lock
            // when setting NEW security questions. The previous code kept the
            // old counter, so the admin could be locked out of their NEW
            // questions with attempts from the OLD ones.
            securityAttempts: 0,
            securityLockUntil: null,
          },
        })
        // round-8 bugfix (#17): new questions must kill every challenge issued
        // against the OLD questions.
        await bumpChallengeTokenVersion(u.id, tx)
        if (currentSessionToken) {
          await tx.session.deleteMany({
            // Security audit fix (33-d #1): Session.token stores the HMAC
            // digest of the cookie JWT — compare hashes, not raw tokens.
            where: { userId: u.id, NOT: { token: hashSessionToken(currentSessionToken) } },
          })
        }
      })
      purgeUserSessionsFromCache(u.id)
      return { ok: true, count: cleaned.length }
    }

    if (action === 'remove-security-questions') {
      const u = await requireUser()
      if (u.role !== 'ADMIN') throw new Error('FORBIDDEN')

      // 2026-09-09 audit fix (M3): password re-auth (mirrors toggle-2fa) before
      // mutating the admin security gate — an ADMIN session cookie alone must
      // not suffice to remove the security questions.
      const password = String(body.password || '')
      if (!password) throw new Error('Password is required to change security questions.')
      const fullUser = await getAuthUser({ id: u.id })
      if (!fullUser) throw new Error('UNAUTHORIZED')
      if (!verifyPassword(password, fullUser.passwordHash)) {
        throw new Error('Current password is incorrect.')
      }

      const currentSessionToken = await getCurrentSessionToken()
      await db.$transaction(async (tx) => {
        await tx.user.update({
          where: { id: u.id },
          data: {
            securityQuestions: null,
            securityLockUntil: null,
            securityAttempts: 0,
          },
        })
        // round-8 bugfix (#17): removing the gate also invalidates any
        // outstanding challenge issued against the old questions.
        await bumpChallengeTokenVersion(u.id, tx)
        if (currentSessionToken) {
          await tx.session.deleteMany({
            // Security audit fix (33-d #1): compare the hashed current token.
            where: { userId: u.id, NOT: { token: hashSessionToken(currentSessionToken) } },
          })
        }
      })
      purgeUserSessionsFromCache(u.id)
      return { ok: true }
    }

    // ─── GET-SECURITY-QUESTIONS (admin only) ──────────────────────────────────
    // fresh6-fix-frontend-all Fix 23: returns the QUESTION TEXTS the admin
    // has saved (so the AdminSecurityCard can pre-populate its form on
    // mount). Answers are NEVER returned — they're stored as HMAC-SHA256
    // hashes and would be useless to display anyway (the admin can't
    // "edit" a hash). The card sends the user back through `set-security-questions`
    // to replace the answer if they want to change it.
    if (action === 'get-security-questions') {
      const u = await requireUser()
      if (u.role !== 'ADMIN') throw new Error('FORBIDDEN')
      const fullUser = await db.user.findUnique({
        where: { id: u.id },
        select: { securityQuestions: true },
      })
      let questions: Array<{ question: string }> = []
      if (fullUser?.securityQuestions) {
        try {
          const parsed = JSON.parse(fullUser.securityQuestions)
          if (Array.isArray(parsed)) {
            questions = parsed
              .map((q: any) => ({ question: typeof q?.question === 'string' ? q.question : '' }))
              .filter((q: any) => q.question.length > 0)
          }
        } catch { /* malformed JSON — treat as no questions */ }
      }
      return { questions }
    }

    // ─── TOGGLE-2FA ─────────────────────────────────────────────────────────────
    // M-11 fix: require password re-auth to toggle 2FA.
    if (action === 'toggle-2fa') {
      const u = await requireUser()
      const { enable } = body
      if (typeof enable !== 'boolean') throw new Error('Enable flag is required.')
      const password = String(body.password || '')
      if (!password) throw new Error('Password is required to change 2FA settings.')

      const fullUser = await db.user.findUnique({ where: { id: u.id } })
      if (!fullUser) throw new Error('UNAUTHORIZED')
      if (!verifyPassword(password, fullUser.passwordHash)) {
        throw new Error('Current password is incorrect.')
      }

      // fresh3-fix-api Fix 3: when 2FA is ENABLED, invalidate all other
      // sessions for this user. A stolen cookie obtained before 2FA was
      // enabled would otherwise continue to work — the attacker could
      // browse the account without ever completing a 2FA challenge. We
      // keep the current session (the one that just re-authenticated with
      // the password) so the user setting up 2FA stays logged in.
      //
      // Disabling 2FA already requires a password re-auth above, so we
      // don't invalidate sessions on disable (the user explicitly chose
      // to lower their security posture).
      //
      // RA4-3 fix (reaudit4): wrap the twoFactorOn update + session
      // deleteMany in a single transaction. Previously these were two
      // separate DB calls — if the deleteMany failed (DB blip), the
      // twoFactorOn update had already committed, leaving the user with
      // 2FA "enabled" but old (pre-2FA) sessions still alive. A stolen
      // cookie would then survive the 2FA-enable, defeating the entire
      // protection. Mirrors the change-password flow (line 732) which
      // correctly uses a transaction. The setSessionCookie (else branch)
      // stays outside the tx — cookies can't be set inside one.
      if (enable) {
        const currentSessionToken = await getCurrentSessionToken()
        await db.$transaction(async (tx) => {
          await tx.user.update({
            where: { id: u.id },
            data: { twoFactorOn: true },
          })
          if (currentSessionToken) {
            await tx.session.deleteMany({
              where: {
                userId: u.id,
                // Security audit fix (33-d #1): compare the hashed current token.
                NOT: { token: hashSessionToken(currentSessionToken) }, // keep current session
              },
            })
          } else {
            // No current session cookie — shouldn't happen (requireUser
            // passed), but defensively invalidate everything so a stolen
            // cookie can't survive a 2FA enable.
            await tx.session.deleteMany({ where: { userId: u.id } })
          }
        })
        if (!currentSessionToken) {
          await setSessionCookie(u.id, u.role as Role, body.remember === true)
        }
        // RA3-1 fix (reaudit3): purge ALL cached sessions for this user
        // (except the current one — it's still valid). The deleteMany above
        // removed the DB rows, but the in-memory cache held entries for
        // up to 10s — a stolen cookie could survive a 2FA enable for 10s.
        purgeUserSessionsFromCache(u.id)
      } else {
        await db.user.update({
          where: { id: u.id },
          data: { twoFactorOn: false },
        })
      }

      return { ok: true, twoFactorOn: enable }
    }

    throw new Error('Unknown auth action')
  })
  // R4-A1: rate limiting moved INSIDE the handler (see top of the dispatcher)
  // so routine read-only actions no longer burn the sensitive-action budget.
  // Per-action protections remain:
  //  - login: 3-attempt lockout for admin security questions
  //  - OTP send: 3 per 10 min per (email, type)
  //  - verify-security: 3 wrong answers → 24h lock
  //  - sensitive bucket: 10 actions / 15 min / IP, routine bucket: 60 / 15 min
}

// Routine, non-sensitive actions that must not consume the strict
// auth-action budget (they fire automatically during normal dashboard use).
const ROUTINE_AUTH_ACTIONS = new Set<string>([
  'get-security-questions',
  'update-profile',
  'logout',
])

// Tiny helper for the avatar URL field (kept inline so the diff is readable).
//
// fresh3-fix-api Fix 7: avatar URLs must come from an approved image host.
// Previously any `https?://` URL was accepted — a privacy leak (the URL
// could be a tracking pixel that an attacker controls, revealing when the
// user's profile is viewed) and a potential vector for malicious content.
// Only allow the production CDN hosts we actually upload to.
const ALLOWED_AVATAR_HOSTS = new Set<string>([
  'z-cdn.chatglm.cn',
  'firebasestorage.googleapis.com',
  'res.cloudinary.com',
  'cdn.nixe.pk',
])

function availUrl(v: string): string {
  if (typeof v !== 'string') {
    throw new Error('Avatar must be from an approved image host')
  }
  if (/^https?:\/\//i.test(v)) {
    // Validate the host against the allowlist.
    let host = ''
    try {
      host = new URL(v).host.toLowerCase()
    } catch {
      throw new Error('Avatar must be from an approved image host')
    }
    if (!ALLOWED_AVATAR_HOSTS.has(host)) {
      throw new Error('Avatar must be from an approved image host')
    }
    return v.slice(0, 2048)
  }
  if (/^data:/i.test(v)) {
    // data: URLs already restricted to safe raster types (prior fix).
    // SVG (`data:image/svg+xml`) is an XSS vector — SVG can carry
    // <script> tags and is rendered as active content.
    if (!/^data:image\/(png|jpe?g|webp|gif)\b/i.test(v)) {
      throw new Error('Invalid image format. Only PNG, JPEG, WebP, and GIF are allowed.')
    }
    /* Audit-15 fix (A15-A L6): the old `v.slice(0, 2048)` silently
     * truncated every real avatar data-URL into a corrupt, unrenderable
     * image — the sanctioned /api/auth/avatar route stores sharp-processed
     * 256×256 WebP data URLs (~10-20KB ≈ 14-28K base64 chars), far beyond
     * 2048. Truncation corrupts; REJECT over-cap values instead (mirrors
     * the seller product-image policy) with a pointer to the upload route. */
    if (v.length > 30_000) {
      throw new Error(
        'Inline avatar image is too large (max 30,000 characters). Upload via /api/auth/avatar and use the returned URL instead.'
      )
    }
    return v
  }
  // Reject javascript:, file:, ftp:, and any other non-http(s)/non-data: scheme.
  throw new Error('Avatar must be from an approved image host')
}

/**
 * BUG 1 fix — merge a guest cart (if any) into the just-logged-in user's
 * cart. Reads the `nixe_guest_cart` cookie; if present, calls
 * `mergeGuestCartIntoUserCart` to combine quantities and delete the guest
 * cart, then clears the cookie.
 *
 * Failures are logged but NOT thrown — a cart-merge bug should never
 * prevent the user from logging in. The guest cart cookie is cleared only
 * after a successful merge; preserving it on failure allows a later retry
 * instead of silently orphaning the guest cart.
 */
async function mergeGuestCartIfAny(userId: string): Promise<void> {
  try {
    const guestId = await readGuestCartCookie()
    if (!guestId) return
    await mergeGuestCartIntoUserCart(guestId, userId)
    // Clear only after the merge succeeds. If the database is temporarily
    // unavailable, keep the cookie so a later login can retry safely.
    try { await clearGuestCartCookie() } catch { /* ignore */ }
  } catch (e: any) {
    logger.info('[auth] guest cart merge failed (non-fatal):', e?.message)
  }
}
