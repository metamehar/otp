import { PrismaClient } from '@prisma/client'
import { PrismaLibSql } from '@prisma/adapter-libsql'
import { PrismaPg } from '@prisma/adapter-pg'
import type { Prisma } from '@prisma/client'
// Env validation — logs warnings but never crashes (see env.ts).
import '@/lib/env'

const databaseUrl = process.env.DATABASE_URL ?? 'file:./db/custom.db'

// round-10 fix (r10-d D5): on a Vercel production deployment a missing
// DATABASE_URL is ALWAYS a configuration error (Vercel injects it for every
// environment) — the old silent fallback served an empty SQLite catalog
// with 200s instead of failing loudly. Hard-fail at module load so the
// deployment surfaces the misconfiguration immediately. Local dev (and
// non-Vercel self-hosting, where a file: fallback may be deliberate) keeps
// the lenient default.
if (process.env.VERCEL === '1' && process.env.NODE_ENV === 'production' && !process.env.DATABASE_URL) {
  throw new Error(
    '[db] FATAL: DATABASE_URL is not set on this production deployment. ' +
    'Configure the Postgres connection string in the hosting dashboard — refusing to serve an empty local database.'
  )
}

// C4/C3 support (2026 audit): provider flag shared by code that must branch
// between SQLite (dev) and Postgres (Supabase prod) behavior — e.g.
// case-insensitive `contains` (mode: 'insensitive' is Postgres-only) and
// information_schema vs sqlite_master table listings.
export const isPostgres =
  databaseUrl.startsWith('postgres://') || databaseUrl.startsWith('postgresql://')

function createPrismaClient() {
  if (databaseUrl.startsWith('postgres://') || databaseUrl.startsWith('postgresql://')) {
    const adapter = new PrismaPg({
      connectionString: databaseUrl,
      // 2026-10-03 fix: bounded I/O. The pg defaults (connectionTimeoutMillis=0,
      // no statement/query timeout) mean a stalled or unreachable Postgres
      // hangs page prerendering and API requests indefinitely — exactly the
      // "stuck in Building for 10+ minutes" Vercel deploys we saw. With these
      // bounds, a bad DB fails FAST and the catalog layer degrades pages to
      // empty states instead (see src/lib/catalog.ts safeDb).
      connectionTimeoutMillis: 15_000,
      statement_timeout: 20_000,
      query_timeout: 20_000,
      // 2026-10-05 perf fix ("slow sometimes, normal sometimes"): the Vercel
      // function and Supabase are in different regions (~170ms RTT measured —
      // see worklog Task 38). A new pg connection pays TCP + TLS + SCRAM auth
      // ≈ 4-5 round trips ≈ 700ms. The old 30s idle reap meant ANY warm
      // instance that sat idle >30s tore its pooled connection down and paid
      // that handshake again on the next request — the exact intermittent
      // slowness pattern. Keep connections pooled for 5 minutes so warm
      // instances reuse them, and enable TCP keepalive so NAT-dropped or
      // freeze-killed sockets are detected quickly instead of hanging.
      idleTimeoutMillis: 300_000,
      keepAlive: true,
      keepAliveInitialDelayMillis: 15_000,
    })
    return new PrismaClient({ adapter })
  }

  // PrismaLibSql supports both remote libSQL URLs and local `file:` SQLite
  // URLs. Using one adapter for both avoids the native better-sqlite3 install
  // chain while preserving the Unix-epoch-millisecond format used by the
  // existing Prisma SQLite database.
  const adapter = new PrismaLibSql(
    {
      url: databaseUrl,
      authToken: process.env.TURSO_AUTH_TOKEN,
    },
    { timestampFormat: 'unixepoch-ms' },
  )
  return new PrismaClient({ adapter })
}

type PrismaDbClient = ReturnType<typeof createPrismaClient>

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaDbClient | undefined
}

// SAFETY: always construct a PrismaClient. If DATABASE_URL is missing or the
// database is unreachable, individual queries throw and are handled by the
// existing API/SSR boundaries.
export const db = globalForPrisma.prisma ?? createPrismaClient()

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = db

/**
 * Serialize a short critical section per key (security audit run-2 fix for
 * auth-lockout-nonautomic-count-then-insert + newsletter-unsubscribe-verify-
 * lockout.email-keyed-bait-accounting).
 *
 * The login lockout, the OTP bait-row lockout, and the OTP issuance caps were
 * all count-then-insert sequences across separate auto-commit statements: a
 * concurrent wave whose COUNT reads all execute before any INSERT commits
 * each observe the same sub-threshold count and are all admitted, so the
 * failed-guess budget per email/window overshoots the configured cap (run-1
 * lead, re-verified in run-2). Wrapping the count+insert pair in a short
 * transaction that first takes a Postgres transaction-scoped advisory lock
 * keyed on the caller-supplied key serializes every concurrent request for
 * the same email/type until the pair commits — the codebase's existing
 * spend-first pattern (verify-security) generalized.
 *
 * On Postgres, `pg_advisory_xact_lock(hashtext(key)::bigint)` blocks other
 * withKeyLock callers with the same key until this transaction commits (the
 * lock auto-releases; no cleanup path exists). On SQLite/libSQL (local dev)
 * the plain interactive transaction still pairs the statements; local dev
 * does not face the multi-instance concurrency the lock exists for.
 *
 * Keep the callback SHORT (count + insert only) — never run bcrypt, network
 * I/O, or long computations inside it.
 */
export async function withKeyLock<T>(
  key: string,
  fn: (tx: Prisma.TransactionClient) => Promise<T>,
): Promise<T> {
  if (isPostgres) {
    return db.$transaction(async (tx) => {
      // 2026-10-15 Supabase migration fix: $queryRaw FAILS on Postgres here —
      // pg_advisory_xact_lock() returns `void`, and Prisma's $queryRaw result
      // deserializer cannot read a void column ("Failed to deserialize column
      // of type 'void'"), which 500'd every withKeyLock caller on Postgres
      // (login lockout accounting, OTP issuance caps, bait-row lockouts).
      // $executeRaw runs the statement and skips result-column deserialization.
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${key})::bigint)`
      return fn(tx)
    })
  }
  return db.$transaction(async (tx) => fn(tx))
}
