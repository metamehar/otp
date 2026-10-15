import { logger } from './logger'

/**
 * Resend email transport — REPLACES the Gmail SMTP path for ALL OTP mail.
 *
 * Scope (2026-10-15 OTP-over-Resend migration):
 *   - src/lib/email.ts sendOtpEmail() and sendAlreadyRegisteredEmail() now
 *     deliver through this module (Resend REST API, https://resend.com).
 *   - The nodemailer/Gmail transporter in email.ts remains ONLY for the
 *     non-OTP transactional mailers (order confirmation, contact form,
 *     seller verification, job applications).
 *
 * SETUP (.env):
 *   RESEND_API_KEY="re_..."        # resend.com → API Keys → Create API Key
 *   RESEND_FROM="NIXE <onboarding@resend.dev>"
 *                                  # shared TEST sender — delivers ONLY to
 *                                  # the email that owns the Resend account
 *   RESEND_FROM="NIXE <no-reply@nixe.pk>"
 *                                  # production sender — requires verifying
 *                                  # the domain in Resend → Domains (DNS)
 *   RESEND_REPLY_TO="support@nixe.pk"  # optional
 *
 * API reference: POST https://api.resend.com/emails
 *   { from, to[], subject, html, text, reply_to?, attachments? }
 *   attachments: [{ filename, content: <base64>, content_id }] — content_id
 *   enables inline CID references (the NIXE logo uses cid:nixelogo).
 */

const RESEND_API_KEY = process.env.RESEND_API_KEY || ''
const RESEND_FROM = process.env.RESEND_FROM || 'NIXE <onboarding@resend.dev>'
const RESEND_REPLY_TO = process.env.RESEND_REPLY_TO || ''

/** True when the OTP email path is operational (Resend key present). */
export const isResendConfigured = Boolean(RESEND_API_KEY)

/** CRLF strip — same defense-in-depth as email.ts sanitizeHeader. */
function safeHeader(value: string): string {
  return String(value).replace(/[\r\n]/g, '').trim()
}

export interface ResendAttachment {
  filename: string
  /** Base64-encoded file content. */
  content: string
  /** Inline CID for <img src="cid:..."> references. */
  content_id?: string
}

export interface ResendSendOptions {
  to: string
  subject: string
  html: string
  text: string
  attachments?: ResendAttachment[]
}

/**
 * Send one email through the Resend REST API. Throws on any failure —
 * callers (auth/otp route) invalidate the issued OTP when this throws so a
 * code that was never delivered can never be used.
 */
export async function sendViaResend(opts: ResendSendOptions): Promise<{ id: string }> {
  if (!RESEND_API_KEY) {
    throw new Error('Email service not configured. Add RESEND_API_KEY to .env')
  }

  const payload: Record<string, unknown> = {
    from: safeHeader(RESEND_FROM),
    to: [safeHeader(opts.to)],
    subject: safeHeader(opts.subject),
    html: opts.html,
    text: opts.text,
  }
  if (RESEND_REPLY_TO) payload.reply_to = safeHeader(RESEND_REPLY_TO)
  if (opts.attachments && opts.attachments.length > 0) payload.attachments = opts.attachments

  let res: Response
  try {
    res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
      // Bound the network wait so a stalled Resend API cannot hold an auth
      // request until the platform kills the function (mirrors the SMTP
      // timeouts the nodemailer path used).
      signal: AbortSignal.timeout(15_000),
    })
  } catch (err) {
    logger.error('[resend] network failure:', err instanceof Error ? err.message : String(err))
    throw new Error('Email delivery network failure.')
  }

  if (!res.ok) {
    let detail = ''
    try {
      const body = (await res.json()) as { message?: string; name?: string }
      detail = [body?.name, body?.message].filter(Boolean).join(': ')
    } catch {
      detail = (await res.text().catch(() => '')).slice(0, 300)
    }
    logger.error(`[resend] delivery failed (${res.status}): ${detail}`)
    // Surface operator-actionable cases distinctly (they end up in dev.log /
    // Vercel logs; the end user only ever sees the route's generic message).
    if (res.status === 401) {
      throw new Error('Resend API key rejected (401) — check RESEND_API_KEY.')
    }
    if (res.status === 403) {
      // Classic sandbox-mode restriction: sending to a non-account email
      // before the domain is verified.
      throw new Error(
        `Resend refused the send (403): ${detail || 'unverified domain / testing restriction'}. ` +
        `Verify your domain in Resend → Domains, or send only to the Resend account email while using onboarding@resend.dev.`
      )
    }
    if (res.status === 422) {
      throw new Error(`Resend rejected the email payload (422): ${detail}`)
    }
    if (res.status === 429) {
      throw new Error('Resend rate limit hit (429) — slow down OTP sends.')
    }
    throw new Error(`Resend delivery failed (${res.status}).`)
  }

  const json = (await res.json().catch(() => null)) as { id?: string } | null
  if (!json?.id) {
    logger.error('[resend] 2xx response without an email id — treating as failure.')
    throw new Error('Resend returned an unexpected response.')
  }
  return { id: json.id }
}
