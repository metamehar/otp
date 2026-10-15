// round-11 fix (r11-c D2): nodemailer 10 bundles its own declarations, but
// they export NAMED types instead of the global `nodemailer` namespace the
// removed @types/nodemailer package provided — import the two types we use
// by name. (v10 keeps the CJS default export; runtime usage unchanged.)
import nodemailer from 'nodemailer'
import type { Transporter, SendMailOptions } from 'nodemailer'
import fs from 'fs'
import path from 'path'
import { BASE_URL } from '@/lib/site'
import { sendViaResend, isResendConfigured } from '@/lib/resend'
import type { ValidatedSellerApplication } from '@/lib/seller-verification'

/**
 * Email Service.
 *
 * 2026-10-15 OTP-over-Resend migration — the OTP sending mechanism now runs
 * EXCLUSIVELY through Resend (https://resend.com, REST API):
 *   - sendOtpEmail()          → Resend (was Gmail SMTP)
 *   - sendAlreadyRegisteredEmail() → Resend (was Gmail SMTP)
 *   - isEmailConfigured       → true iff RESEND_API_KEY is set
 * The Gmail SMTP / nodemailer transporter below remains ONLY for the non-OTP
 * transactional mailers (order confirmation, contact form, seller
 * verification, job applications).
 *
 * LEGACY non-OTP SMTP SETUP (unchanged):
 * 1. https://myaccount.google.com/security → Enable 2-Step Verification
 * 2. "App passwords" → Generate a new app password for "Mail"
 * 3. Add to .env: EMAIL_USER=your@gmail.com  EMAIL_PASS=your-16-char-password
 */

const EMAIL_USER = process.env.EMAIL_USER || ''
const EMAIL_PASS = process.env.EMAIL_PASS || ''
const SMTP_HOST = process.env.SMTP_HOST || ''
const SMTP_PORT = Number(process.env.SMTP_PORT || '587')
const SMTP_SECURE = process.env.SMTP_SECURE === 'true'
const SMTP_REQUIRE_TLS = process.env.SMTP_REQUIRE_TLS === 'true'
const FROM_NAME = process.env.EMAIL_FROM_NAME || 'NIXE'
const FROM_EMAIL = process.env.EMAIL_FROM || EMAIL_USER

let transporter: Transporter | null = null

/**
 * fix-critical-security #16: strip CR/LF from any value destined for an
 * email header (From, To, Subject, Reply-To, etc.).
 *
 * Email headers are separated by CRLF (`\r\n`). If a user-supplied value
 * (name, email, subject) contains a literal CR or LF, an attacker can
 * inject additional headers — e.g. a `Bcc: attacker@evil.com` header
 * that secretly CCs the attacker on every email, or a fake
 * `Subject: ...` that overwrites the real subject. This is "email
 * header injection" (CWE-93).
 *
 * Stripping `\r` and `\n` from header values closes the injection
 * vector. We also `.trim()` to drop trailing whitespace (some clients
 * add a trailing space to headers, which is harmless but ugly).
 *
 * NOTE: this does NOT validate the value is a "legal" header — it just
 * ensures it can't break out of the current header. Email-format
 * validation (e.g. for `to`/`replyTo`) is the caller's responsibility
 * (see `validateEmail` in src/lib/validate.ts).
 */
function sanitizeHeader(value: unknown): string {
  if (value == null) return ''
  return String(value).replace(/[\r\n]/g, '').trim()
}

function getTransporter(): Transporter | null {
  if (!EMAIL_USER || !EMAIL_PASS) return null

  if (!transporter) {
    const transportOptions = SMTP_HOST
      ? {
          host: SMTP_HOST,
          port: Number.isFinite(SMTP_PORT) ? SMTP_PORT : 587,
          secure: SMTP_SECURE,
          requireTLS: SMTP_REQUIRE_TLS,
          auth: {
            user: EMAIL_USER,
            pass: EMAIL_PASS,
          },
        }
      : {
          service: 'gmail' as const,
          auth: {
            user: EMAIL_USER,
            pass: EMAIL_PASS,
          },
        }

    transporter = nodemailer.createTransport({
      ...transportOptions,
      // Bound network waits so an SMTP outage cannot hold an auth request
      // until the hosting platform kills the function. We intentionally do
      // not blindly retry sendMail(): after a socket timeout Gmail may already
      // have accepted the message, and retrying sensitive identity details can
      // create duplicate review emails.
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 15_000,
    })
  }
  return transporter
}

/**
 * Whether the OTP email path is operational.
 *
 * 2026-10-15: OTP mail is delivered ONLY via Resend, so this is now keyed to
 * RESEND_API_KEY (was: Gmail EMAIL_USER+EMAIL_PASS). All OTP call sites
 * (auth/otp route, newsletter subscribe/unsubscribe) gate on this flag.
 * The non-OTP mailers keep using the legacy SMTP transporter and do NOT
 * consult this flag.
 */
export const isEmailConfigured = isResendConfigured

/** Read the logo file as a Buffer for inline embedding.
 *  Uses the DARK logo (white text) — visible on dark email header backgrounds.
 *
 *  BUG 70 fix (audit4): cache the buffer at module level. Previously every
 *  email send read the logo file from disk synchronously, blocking the event
 *  loop. Under high email volume (e.g. flash sale with 1000 OTPs), this
 *  caused significant I/O latency. Now the file is read once and cached.
 */
let logoBufferCache: Buffer | null | undefined = undefined
function getLogoBuffer(): Buffer | null {
  if (logoBufferCache !== undefined) return logoBufferCache
  try {
    const logoPath = path.join(process.cwd(), 'public', 'nixe-logo-dark.png')
    logoBufferCache = fs.readFileSync(logoPath)
  } catch {
    logoBufferCache = null
  }
  return logoBufferCache
}

/** Send an OTP verification email */
export async function sendOtpEmail(to: string, code: string, type: 'signup' | 'reset' | 'login' | 'unlock' | 'unsubscribe' | 'subscribe'): Promise<boolean> {
  // 2026-10-15 OTP-over-Resend migration: OTP mail is delivered ONLY via
  // Resend. The legacy Gmail transporter is no longer consulted here.
  if (!isResendConfigured) {
    throw new Error('Email service not configured. Add RESEND_API_KEY to .env')
  }

  const subject = type === 'reset'
    ? 'Reset your NIXE password'
    : type === 'login'
    ? 'Your NIXE login code'
    : type === 'unlock'
    ? 'Unlock your NIXE admin account'
    : type === 'unsubscribe'
    ? 'Confirm your NIXE newsletter unsubscribe'
    : type === 'subscribe'
    ? 'Confirm your NIXE newsletter subscription'
    : 'Verify your NIXE account'

  const purpose = type === 'reset'
    ? 'reset your password'
    : type === 'login'
    ? 'log in to your account'
    : type === 'unlock'
    ? 'unlock your admin account'
    : type === 'unsubscribe'
    ? 'unsubscribe from the NIXE newsletter'
    : type === 'subscribe'
    ? 'finish subscribing to the NIXE newsletter'
    : 'verify your email address'

  const logoBuffer = getLogoBuffer()

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background:#f3f3f3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f3f3f3;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
          <!-- Header with NIXE logo -->
          <tr>
            <td style="background:#14110c;padding:28px 40px;text-align:center;">
              ${logoBuffer
                ? `<img src="cid:nixelogo" alt="NIXE" width="120" style="display:block;margin:0 auto;" />`
                : '<h1 style="margin:0;color:#ffffff;font-size:28px;font-weight:900;letter-spacing:-1px;">NIXE</h1>'
              }
              <p style="margin:8px 0 0;color:#999;font-size:13px;">Everything you love, delivered fast</p>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td style="padding:36px 40px;">
              <h2 style="margin:0 0 8px;color:#14110c;font-size:20px;font-weight:700;">${subject}</h2>
              <p style="margin:0 0 24px;color:#555;font-size:15px;line-height:1.6;">
                Use the code below to ${purpose}. This code expires in 10 minutes.
              </p>
              <!-- OTP Code -->
              <div style="text-align:center;margin:28px 0;">
                <div style="display:inline-block;background:#FFF8E7;border:2px dashed #FFD700;border-radius:10px;padding:18px 40px;">
                  <span style="font-size:36px;font-weight:900;letter-spacing:8px;color:#14110c;font-family:'Courier New',monospace;">${code}</span>
                </div>
              </div>
              <p style="margin:24px 0 0;color:#999;font-size:13px;line-height:1.5;">
                If you didn't request this code, you can safely ignore this email. Someone may have entered your email by mistake.
              </p>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="background:#14110c;padding:24px 40px;text-align:center;">
              <p style="margin:0 0 8px;color:#ffffff;font-size:16px;font-weight:900;letter-spacing:-0.5px;">NIXE</p>
              <p style="margin:0;color:#888;font-size:12px;">
                &copy; ${new Date().getFullYear()} NIXE, Inc. &middot; This is an automated email, please do not reply.
              </p>
              <p style="margin:4px 0 0;color:#666;font-size:11px;">
                <a href="${BASE_URL}" style="color:#666;text-decoration:none;">${BASE_URL}</a>
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `.trim()

  const text = `NIXE — ${subject}\n\nYour verification code is: ${code}\n\nUse this code to ${purpose}. This code expires in 10 minutes.\n\nIf you didn't request this, you can safely ignore this email.\n\n© ${new Date().getFullYear()} NIXE, Inc.\n${BASE_URL}`

  // Build the Resend payload.
  // fix-critical-security #16: sanitize ALL header-bound values to prevent
  // email header injection (CRLF injection → Bcc/Subject spoofing).
  //   - `to` is the user's email — the caller runs validateEmail, but we
  //     sanitize again in case the value slipped through with embedded CRLF.
  //   - `subject` is hardcoded (no user input) but sanitized for symmetry.
  //   - `from` is operator-controlled via RESEND_FROM and sanitized inside
  //     sendViaResend itself.
  const safeTo = sanitizeHeader(to)
  const safeSubject = sanitizeHeader(subject)

  // 2026-10-15: delivered via the Resend REST API. The attachments entry
  // carries content_id: 'nixelogo', giving the exact same inline-CID
  // behaviour nodemailer's `cid:` option provided for the logo.
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
}

/**
 * 2026-09-10 re-audit fix (M2 residual): when someone requests a SIGNUP
 * verification code for an email that is already registered, no code is
 * issued (suppression). Previously that left the requester in a silent
 * dead-end: the generic "code sent" response arrives, no email is ever
 * delivered, and every code they type fails. This mailer tells the actual
 * mailbox owner what happened and what to do instead (sign in / reset
 * password). It also keeps the request timing comparable between the
 * registered and unregistered paths (both hit SMTP), blunting the
 * suppression-vs-send timing side channel.
 */
export async function sendAlreadyRegisteredEmail(to: string): Promise<boolean> {
  // 2026-10-15 OTP-over-Resend migration: courtesy notice goes via Resend.
  // When Resend is not configured this is a silent no-op — the notice is
  // best-effort by design and must never break the signup flow.
  if (!isResendConfigured) return false

  const subject = 'You already have a NIXE account'
  const logoBuffer = getLogoBuffer()

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background:#f3f3f3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f3f3f3;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
          <tr>
            <td style="background:#14110c;padding:28px 40px;text-align:center;">
              ${logoBuffer
                ? `<img src="cid:nixelogo" alt="NIXE" width="120" style="display:block;margin:0 auto;" />`
                : '<h1 style="margin:0;color:#ffffff;font-size:28px;font-weight:900;letter-spacing:-1px;">NIXE</h1>'
              }
              <p style="margin:8px 0 0;color:#999;font-size:13px;">Everything you love, delivered fast</p>
            </td>
          </tr>
          <tr>
            <td style="padding:36px 40px;">
              <h2 style="margin:0 0 8px;color:#14110c;font-size:20px;font-weight:700;">${subject}</h2>
              <p style="margin:0 0 16px;color:#555;font-size:15px;line-height:1.6;">
                Someone just tried to create a new NIXE account with this email address — but an account
                with this address already exists, so we didn't send a signup code.
              </p>
              <ul style="margin:0 0 16px;padding-left:20px;color:#555;font-size:15px;line-height:1.8;">
                <li>If this was you, <a href="${BASE_URL}/login" style="color:#d97706;">sign in</a> instead.</li>
                <li>Forgot your password? <a href="${BASE_URL}/forgot-password" style="color:#d97706;">Reset it here</a>.</li>
              </ul>
              <p style="margin:24px 0 0;color:#999;font-size:13px;line-height:1.5;">
                If you didn't request this, you can safely ignore this email — no signup code was sent and no account changes were made.
              </p>
            </td>
          </tr>
          <tr>
            <td style="background:#14110c;padding:24px 40px;text-align:center;">
              <p style="margin:0 0 8px;color:#ffffff;font-size:16px;font-weight:900;letter-spacing:-0.5px;">NIXE</p>
              <p style="margin:0;color:#888;font-size:12px;">
                &copy; ${new Date().getFullYear()} NIXE, Inc. &middot; This is an automated email, please do not reply.
              </p>
              <p style="margin:4px 0 0;color:#666;font-size:11px;">
                <a href="${BASE_URL}" style="color:#666;text-decoration:none;">${BASE_URL}</a>
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `.trim()

  const text = `NIXE — ${subject}\n\nSomeone just tried to create a new NIXE account with this email address, but an account already exists, so no signup code was sent.\n\nIf this was you, sign in instead: ${BASE_URL}/login\nForgot your password? Reset it here: ${BASE_URL}/forgot-password\n\nIf you didn't request this, you can safely ignore this email.\n\n© ${new Date().getFullYear()} NIXE, Inc.\n${BASE_URL}`

  const safeTo = sanitizeHeader(to)
  const safeSubject = sanitizeHeader(subject)

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
}

/**
 * H3 fix (2026 audit): transactional order-confirmation email sent to the
 * BUYER. The checkout route previously reused sendContactEmail — whose
 * default recipient is the NIXE support inbox — so every "Order
 * Confirmation" landed with the operators and the customer received
 * nothing (no order number, no COD amount). This is a real transactional
 * mailer: `to` is the customer's address, the operator notification stays
 * a separate sendContactEmail call in the checkout route.
 */
export async function sendOrderConfirmationEmail(opts: {
  to: string
  name: string
  orderNumber: string
  subtotal: string
  shippingFee: string
  /* Audit-4 fix (A3): optional promo-discount row — without it the COD
   * receipt showed Subtotal + Shipping ≠ Total with an unexplained gap
   * on every promo order, exactly on the document the customer uses to
   * prepare the courier amount. */
  discount?: string
  total: string
  paymentMethod: string
  deliveryMethod: string
  itemLines: { title: string; quantity: number; price: string }[]
}): Promise<boolean> {
  const transport = getTransporter()
  if (!transport) {
    throw new Error('Email service not configured. Add EMAIL_USER and EMAIL_PASS to .env')
  }

  const logoBuffer = getLogoBuffer()

  const deliveryLabel =
    opts.deliveryMethod === 'PRIME'
      ? 'NIXE Swift (priority delivery)'
      : opts.deliveryMethod === 'EXPRESS'
        ? 'Express (1–2 business days)'
        : 'Standard (3–7 business days)'

  const itemRows = opts.itemLines
    .map(
      (l) => `
        <tr>
          <td style="padding:10px 16px;background:#ffffff;border:1px solid #e5e5e5;font-size:14px;color:#14110c;">${escapeHtml(l.title)}</td>
          <td style="padding:10px 16px;background:#ffffff;border:1px solid #e5e5e5;font-size:14px;color:#14110c;text-align:center;">${escapeHtml(String(l.quantity))}</td>
          <td style="padding:10px 16px;background:#ffffff;border:1px solid #e5e5e5;font-size:14px;color:#14110c;text-align:right;">${escapeHtml(l.price)}</td>
        </tr>
      `
    )
    .join('')

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background:#f3f3f3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f3f3f3;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
          <tr>
            <td style="background:#14110c;padding:28px 40px;text-align:center;">
              ${logoBuffer
                ? `<img src="cid:nixelogo" alt="NIXE" width="120" style="display:block;margin:0 auto;" />`
                : '<h1 style="margin:0;color:#ffffff;font-size:28px;font-weight:900;letter-spacing:-1px;">NIXE</h1>'
              }
              <p style="margin:8px 0 0;color:#999;font-size:13px;">Everything you love, delivered fast</p>
            </td>
          </tr>
          <tr>
            <td style="padding:36px 40px;">
              <h2 style="margin:0 0 8px;color:#14110c;font-size:20px;font-weight:700;">Thank you for your order!</h2>
              <p style="margin:0 0 24px;color:#555;font-size:15px;line-height:1.6;">
                Hi ${escapeHtml(opts.name)}, we've received your order and will start preparing it right away.
              </p>
              <div style="background:#FFF8E7;border:1px solid #FFD700;border-radius:10px;padding:16px 20px;margin:0 0 24px;">
                <p style="margin:0;font-size:13px;color:#555;">Order Number</p>
                <p style="margin:4px 0 0;font-size:22px;font-weight:900;color:#14110c;letter-spacing:1px;">${escapeHtml(opts.orderNumber)}</p>
              </div>
              <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin:0 0 16px;">
                <tr>
                  <th style="padding:10px 16px;background:#f7f7f7;border:1px solid #e5e5e5;font-size:12px;font-weight:700;color:#555;text-align:left;">Item</th>
                  <th style="padding:10px 16px;background:#f7f7f7;border:1px solid #e5e5e5;font-size:12px;font-weight:700;color:#555;text-align:center;">Qty</th>
                  <th style="padding:10px 16px;background:#f7f7f7;border:1px solid #e5e5e5;font-size:12px;font-weight:700;color:#555;text-align:right;">Price</th>
                </tr>
                ${itemRows}
              </table>
              <table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 24px;">
                <tr>
                  <td style="padding:4px 0;font-size:14px;color:#555;">Subtotal</td>
                  <td style="padding:4px 0;font-size:14px;color:#14110c;text-align:right;">${escapeHtml(opts.subtotal)}</td>
                </tr>
                <tr>
                  <td style="padding:4px 0;font-size:14px;color:#555;">Shipping (${escapeHtml(deliveryLabel)})</td>
                  <td style="padding:4px 0;font-size:14px;color:#14110c;text-align:right;">${escapeHtml(opts.shippingFee)}</td>
                </tr>
                ${opts.discount ? `<tr>
                  <td style="padding:4px 0;font-size:14px;color:#555;">Discount</td>
                  <td style="padding:4px 0;font-size:14px;color:#2a7a2a;text-align:right;">−${escapeHtml(opts.discount)}</td>
                </tr>` : ''}
                <tr>
                  <td style="padding:12px 0 4px;font-size:16px;font-weight:700;color:#14110c;">Total</td>
                  <td style="padding:12px 0 4px;font-size:16px;font-weight:700;color:#14110c;text-align:right;">${escapeHtml(opts.total)}</td>
                </tr>
              </table>
              <p style="margin:0 0 24px;color:#555;font-size:14px;line-height:1.6;">
                Payment: <strong>${opts.paymentMethod === 'COD' ? 'Cash on Delivery' : escapeHtml(opts.paymentMethod)}</strong> —
                ${opts.paymentMethod === 'COD'
                  ? 'please keep the exact amount ready for the courier.'
                  : 'your payment method on file will be charged.'}
              </p>
              <p style="margin:24px 0 0;color:#999;font-size:13px;line-height:1.5;">
                You can track your order status any time from your NIXE account.
                If you have questions, reply to this email or contact support@nixe.pk.
              </p>
            </td>
          </tr>
          <tr>
            <td style="background:#14110c;padding:24px 40px;text-align:center;">
              <p style="margin:0 0 8px;color:#ffffff;font-size:16px;font-weight:900;letter-spacing:-0.5px;">NIXE</p>
              <p style="margin:0;color:#888;font-size:12px;">
                &copy; ${new Date().getFullYear()} NIXE, Inc. &middot; This is an automated email, please do not reply.
              </p>
              <p style="margin:4px 0 0;color:#666;font-size:11px;">
                <a href="${BASE_URL}" style="color:#666;text-decoration:none;">${BASE_URL}</a>
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `.trim()

  const text = `NIXE — Order Confirmation\n\nThank you for your order!\n\nOrder Number: ${opts.orderNumber}\n${opts.itemLines.map((l) => `\n  • ${l.title} × ${l.quantity} — ${l.price}`).join('')}\n\nSubtotal: ${opts.subtotal}\nShipping: ${opts.shippingFee}${opts.discount ? `\nDiscount: -${opts.discount}` : ''}\nTotal: ${opts.total}\nPayment: ${opts.paymentMethod === 'COD' ? 'Cash on Delivery' : opts.paymentMethod}\n\nTrack your order any time from your NIXE account.\n\n© ${new Date().getFullYear()} NIXE, Inc.\n${BASE_URL}`

  // fix-critical-security #16 pattern: sanitize ALL header-bound values to
  // prevent email header injection (the buyer's name/email are user input).
  const safeFromName = sanitizeHeader(FROM_NAME)
  const safeFromEmail = sanitizeHeader(FROM_EMAIL)
  const safeTo = sanitizeHeader(opts.to)
  const safeSubject = sanitizeHeader(`Order Confirmation — ${opts.orderNumber}`)
  const mailOptions: SendMailOptions = {
    from: `"${safeFromName}" <${safeFromEmail}>`,
    to: safeTo,
    subject: safeSubject,
    text,
    html,
  }

  if (logoBuffer) {
    mailOptions.attachments = [{
      filename: 'nixe-logo.png',
      content: logoBuffer,
      cid: 'nixelogo',
      encoding: 'base64',
    }]
  }

  await transport.sendMail(mailOptions)

  return true
}

/**
 * Send a contact form submission email to the NIXE team.
 * The message is sent to both approved NIXE inboxes: support@nixe.pk and
 * metamehar@outlook.com.
 *
 * The email body is formatted as a table (rows/columns) so it's easy
 * to review every field at a glance. For job applications, extra
 * fields (qualification, experience, etc.) are included as rows.
 *
 * fix-3b-api Fix 4: `replyTo` is now an explicit field. Callers that
 * want a non-default Reply-To (e.g. anonymous contact → support@nixe.pk)
 * can set opts.replyTo; otherwise it defaults to opts.email for
 * backwards compatibility.
 */
export async function sendContactEmail(opts: Record<string, string>): Promise<boolean> {
  const transport = getTransporter()
  if (!transport) {
    throw new Error('Email service not configured. Add EMAIL_USER and EMAIL_PASS to .env')
  }

  const to = opts.to || 'support@nixe.pk, metamehar@outlook.com'
  // fix-3b-api Fix 4: explicit replyTo override (defaults to opts.email
  // for back-compat with existing callers).
  const replyTo = opts.replyTo || opts.email
  const logoBuffer = getLogoBuffer()
  const isJobApplication = opts.isJobApplication === 'true'

  // Define the field order for the table. Only fields that have a value
  // are rendered (so the table isn't full of empty rows).
  const fieldLabels: [string, string][] = [
    ['name', 'Name'],
    ['email', 'Email'],
    ['phone', 'Phone'],
    ['jobTitle', 'Position Applied For'],
    ['jobTeam', 'Team'],
    ['jobLocation', 'Job Location'],
    ['jobType', 'Employment Type'],
    ['jobDescription', 'Job Description'],
    ['qualification', 'Highest Qualification'],
    ['experience', 'Years of Experience'],
    ['currentLocation', 'Current Location'],
    ['currentCompany', 'Current Company'],
    ['expectedSalary', 'Expected Salary'],
    ['noticePeriod', 'Notice Period'],
    ['portfolioUrl', 'Portfolio URL'],
    ['subject', 'Subject'],
  ]

  // Build table rows (only for fields that have a value).
  const rows = fieldLabels
    .filter(([key]) => opts[key] && opts[key].trim())
    .map(([key, label]) => {
      const value = opts[key]
      const isLink = key === 'email' || key === 'portfolioUrl'
      // RA5-LIB-005 fix: validate the URL scheme for portfolioUrl before
      // rendering as a clickable link. `escapeHtml` escapes `&`, `<`, `>`,
      // `"`, `'` but does NOT block dangerous URL schemes like `javascript:`,
      // `data:`, or `vbscript:`. A malicious portfolioUrl like
      // `javascript:alert(document.cookie)` would render as a clickable link
      // in the email body — modern email clients strip these, but older /
      // less-secure clients may execute them. Render non-http(s) URLs as
      // `href="#"` (non-clickable) so no scheme can ever execute.
      const safeHref =
        key === 'email'
          ? `mailto:${value}`
          : key === 'portfolioUrl' && (value.startsWith('http://') || value.startsWith('https://'))
            ? value
            : '#'
      const displayValue = isLink
        ? `<a href="${escapeHtml(safeHref)}" style="color:#0073bb;text-decoration:none;">${escapeHtml(value)}</a>`
        : escapeHtml(value)
      return `
        <tr>
          <td style="padding:10px 16px;background:#f7f7f7;border:1px solid #e5e5e5;font-size:13px;font-weight:600;color:#555;width:180px;vertical-align:top;">${escapeHtml(label)}</td>
          <td style="padding:10px 16px;background:#ffffff;border:1px solid #e5e5e5;font-size:14px;color:#14110c;vertical-align:top;">${displayValue}</td>
        </tr>
      `
    })
    .join('')

  const subtitleText = isJobApplication ? 'New job application' : 'New contact form submission'
  const emailSubjectPrefix = isJobApplication ? '[Job Application]' : '[Contact]'

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background:#f3f3f3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f3f3f3;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="620" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
          <!-- Header with NIXE logo -->
          <tr>
            <td style="background:#14110c;padding:28px 40px;text-align:center;">
              ${logoBuffer
                ? `<img src="cid:nixelogo" alt="NIXE" width="120" style="display:block;margin:0 auto;" />`
                : '<h1 style="margin:0;color:#ffffff;font-size:28px;font-weight:900;letter-spacing:-1px;">NIXE</h1>'
              }
              <p style="margin:8px 0 0;color:#999;font-size:13px;">${escapeHtml(subtitleText)}</p>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td style="padding:36px 40px;">
              <h2 style="margin:0 0 20px;color:#14110c;font-size:20px;font-weight:700;">${escapeHtml(opts.subject || (isJobApplication ? 'Job Application' : 'Contact Form'))}</h2>

              <!-- Details table (rows + columns) -->
              <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin-bottom:24px;">
                <tr>
                  <td colspan="2" style="padding:8px 16px;background:#14110c;color:#fff;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;">Applicant Details</td>
                </tr>
                ${rows}
              </table>

              <!-- Message / Cover Letter -->
              <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin-bottom:24px;">
                <tr>
                  <td style="padding:8px 16px;background:#14110c;color:#fff;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;">${isJobApplication ? 'Cover Letter / Message' : 'Message'}</td>
                </tr>
                <tr>
                  <td style="padding:16px;background:#f7f7f7;border:1px solid #e5e5e5;">
                    <p style="margin:0;color:#333;font-size:14px;line-height:1.7;white-space:pre-wrap;">${escapeHtml(opts.message || '')}</p>
                  </td>
                </tr>
              </table>

              <p style="margin:24px 0 0;color:#999;font-size:13px;">
                Reply directly to this person at <a href="mailto:${escapeHtml(opts.email || '')}" style="color:#0073bb;">${escapeHtml(opts.email || '')}</a>.
              </p>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="background:#14110c;padding:24px 40px;text-align:center;">
              <p style="margin:0;color:#888;font-size:12px;">
                &copy; ${new Date().getFullYear()} NIXE, Inc. &middot; ${escapeHtml(subtitleText)}
              </p>
              <p style="margin:4px 0 0;color:#666;font-size:11px;">
                <a href="${BASE_URL}" style="color:#666;text-decoration:none;">${BASE_URL}</a>
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `.trim()

  // Plain-text version (for email clients that don't render HTML).
  const textLines: string[] = []
  textLines.push(`NIXE — ${subtitleText}`)
  textLines.push('')
  for (const [key, label] of fieldLabels) {
    if (opts[key] && opts[key].trim()) {
      textLines.push(`${label}: ${opts[key]}`)
    }
  }
  textLines.push('')
  textLines.push(`${isJobApplication ? 'Cover Letter / Message' : 'Message'}:`)
  textLines.push(opts.message || '')
  textLines.push('')
  textLines.push(`Reply to: ${opts.email || ''}`)
  const text = textLines.join('\n')

  // fix-critical-security #16: sanitize ALL user-supplied header values to
  // prevent email header injection (CRLF → Bcc/Subject spoofing).
  //   - `to` may come from opts.to (defaults to a hardcoded address, but if
  //     a caller passes a user-supplied value we must sanitize it).
  //   - `replyTo` is opts.replyTo || opts.email — fully user-supplied.
  //   - `subject` is built from opts.subject — user-supplied.
  //   - `from` is env-derived; sanitized for defense-in-depth.
  const safeFromName = sanitizeHeader(FROM_NAME)
  const safeFromEmail = sanitizeHeader(FROM_EMAIL)
  const safeTo = sanitizeHeader(to)
  const safeReplyTo = sanitizeHeader(replyTo)
  const safeSubject = sanitizeHeader(`${emailSubjectPrefix} ${opts.subject || ''}`.trim())
  const mailOptions: SendMailOptions = {
    from: `"${safeFromName}" <${safeFromEmail}>`,
    to: safeTo,
    replyTo: safeReplyTo,
    subject: safeSubject,
    text,
    html,
  }

  if (logoBuffer) {
    mailOptions.attachments = [{
      filename: 'nixe-logo.png',
      content: logoBuffer,
      cid: 'nixelogo',
      encoding: 'base64',
    }]
  }

  await transport.sendMail(mailOptions)
  return true
}

/**
 * Send a seller verification request to the fixed NIXE review inbox.
 *
 * Sensitive identity fields are intentionally never written to Prisma by the
 * seller signup route. They are sent only in this operator-controlled email.
 * The recipient mailbox will retain the message according to its own policy.
 */
export async function sendSellerVerificationEmail(opts: {
  accountEmail: string
  storeName: string
  application: ValidatedSellerApplication
}): Promise<boolean> {
  const transport = getTransporter()
  if (!transport) {
    throw new Error('Email service not configured. Add EMAIL_USER and EMAIL_PASS to .env')
  }

  const recipient = 'support@nixe.pk'
  const logoBuffer = getLogoBuffer()
  const { application } = opts
  const dateOfBirth = application.dateOfBirth.toISOString().slice(0, 10)
  const fields: Array<[string, string]> = [
    ['Account email', opts.accountEmail],
    ['Store name', opts.storeName],
    ['Legal first name', application.firstName],
    ['Legal last name', application.lastName],
    ['CNIC', application.cnic],
    ['Date of birth', dateOfBirth],
    ['Phone', application.phone],
    ['WhatsApp', application.whatsappPhone],
    ['City', application.city],
    ['Province / territory', application.province],
    ['Shop address', application.shopAddress],
    ['Postal code', application.postalCode],
    ['Business category', application.businessCategory],
  ]
  const rows = fields.map(([label, value]) => `
    <tr>
      <td style="padding:10px 14px;border:1px solid #e5e7eb;color:#6b7280;font-size:13px;width:34%;vertical-align:top;">${escapeHtml(label)}</td>
      <td style="padding:10px 14px;border:1px solid #e5e7eb;color:#111827;font-size:14px;word-break:break-word;">${escapeHtml(value)}</td>
    </tr>`).join('')
  const subject = `[NIXE Seller Review] ${opts.storeName}`
  const html = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f3f3f3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f3f3f3;padding:32px 16px;">
    <tr><td align="center">
      <table width="680" cellpadding="0" cellspacing="0" style="max-width:680px;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
        <tr><td style="background:#14110c;padding:26px 32px;text-align:center;">
          ${logoBuffer ? `<img src="cid:nixelogo" alt="NIXE" width="120" style="display:block;margin:0 auto;" />` : '<h1 style="margin:0;color:#fff;font-size:28px;font-weight:900;">NIXE</h1>'}
          <p style="margin:8px 0 0;color:#fbbf24;font-size:13px;">Seller verification request</p>
        </td></tr>
        <tr><td style="padding:30px 32px;">
          <h2 style="margin:0 0 8px;color:#14110c;font-size:21px;">New seller request</h2>
          <p style="margin:0 0 22px;color:#4b5563;font-size:14px;line-height:1.6;">The applicant verified their email address and submitted the following details for manual review. This message contains sensitive identity information; handle it securely and do not forward it unnecessarily.</p>
          <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">${rows}</table>
          <p style="margin:22px 0 0;color:#6b7280;font-size:13px;line-height:1.6;">Review the applicant directly, then approve or keep the pending seller account from the NIXE admin seller panel. This request was not saved as a seller-application record in the NIXE database.</p>
        </td></tr>
        <tr><td style="background:#14110c;padding:20px 32px;text-align:center;color:#9ca3af;font-size:12px;">NIXE private seller review &middot; ${new Date().getFullYear()}</td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`.trim()
  const text = [
    'NIXE — Seller verification request',
    '',
    'The applicant verified their email address and submitted these details for manual review.',
    '',
    ...fields.map(([label, value]) => `${label}: ${value}`),
    '',
    'Sensitive identity information: handle securely and do not forward unnecessarily.',
    'This request was not saved as a seller-application record in the NIXE database.',
    // 2026-09-09 audit fix (L11): join with a real newline. The previous
    // '\\n' was an escaped backslash, so the plain-text email rendered as one
    // long line with literal "\n" between fields.
  ].join('\n')

  const safeFromName = sanitizeHeader(FROM_NAME)
  const safeFromEmail = sanitizeHeader(FROM_EMAIL)
  const safeTo = sanitizeHeader(recipient)
  const safeReplyTo = sanitizeHeader(opts.accountEmail)
  const safeSubject = sanitizeHeader(subject)
  const mailOptions: SendMailOptions = {
    from: `"${safeFromName}" <${safeFromEmail}>`,
    to: safeTo,
    replyTo: safeReplyTo,
    subject: safeSubject,
    text,
    html,
  }
  if (logoBuffer) {
    mailOptions.attachments = [{
      filename: 'nixe-logo.png',
      content: logoBuffer,
      cid: 'nixelogo',
      encoding: 'base64',
    }]
  }

  await transport.sendMail(mailOptions)
  return true
}

/**
 * Send a job application notification email with resume attachment.
 */
export async function sendJobApplicationEmail(opts: {
  to?: string
  jobTitle: string
  name: string
  email: string
  phone?: string
  coverLetter?: string
  resumeBuffer: Buffer
  resumeFilename: string
  resumeMimetype: string
}): Promise<boolean> {
  const transport = getTransporter()
  if (!transport) {
    throw new Error('Email service not configured. Add EMAIL_USER and EMAIL_PASS to .env')
  }

  const to = opts.to || 'metamehar@outlook.com'
  const logoBuffer = getLogoBuffer()

  const html = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f3f3f3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f3f3f3;padding:40px 20px;">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
        <tr><td style="background:#14110c;padding:28px 40px;text-align:center;">
          ${logoBuffer ? `<img src="cid:nixelogo" alt="NIXE" width="120" style="display:block;margin:0 auto;" />` : '<h1 style="margin:0;color:#fff;font-size:28px;font-weight:900;">NIXE</h1>'}
          <p style="margin:8px 0 0;color:#999;font-size:13px;">New job application</p>
        </td></tr>
        <tr><td style="padding:36px 40px;">
          <h2 style="margin:0 0 8px;color:#14110c;font-size:20px;font-weight:700;">Application: ${escapeHtml(opts.jobTitle)}</h2>
          <table width="100%" cellpadding="0" cellspacing="0" style="margin:16px 0;">
            <tr><td style="padding:4px 0;color:#999;font-size:13px;width:80px;">Name:</td><td style="padding:4px 0;color:#14110c;font-size:14px;font-weight:600;">${escapeHtml(opts.name)}</td></tr>
            <tr><td style="padding:4px 0;color:#999;font-size:13px;">Email:</td><td style="padding:4px 0;color:#14110c;font-size:14px;"><a href="mailto:${escapeHtml(opts.email)}" style="color:#0073bb;text-decoration:none;">${escapeHtml(opts.email)}</a></td></tr>
            ${opts.phone ? `<tr><td style="padding:4px 0;color:#999;font-size:13px;">Phone:</td><td style="padding:4px 0;color:#14110c;font-size:14px;">${escapeHtml(opts.phone)}</td></tr>` : ''}
          </table>
          ${opts.coverLetter ? `<div style="background:#f7f7f7;border-radius:8px;padding:20px;margin:16px 0;"><p style="margin:0 0 8px;color:#999;font-size:12px;text-transform:uppercase;letter-spacing:0.5px;">Cover Letter</p><p style="margin:0;color:#333;font-size:14px;line-height:1.7;white-space:pre-wrap;">${escapeHtml(opts.coverLetter)}</p></div>` : ''}
          <p style="margin:24px 0 0;color:#999;font-size:13px;">The resume is attached to this email as <strong>${escapeHtml(opts.resumeFilename)}</strong>.</p>
        </td></tr>
        <tr><td style="background:#14110c;padding:24px 40px;text-align:center;">
          <p style="margin:0;color:#888;font-size:12px;">&copy; ${new Date().getFullYear()} NIXE, Inc. &middot; Job application notification</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
  `.trim()

  const text = `NIXE — Job Application\n\nPosition: ${opts.jobTitle}\nName: ${opts.name}\nEmail: ${opts.email}\nPhone: ${opts.phone || 'N/A'}\n\nCover Letter:\n${opts.coverLetter || 'N/A'}\n\nResume: ${opts.resumeFilename} (attached)`

  // fix-critical-security #16: sanitize ALL user-supplied header values to
  // prevent email header injection (CRLF → Bcc/Subject spoofing).
  //   - `to` may come from opts.to (defaults to a hardcoded address).
  //   - `replyTo` is opts.email — fully user-supplied.
  //   - `subject` is built from opts.jobTitle + opts.name — user-supplied.
  //   - `from` is env-derived; sanitized for defense-in-depth.
  //   - `resumeFilename` is sanitized too (nodemailer uses it in the
  //     Content-Disposition header of the attachment — same injection
  //     vector).
  const safeFromName = sanitizeHeader(FROM_NAME)
  const safeFromEmail = sanitizeHeader(FROM_EMAIL)
  const safeTo = sanitizeHeader(to)
  const safeReplyTo = sanitizeHeader(opts.email)
  const safeSubject = sanitizeHeader(`[Job Application] ${opts.jobTitle} — ${opts.name}`)
  // BUG 85 fix (audit4): sanitize the resume filename more aggressively.
  // sanitizeHeader only strips CRLF (prevents header injection). But the
  // filename is also used as the attachment's Content-Disposition filename,
  // which email clients may use to save the file. Path traversal sequences
  // (../) or special chars could cause issues. Use basename + replace
  // non-alphanumeric chars (except . _ -) with underscores.
  const safeFilename = sanitizeHeader(
    path.basename(opts.resumeFilename).replace(/[^a-zA-Z0-9._-]/g, '_')
  )
  const mailOptions: SendMailOptions = {
    from: `"${safeFromName}" <${safeFromEmail}>`,
    to: safeTo,
    replyTo: safeReplyTo,
    subject: safeSubject,
    text,
    html,
    attachments: [{
      filename: safeFilename,
      content: opts.resumeBuffer,
      contentType: opts.resumeMimetype,
    }],
  }

  if (logoBuffer) {
    const attachments = mailOptions.attachments ?? []
    attachments.unshift({
      filename: 'nixe-logo.png',
      content: logoBuffer,
      cid: 'nixelogo',
      encoding: 'base64',
    })
    mailOptions.attachments = attachments
  }

  await transport.sendMail(mailOptions)
  return true
}

function escapeHtml(s: string): string {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}
