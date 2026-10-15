"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, KeyRound, Loader2, Mail, RotateCcw } from "lucide-react";
import { AuthShell } from "@/components/auth-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useNixe } from "@/lib/store";

export function ForgotPasswordClient() {
  const pushToast = useNixe((s) => s.pushToast);

  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [otpCode, setOtpCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /* Audit-14 fix (14-b #9): mirror signup's R6-B5 cooldown. Resend had no
   * busy state and no cooldown — a double-click fired two OTP sends (each
   * new code marks prior unused codes used, burning 2 of the 3-per-10-min
   * budget), and Resend stayed enabled while the reset POST was in flight
   * so a mid-verify resend guaranteed "Invalid or expired code". */
  const [sendingCode, setSendingCode] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);

  useEffect(() => {
    if (resendCooldown <= 0) return;
    const t = setInterval(() => setResendCooldown((s) => s - 1), 1000);
    return () => clearInterval(t);
  }, [resendCooldown]);

  const sendResetCode = async (isResend = false) => {
    if (sendingCode) return;
    setSendingCode(true);
    try {
      const res = await fetch("/api/auth/otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ action: "send", type: "reset", email }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setSent(true);
        setError(null);
        setResendCooldown(60);
        pushToast({
          title: isResend ? "Reset code resent" : "Reset code sent",
          description: `Check ${email || "your inbox"} for the 6-digit code.`,
          variant: "success",
        });
      } else {
        setError((data as { error?: string }).error || "Couldn't send the reset code.");
      }
    } catch {
      setError("Network hiccup — please try again.");
    } finally {
      setSendingCode(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (submitting) return;
    setError(null);
    setSubmitting(true);
    try {
      if (!sent) {
        await sendResetCode();
        return;
      }
      const res = await fetch("/api/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ action: "reset-password", email, otpCode, newPassword }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        pushToast({
          title: "Password reset",
          description: "Sign in with your new password.",
          variant: "success",
        });
        window.location.href = "/login";
      } else {
        setError((data as { error?: string }).error || "Couldn't reset your password.");
      }
    } catch {
      setError("Network hiccup — please try again.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell
      title="Reset your password"
      subtitle={
        sent
          ? undefined
          : "Enter the email tied to your account and we'll email you a 6-digit reset code."
      }
    >
      {sent ? (
        <div className="animate-fade-up flex flex-col items-center rounded-2xl border border-border bg-card p-8 text-center">
          <span className="flex size-16 items-center justify-center rounded-full bg-success/10">
            <Mail className="size-7 text-success" />
          </span>
          <h2 className="mt-5 text-xl font-bold tracking-tight">
            Check your inbox
          </h2>
          <p className="mt-2 max-w-xs text-sm text-muted-foreground">
            If an account exists for{" "}
            <span className="font-semibold text-foreground">
              {email || "your email"}
            </span>
            , a 6-digit reset code is on its way. It expires in 10 minutes.
          </p>
          <p className="mt-2 max-w-xs text-xs text-muted-foreground">
            No email after a few minutes? Check your spam folder, request a new
            code below, or start over with the correct address.
          </p>
          <form onSubmit={handleSubmit} className="mt-6 w-full space-y-4 text-left">
            <div className="space-y-2">
              <Label htmlFor="reset-code">Reset code</Label>
              <Input
                id="reset-code"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="6-digit code"
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value)}
                className="focus-ring h-11 rounded-xl tracking-[0.3em]"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="new-password">New password</Label>
              <div className="relative">
                <KeyRound className="absolute top-1/2 left-3.5 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="new-password"
                  type="password"
                  autoComplete="new-password"
                  placeholder="8+ chars, number & symbol"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="focus-ring h-11 rounded-xl pl-10"
                  required
                />
              </div>
            </div>
            {error && (
              <p className="rounded-xl bg-destructive/10 px-4 py-3 text-sm font-medium text-destructive">
                {error}
              </p>
            )}
            <Button
              type="submit"
              disabled={submitting}
              className="h-11 w-full rounded-full text-sm font-semibold"
            >
              {submitting ? (
                <>
                  <Loader2 className="size-4 animate-spin" />
                  Resetting…
                </>
              ) : (
                "Reset password"
              )}
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={() => void sendResetCode(true)}
              disabled={sendingCode || submitting || resendCooldown > 0}
              className="h-11 w-full rounded-full"
            >
              {sendingCode ? (
                <>
                  <Loader2 className="size-4 animate-spin" />
                  Sending…
                </>
              ) : resendCooldown > 0 ? (
                <>
                  <RotateCcw className="size-4" />
                  Resend available in {resendCooldown}s
                </>
              ) : (
                <>
                  <RotateCcw className="size-4" />
                  Resend code
                </>
              )}
            </Button>
          </form>
          <Button
            type="button"
            variant="link"
            onClick={() => {
              setSent(false);
              setOtpCode("");
              setNewPassword("");
              setError(null);
            }}
            className="mt-2 h-auto p-0 text-xs text-muted-foreground hover:text-foreground"
          >
            Not your email? Start over
          </Button>
          <Link
            href="/login"
            className="mt-4 inline-flex items-center gap-1.5 text-sm font-medium text-primary hover:underline"
          >
            <ArrowLeft className="size-3.5" />
            Back to sign in
          </Link>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-5">
          <div className="space-y-2">
            <Label htmlFor="reset-email">Email address</Label>
            <div className="relative">
              <Mail className="absolute top-1/2 left-3.5 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                id="reset-email"
                type="email"
                autoComplete="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="focus-ring h-11 rounded-xl pl-10"
                required
              />
            </div>
          </div>

          <div className="flex items-start gap-3 rounded-xl bg-secondary/60 p-4 text-sm text-secondary-foreground">
            <KeyRound className="mt-0.5 size-4 shrink-0" />
            <p>
              Tip: use at least 8 characters with a mix of letters, numbers and
              symbols to keep your account safe.
            </p>
          </div>

          <Button
            type="submit"
            disabled={submitting}
            className="h-11 w-full rounded-full text-sm font-semibold"
          >
            {submitting ? (
              <>
                <Loader2 className="size-4 animate-spin" />
                Sending…
              </>
            ) : (
              <>
                <Mail className="size-4" />
                Send reset code
              </>
            )}
          </Button>

          <Link
            href="/login"
            className="flex items-center justify-center gap-1.5 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
          >
            <ArrowLeft className="size-3.5" />
            Back to sign in
          </Link>
        </form>
      )}
    </AuthShell>
  );
}
