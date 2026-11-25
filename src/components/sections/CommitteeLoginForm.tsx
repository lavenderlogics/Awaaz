"use client";

import { ArrowRight, Eye, EyeOff, Lock, Mail, UserPlus } from "lucide-react";
import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";
import { Button, LinkButton } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { FormField, Input } from "@/components/ui/FormField";
import { StatusNotice } from "@/components/ui/StatusNotice";
import { createClient } from "@/lib/supabase/client";

type AuthMode = "signin" | "signup";

interface CommitteeLoginFormProps {
  isConfigured: boolean;
}

/** Committee authentication card supporting Sign In and Sign Up with email verification. */
export function CommitteeLoginForm({ isConfigured }: CommitteeLoginFormProps) {
  const router = useRouter();
  const [mode, setMode] = useState<AuthMode>("signin");
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isResending, setIsResending] = useState(false);
  const [error, setError] = useState("");
  const [verificationSentTo, setVerificationSentTo] = useState<string | null>(
    null
  );
  const [resendMessage, setResendMessage] = useState("");

  const switchMode = (nextMode: AuthMode) => {
    setMode(nextMode);
    setError("");
    setResendMessage("");
    setVerificationSentTo(null);
  };

  const getCallbackUrl = () =>
    `${window.location.origin}/auth/callback?next=/committee/dashboard`;

  const handleResendVerification = async (targetEmail: string) => {
    if (!isConfigured || !targetEmail.trim()) return;
    setIsResending(true);
    setResendMessage("");
    setError("");

    try {
      const supabase = createClient();
      const { error: resendError } = await supabase.auth.resend({
        type: "signup",
        email: targetEmail.trim(),
        options: {
          emailRedirectTo: getCallbackUrl(),
        },
      });

      if (resendError) {
        setError(resendError.message);
        return;
      }

      setResendMessage(`Verification email resent to ${targetEmail.trim()}.`);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to resend verification email."
      );
    } finally {
      setIsResending(false);
    }
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!isConfigured) {
      setError(
        "Supabase environment variables are not configured in this deployment."
      );
      return;
    }

    const trimmedEmail = email.trim();
    if (!trimmedEmail || !password) {
      setError("Please enter both an institutional email and password.");
      return;
    }

    setError("");
    setResendMessage("");
    setVerificationSentTo(null);

    if (mode === "signup") {
      if (!fullName.trim()) {
        setError("Please enter your full name.");
        return;
      }
      if (password.length < 8) {
        setError("Password must be at least 8 characters long.");
        return;
      }
      if (password !== confirmPassword) {
        setError("Passwords do not match.");
        return;
      }
    }

    setIsSubmitting(true);

    try {
      const supabase = createClient();

      if (mode === "signin") {
        const { error: authError } = await supabase.auth.signInWithPassword({
          email: trimmedEmail,
          password,
        });

        if (authError) {
          setError(authError.message);
          return;
        }

        router.push("/committee/dashboard");
        router.refresh();
        return;
      }

      const { data, error: signUpError } = await supabase.auth.signUp({
        email: trimmedEmail,
        password,
        options: {
          emailRedirectTo: getCallbackUrl(),
          data: {
            full_name: fullName.trim(),
          },
        },
      });

      if (signUpError) {
        setError(signUpError.message);
        return;
      }

      if (
        data.user &&
        Array.isArray(data.user.identities) &&
        data.user.identities.length === 0
      ) {
        setError(
          "An account with this email already exists. Please sign in instead."
        );
        return;
      }

      if (data.session) {
        router.push("/committee/dashboard");
        router.refresh();
        return;
      }

      setVerificationSentTo(trimmedEmail);
      setPassword("");
      setConfirmPassword("");
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to connect to Supabase authentication."
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const showResendInSignInError =
    mode === "signin" && error.toLowerCase().includes("email not confirmed");

  return (
    <Card className="mx-auto max-w-md">
      <CardHeader className="border-b border-slate-100">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-navy-900 text-white">
            {mode === "signin" ? (
              <Lock className="h-5 w-5" />
            ) : (
              <UserPlus className="h-5 w-5" />
            )}
          </div>

          <div
            role="tablist"
            aria-label="Authentication mode"
            className="inline-flex rounded-xl border border-slate-200 bg-slate-50 p-1"
          >
            <button
              type="button"
              role="tab"
              aria-selected={mode === "signin"}
              onClick={() => switchMode("signin")}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                mode === "signin"
                  ? "bg-white text-navy-950 shadow-2xs"
                  : "text-slate-600 hover:text-navy-900"
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === "signup"}
              onClick={() => switchMode("signup")}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                mode === "signup"
                  ? "bg-white text-navy-950 shadow-2xs"
                  : "text-slate-600 hover:text-navy-900"
              }`}
            >
              Sign Up
            </button>
          </div>
        </div>

        <CardTitle>
          {mode === "signin"
            ? "Committee Member Sign In"
            : "Create Committee Account"}
        </CardTitle>
        <p className="mt-1 text-sm text-slate-600">
          {mode === "signin"
            ? "Restricted access for Anti-Ragging & Internal Complaints Committee officers."
            : "Register with your institutional email. A verification link will be sent to your inbox."}
        </p>
      </CardHeader>

      <CardContent className="pt-6">
        <form onSubmit={handleSubmit} className="space-y-5" noValidate>
          {mode === "signup" ? (
            <FormField id="committeeName" label="Full Name" required>
              <Input
                id="committeeName"
                type="text"
                autoComplete="name"
                placeholder="Dr. Ananya Sharma"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                disabled={isSubmitting || !isConfigured}
              />
            </FormField>
          ) : null}

          <FormField id="committeeEmail" label="Institutional Email" required>
            <Input
              id="committeeEmail"
              type="email"
              autoComplete="email"
              placeholder="committee@college.edu"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={isSubmitting || !isConfigured}
            />
          </FormField>

          <FormField
            id="committeePassword"
            label="Password"
            hint={mode === "signup" ? "Minimum 8 characters." : undefined}
            required
          >
            <div className="relative">
              <Input
                id="committeePassword"
                type={showPassword ? "text" : "password"}
                autoComplete={
                  mode === "signin" ? "current-password" : "new-password"
                }
                placeholder="Enter password"
                className="pr-10"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={isSubmitting || !isConfigured}
              />
              <button
                type="button"
                onClick={() => setShowPassword((prev) => !prev)}
                className="absolute inset-y-0 right-0 flex items-center px-3 text-slate-500 hover:text-navy-900"
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? (
                  <EyeOff className="h-4 w-4" />
                ) : (
                  <Eye className="h-4 w-4" />
                )}
              </button>
            </div>
          </FormField>

          {mode === "signup" ? (
            <FormField
              id="committeeConfirmPassword"
              label="Confirm Password"
              required
            >
              <Input
                id="committeeConfirmPassword"
                type={showPassword ? "text" : "password"}
                autoComplete="new-password"
                placeholder="Re-enter password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                disabled={isSubmitting || !isConfigured}
              />
            </FormField>
          ) : null}

          {verificationSentTo ? (
            <StatusNotice title="Verification Email Sent" variant="success">
              <p>
                We sent an authentication link to{" "}
                <strong>{verificationSentTo}</strong>. Open that email (check
                spam/promotions if needed) and click the verification link to
                activate your account.
              </p>
              <div className="mt-3">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={isResending}
                  onClick={() => handleResendVerification(verificationSentTo)}
                >
                  <Mail className="h-3.5 w-3.5" />
                  {isResending ? "Resending..." : "Resend Verification Email"}
                </Button>
              </div>
            </StatusNotice>
          ) : null}

          {resendMessage ? (
            <StatusNotice title="Email Resent" variant="info">
              {resendMessage}
            </StatusNotice>
          ) : null}

          {error ? (
            <StatusNotice
              title={mode === "signin" ? "Sign-In Failed" : "Sign-Up Failed"}
              variant="warning"
            >
              <p>{error}</p>
              {showResendInSignInError ? (
                <div className="mt-3">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={isResending}
                    onClick={() => handleResendVerification(email)}
                  >
                    <Mail className="h-3.5 w-3.5" />
                    {isResending ? "Resending..." : "Resend Verification Email"}
                  </Button>
                </div>
              ) : null}
            </StatusNotice>
          ) : null}

          <div className="space-y-3 pt-1">
            <Button
              type="submit"
              variant="primary"
              size="lg"
              className="w-full"
              disabled={isSubmitting || !isConfigured}
            >
              {isSubmitting
                ? mode === "signin"
                  ? "Signing In..."
                  : "Creating Account..."
                : mode === "signin"
                  ? "Sign In"
                  : "Create Account & Send Verification"}
            </Button>
            <LinkButton
              href="/committee/dashboard"
              variant="outline"
              size="md"
              className="w-full"
            >
              View Dashboard Workspace
              <ArrowRight className="h-4 w-4" />
            </LinkButton>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
