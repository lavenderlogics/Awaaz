"use client";

import { ArrowRight, Eye, EyeOff, KeyRound } from "lucide-react";
import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";
import { Button, LinkButton } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { FormField, Input } from "@/components/ui/FormField";
import { StatusNotice } from "@/components/ui/StatusNotice";
import { createClient } from "@/lib/supabase/client";

interface ResetPasswordFormProps {
  hasActiveSession: boolean;
  userEmail: string | null;
}

/** Allows an authenticated/recovery-verified user to update their password. */
export function ResetPasswordForm({
  hasActiveSession,
  userEmail,
}: ResetPasswordFormProps) {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [updated, setUpdated] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!hasActiveSession) {
      setError(
        "Your recovery session is missing or expired. Request a new password reset email from Committee Login."
      );
      return;
    }

    if (password.length < 8) {
      setError("New password must be at least 8 characters long.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setError("");
    setIsSubmitting(true);

    try {
      const supabase = createClient();
      const { error: updateError } = await supabase.auth.updateUser({
        password,
      });

      if (updateError) {
        setError(updateError.message);
        return;
      }

      setUpdated(true);
      setPassword("");
      setConfirmPassword("");
      router.refresh();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to update password."
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Card className="mx-auto max-w-md">
      <CardHeader className="border-b border-slate-100">
        <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-xl bg-navy-900 text-white">
          <KeyRound className="h-5 w-5" />
        </div>
        <CardTitle>Set New Password</CardTitle>
        <p className="mt-1 text-sm text-slate-600">
          {userEmail
            ? `Updating password for ${userEmail}.`
            : "Open the recovery link sent to your email before updating your password."}
        </p>
      </CardHeader>

      <CardContent className="pt-6">
        {!hasActiveSession ? (
          <div className="space-y-4">
            <StatusNotice title="Recovery Link Required" variant="warning">
              No active recovery session was found. Request a fresh password
              reset link from the Committee Login page.
            </StatusNotice>
            <LinkButton
              href="/committee/login"
              variant="primary"
              size="md"
              className="w-full"
            >
              Back to Committee Login
            </LinkButton>
          </div>
        ) : updated ? (
          <div className="space-y-4">
            <StatusNotice title="Password Updated" variant="success">
              Your committee account password has been updated. You can now
              continue to the dashboard.
            </StatusNotice>
            <LinkButton
              href="/committee/dashboard"
              variant="primary"
              size="md"
              className="w-full"
            >
              Go to Committee Dashboard
              <ArrowRight className="h-4 w-4" />
            </LinkButton>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-5" noValidate>
            <FormField
              id="newPassword"
              label="New Password"
              hint="Minimum 8 characters."
              required
            >
              <div className="relative">
                <Input
                  id="newPassword"
                  type={showPassword ? "text" : "password"}
                  autoComplete="new-password"
                  placeholder="Enter new password"
                  className="pr-10"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={isSubmitting}
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

            <FormField
              id="confirmNewPassword"
              label="Confirm New Password"
              required
            >
              <Input
                id="confirmNewPassword"
                type={showPassword ? "text" : "password"}
                autoComplete="new-password"
                placeholder="Re-enter new password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                disabled={isSubmitting}
              />
            </FormField>

            {error ? (
              <StatusNotice title="Update Failed" variant="warning">
                {error}
              </StatusNotice>
            ) : null}

            <Button
              type="submit"
              variant="primary"
              size="lg"
              className="w-full"
              disabled={isSubmitting}
            >
              {isSubmitting ? "Updating Password..." : "Update Password"}
            </Button>
          </form>
        )}
      </CardContent>
    </Card>
  );
}
