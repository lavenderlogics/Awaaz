"use client";

import { ArrowRight, Eye, EyeOff, Lock } from "lucide-react";
import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";
import { Button, LinkButton } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { FormField, Input } from "@/components/ui/FormField";
import { StatusNotice } from "@/components/ui/StatusNotice";
import { createClient } from "@/lib/supabase/client";

/** Committee sign-in form wired to Supabase Auth. */
export function CommitteeLoginForm() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmedEmail = email.trim();

    if (!trimmedEmail || !password) {
      setError("Please enter both an institutional email and password.");
      return;
    }

    setError("");
    setIsSubmitting(true);

    try {
      const supabase = createClient();
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

  return (
    <Card className="mx-auto max-w-md">
      <CardHeader className="border-b border-slate-100">
        <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-xl bg-navy-900 text-white">
          <Lock className="h-5 w-5" />
        </div>
        <CardTitle>Committee Member Sign In</CardTitle>
        <p className="mt-1 text-sm text-slate-600">
          Restricted access for Anti-Ragging &amp; Internal Complaints Committee
          officers.
        </p>
      </CardHeader>
      <CardContent className="pt-6">
        <form onSubmit={handleSubmit} className="space-y-5" noValidate>
          <FormField id="committeeEmail" label="Institutional Email" required>
            <Input
              id="committeeEmail"
              type="email"
              autoComplete="email"
              placeholder="committee@college.edu"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={isSubmitting}
            />
          </FormField>

          <FormField id="committeePassword" label="Password" required>
            <div className="relative">
              <Input
                id="committeePassword"
                type={showPassword ? "text" : "password"}
                autoComplete="current-password"
                placeholder="Enter password"
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

          {error ? (
            <StatusNotice title="Sign-In Failed" variant="warning">
              {error}
            </StatusNotice>
          ) : null}

          <div className="space-y-3 pt-1">
            <Button
              type="submit"
              variant="primary"
              size="lg"
              className="w-full"
              disabled={isSubmitting}
            >
              {isSubmitting ? "Signing In..." : "Sign In"}
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
