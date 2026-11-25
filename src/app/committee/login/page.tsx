import type { Metadata } from "next";
import { Shield } from "lucide-react";
import { CommitteeLoginForm } from "@/components/sections/CommitteeLoginForm";
import { LinkButton } from "@/components/ui/Button";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatusNotice } from "@/components/ui/StatusNotice";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = {
  title: "Committee Login",
  description:
    "Sign-in portal for authorized campus anti-ragging and harassment committee members.",
};

export default async function CommitteeLoginPage() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  return (
    <div>
      <PageHeader
        eyebrow="Authorized Access"
        title="Committee Portal Sign In"
        description="Dedicated access point for institutional anti-ragging and internal complaints committee members."
        badgeText="Supabase Auth Connected"
      />

      <section className="mx-auto max-w-4xl px-4 py-12 sm:px-6 sm:py-16 lg:px-8">
        <div className="mb-8">
          {user ? (
            <StatusNotice title="Active Committee Session Detected" variant="navy">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <span>
                  Signed in as <strong>{user.email}</strong>.
                </span>
                <LinkButton href="/committee/dashboard" variant="primary" size="sm">
                  Go to Dashboard
                </LinkButton>
              </div>
            </StatusNotice>
          ) : (
            <StatusNotice title="Supabase Auth Connected" variant="info">
              Sign in with a committee account provisioned in your Supabase
              project&apos;s Authentication users.
            </StatusNotice>
          )}
        </div>

        <CommitteeLoginForm />

        <div className="mt-8 flex items-center justify-center gap-2 text-xs text-slate-500">
          <Shield className="h-3.5 w-3.5 text-navy-700" />
          <span>
            Role-separated route structure under{" "}
            <code className="font-mono">/committee/*</code>
          </span>
        </div>
      </section>
    </div>
  );
}
