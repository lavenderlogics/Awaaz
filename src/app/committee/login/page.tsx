import type { Metadata } from "next";
import { Shield } from "lucide-react";
import { CommitteeLoginForm } from "@/components/sections/CommitteeLoginForm";
import { LinkButton } from "@/components/ui/Button";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatusNotice } from "@/components/ui/StatusNotice";
import { isSupabaseConfigured } from "@/lib/supabase/config";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = {
  title: "Committee Login",
  description:
    "Sign-in portal for authorized campus anti-ragging and harassment committee members.",
};

export default async function CommitteeLoginPage() {
  const configured = isSupabaseConfigured();
  let userEmail: string | null = null;

  if (configured) {
    try {
      const supabase = await createClient();
      const {
        data: { user },
      } = await supabase.auth.getUser();
      userEmail = user?.email ?? null;
    } catch {
      userEmail = null;
    }
  }

  return (
    <div>
      <PageHeader
        eyebrow="Authorized Access"
        title="Committee Portal Sign In"
        description="Dedicated access point for institutional anti-ragging and internal complaints committee members."
        badgeText={
          configured ? "Supabase Auth Connected" : "Supabase Env Required"
        }
      />

      <section className="mx-auto max-w-4xl px-4 py-12 sm:px-6 sm:py-16 lg:px-8">
        <div className="mb-8">
          {!configured ? (
            <StatusNotice
              title="Missing Supabase Environment Variables on Server"
              variant="warning"
            >
              Add <code className="font-mono">NEXT_PUBLIC_SUPABASE_URL</code>{" "}
              and <code className="font-mono">NEXT_PUBLIC_SUPABASE_ANON_KEY</code>{" "}
              in your deployment environment settings (for example, Vercel
              Project Settings &rarr; Environment Variables) and redeploy to
              enable committee sign-in.
            </StatusNotice>
          ) : userEmail ? (
            <StatusNotice title="Active Committee Session Detected" variant="navy">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <span>
                  Signed in as <strong>{userEmail}</strong>.
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

        <CommitteeLoginForm isConfigured={configured} />

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
