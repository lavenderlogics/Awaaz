import type { Metadata } from "next";
import { Shield } from "lucide-react";
import { CommitteeLoginForm } from "@/components/sections/CommitteeLoginForm";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatusNotice } from "@/components/ui/StatusNotice";

export const metadata: Metadata = {
  title: "Committee Login",
  description:
    "Sign-in portal for authorized campus anti-ragging and harassment committee members.",
};

export default function CommitteeLoginPage() {
  return (
    <div>
      <PageHeader
        eyebrow="Authorized Access"
        title="Committee Portal Sign In"
        description="Dedicated access point for institutional anti-ragging and internal complaints committee members."
        badgeText="Auth Integration Pending"
      />

      <section className="mx-auto max-w-4xl px-4 py-12 sm:px-6 sm:py-16 lg:px-8">
        <div className="mb-8">
          <StatusNotice
            title="Supabase Auth Scheduled for Next Phase"
            variant="info"
          >
            Authentication and role-based session protection will be connected
            with Supabase Auth. No credentials are validated in this frontend
            setup.
          </StatusNotice>
        </div>

        <CommitteeLoginForm />

        <div className="mt-8 flex items-center justify-center gap-2 text-xs text-slate-500">
          <Shield className="h-3.5 w-3.5 text-navy-700" />
          <span>
            Role-separated route structure under <code className="font-mono">/committee/*</code>
          </span>
        </div>
      </section>
    </div>
  );
}
