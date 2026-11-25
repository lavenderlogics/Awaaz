import type { Metadata } from "next";
import { CommitteeDashboardClient } from "@/components/sections/CommitteeDashboardClient";
import { LinkButton } from "@/components/ui/Button";
import { PageHeader } from "@/components/ui/PageHeader";
import {
  isServiceRoleConfigured,
  isSupabaseConfigured,
} from "@/lib/supabase/config";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = {
  title: "Committee Dashboard",
  description:
    "Committee triage dashboard for reviewing and unlocking encrypted campus complaints.",
};

export default async function CommitteeDashboardPage() {
  const configured = isSupabaseConfigured();
  const serviceRoleReady = isServiceRoleConfigured();
  let userEmail: string | null = null;
  let userId: string | null = null;

  if (configured) {
    try {
      const supabase = await createClient();
      const {
        data: { user },
      } = await supabase.auth.getUser();
      userEmail = user?.email ?? null;
      userId = user?.id ?? null;
    } catch {
      userEmail = null;
      userId = null;
    }
  }

  return (
    <div>
      <PageHeader
        eyebrow="Committee Workspace"
        title="Complaint Triage Dashboard"
        description="Centralized review queue, dual-key decryption workflow, and hash-chained audit logs for authorized committee officers."
        badgeText={
          !configured
            ? "Supabase Env Required"
            : userEmail
              ? "Authenticated Session"
              : "Sign-In Required"
        }
        actions={
          <LinkButton href="/committee/login" variant="outline" size="md">
            {userEmail ? "Account Portal" : "Committee Login"}
          </LinkButton>
        }
      />

      <section className="mx-auto max-w-6xl px-4 py-10 sm:px-6 sm:py-14 lg:px-8">
        <CommitteeDashboardClient
          isConfigured={configured}
          isServiceRoleReady={serviceRoleReady}
          userEmail={userEmail}
          userId={userId}
        />
      </section>
    </div>
  );
}
