import type { Metadata } from "next";
import { CommitteeDashboardClient } from "@/components/sections/CommitteeDashboardClient";
import { LinkButton } from "@/components/ui/Button";
import { PageHeader } from "@/components/ui/PageHeader";

export const metadata: Metadata = {
  title: "Committee Dashboard",
  description:
    "Committee triage dashboard shell for reviewing and updating campus complaints.",
};

export default function CommitteeDashboardPage() {
  return (
    <div>
      <PageHeader
        eyebrow="Committee Workspace"
        title="Complaint Triage Dashboard"
        description="Centralized review queue, status filters, and integration hooks for authorized campus committee members."
        badgeText="UI Shell · Awaiting Supabase"
        actions={
          <LinkButton href="/committee/login" variant="outline" size="md">
            Back to Committee Login
          </LinkButton>
        }
      />

      <section className="mx-auto max-w-6xl px-4 py-10 sm:px-6 sm:py-14 lg:px-8">
        <CommitteeDashboardClient />
      </section>
    </div>
  );
}
