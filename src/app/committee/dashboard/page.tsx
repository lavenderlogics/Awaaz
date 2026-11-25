import type { Metadata } from "next";
import {
  CommitteeDashboardClient,
  type CommitteeComplaintRow,
} from "@/components/sections/CommitteeDashboardClient";
import { LinkButton } from "@/components/ui/Button";
import { PageHeader } from "@/components/ui/PageHeader";
import { isSupabaseConfigured } from "@/lib/supabase/config";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = {
  title: "Committee Dashboard",
  description:
    "Committee triage dashboard for reviewing and updating campus complaints.",
};

function readStringField(
  row: Record<string, unknown>,
  keys: string[],
  fallback: string
): string {
  for (const key of keys) {
    const value = row[key];
    if (typeof value === "string" && value.trim()) {
      return value;
    }
  }
  return fallback;
}

export default async function CommitteeDashboardPage() {
  const configured = isSupabaseConfigured();
  let userEmail: string | null = null;
  let complaints: CommitteeComplaintRow[] = [];
  let queryError: string | null = null;

  if (configured) {
    try {
      const supabase = await createClient();
      const {
        data: { user },
      } = await supabase.auth.getUser();
      userEmail = user?.email ?? null;

      if (user) {
        const { data, error } = await supabase
          .from("complaints")
          .select("*")
          .limit(50);

        if (error) {
          queryError = error.message;
        } else if (Array.isArray(data)) {
          complaints = data.map((item, idx) => {
            const record = item as Record<string, unknown>;
            return {
              id: readStringField(record, ["id"], String(idx)),
              caseId: readStringField(
                record,
                ["case_id", "tracking_id", "reference_id", "id"],
                "—"
              ),
              category: readStringField(
                record,
                ["category", "type"],
                "Uncategorized"
              ),
              location: readStringField(
                record,
                ["location", "campus_location"],
                "—"
              ),
              urgency: readStringField(
                record,
                ["urgency", "severity"],
                "standard"
              ),
              status: readStringField(record, ["status"], "submitted"),
            };
          });
        }
      }
    } catch (err) {
      queryError =
        err instanceof Error ? err.message : "Unable to reach Supabase.";
    }
  }

  return (
    <div>
      <PageHeader
        eyebrow="Committee Workspace"
        title="Complaint Triage Dashboard"
        description="Centralized review queue, status filters, and Supabase Auth integration for authorized campus committee members."
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
          userEmail={userEmail}
          complaints={complaints}
          queryError={queryError}
        />
      </section>
    </div>
  );
}
