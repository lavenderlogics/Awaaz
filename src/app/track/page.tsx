import type { Metadata } from "next";
import { TrackCaseClient } from "@/components/sections/TrackCaseClient";
import { LinkButton } from "@/components/ui/Button";
import { PageHeader } from "@/components/ui/PageHeader";

export const metadata: Metadata = {
  title: "Track Case",
  description:
    "Track the status of an anonymous campus complaint using your Awaaz Case ID.",
};

export default function TrackPage() {
  return (
    <div>
      <PageHeader
        eyebrow="Case Follow-Up"
        title="Track Your Complaint Status"
        description="Look up progress using your reference Case ID without logging into a student account."
        badgeText="UI Setup · Lookup Pending"
        actions={
          <LinkButton href="/report" variant="outline" size="md">
            File a New Report
          </LinkButton>
        }
      />

      <section className="mx-auto max-w-5xl px-4 py-10 sm:px-6 sm:py-14 lg:px-8">
        <TrackCaseClient />
      </section>
    </div>
  );
}
