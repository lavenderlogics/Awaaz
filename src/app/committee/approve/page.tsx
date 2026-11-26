import type { Metadata } from "next";
import { ApproveApplicantClient } from "@/components/sections/ApproveApplicantClient";
import { PageHeader } from "@/components/ui/PageHeader";

export const metadata: Metadata = {
  title: "Confirm Committee Member",
  description:
    "Single-use administrator confirmation for authorizing a new Awaaz committee officer.",
};

interface ApprovePageProps {
  searchParams: Promise<{ token?: string }>;
}

export default async function ApproveCommitteePage({
  searchParams,
}: ApprovePageProps) {
  const { token = "" } = await searchParams;

  return (
    <div>
      <PageHeader
        eyebrow="Admin Authorization"
        title="Confirm Committee Access"
        description="Review and confirm whether this registered applicant is an authorized campus committee member."
        badgeText="Single-Use Signed Link"
      />
      <section className="mx-auto max-w-4xl px-4 py-12 sm:px-6 sm:py-16 lg:px-8">
        <ApproveApplicantClient token={token} />
      </section>
    </div>
  );
}
