import type { Metadata } from "next";
import { ShieldAlert, ShieldCheck } from "lucide-react";
import { ReportForm } from "@/components/sections/ReportForm";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatusNotice } from "@/components/ui/StatusNotice";

export const metadata: Metadata = {
  title: "Report Incident",
  description:
    "Submit an anonymous campus ragging or harassment report on Awaaz.",
};

export default function ReportPage() {
  return (
    <div>
      <PageHeader
        eyebrow="Anonymous Intake"
        title="Submit a Campus Incident Report"
        description="Use this structured form to document ragging, intimidation, or harassment without entering your personal identity."
        badgeText="AES-256-GCM Encrypted Intake"
      />

      <section className="mx-auto max-w-6xl px-4 py-10 sm:px-6 sm:py-14 lg:px-8">
        <div className="mb-8">
          <StatusNotice
            title="Zero Plaintext Storage &amp; Browser-Side Encryption"
            variant="info"
          >
            Sensitive complaint details and attached evidence files are
            encrypted inside your browser with <strong>AES-256-GCM</strong>{" "}
            before transmission, and decryption keys are split across
            authorized committee members so no single account can read reports
            alone.
          </StatusNotice>
        </div>

        <div className="grid gap-8 lg:grid-cols-12">
          <div className="lg:col-span-8">
            <ReportForm />
          </div>

          <aside className="space-y-6 lg:col-span-4">
            <Card subtle>
              <CardHeader>
                <div className="flex items-center gap-2 text-navy-800">
                  <ShieldCheck className="h-5 w-5" />
                  <CardTitle className="text-base">
                    Tips for Safe Reporting
                  </CardTitle>
                </div>
              </CardHeader>
              <CardContent className="space-y-3 text-sm leading-relaxed text-slate-600">
                <p>
                  <strong className="text-slate-900">1. Omit self-IDs:</strong>{" "}
                  Avoid writing your name, room number, or personal phone number
                  in the description.
                </p>
                <p>
                  <strong className="text-slate-900">
                    2. Focus on specifics:
                  </strong>{" "}
                  Note exact campus locations, dates, and patterns of behaviour.
                </p>
                <p>
                  <strong className="text-slate-900">
                    3. Save your Case ID &amp; Secret:
                  </strong>{" "}
                  Your Case ID tracks committee progress, and your Recovery
                  Secret authorizes follow-up encrypted evidence uploads.
                </p>
              </CardContent>
            </Card>

            <Card className="border-amber-200 bg-amber-50/50">
              <CardHeader>
                <div className="flex items-center gap-2 text-amber-800">
                  <ShieldAlert className="h-5 w-5" />
                  <CardTitle className="text-base text-amber-950">
                    Immediate Safety Risk?
                  </CardTitle>
                </div>
              </CardHeader>
              <CardContent className="text-sm leading-relaxed text-amber-900">
                Online reporting is intended for structured review, not live
                emergency dispatch. If someone is in immediate danger, contact
                campus security or local emergency responders right away.
              </CardContent>
            </Card>
          </aside>
        </div>
      </section>
    </div>
  );
}
