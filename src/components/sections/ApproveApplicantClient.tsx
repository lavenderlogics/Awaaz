"use client";

import { CheckCircle2, ShieldAlert, ShieldCheck, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { Button, LinkButton } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { StatusNotice } from "@/components/ui/StatusNotice";

interface InspectResult {
  valid: boolean;
  applicantName?: string;
  applicantEmail?: string;
  applicantUserId?: string;
  action?: "approve_member" | "approve_admin" | "reject";
  expiresAt?: string;
  error?: string;
}

const ACTION_LABELS = {
  approve_member: "Approve as Committee Officer",
  approve_admin: "Approve as Committee Admin",
  reject: "Reject Access Request",
} as const;

export function ApproveApplicantClient({ token }: { token: string }) {
  const [inspectState, setInspectState] = useState<InspectResult | null>(
    token
      ? null
      : {
          valid: false,
          error: "Missing approval token in URL.",
        }
  );
  const [loading, setLoading] = useState(Boolean(token));
  const [submitting, setSubmitting] = useState(false);
  const [doneResult, setDoneResult] = useState<{
    decision: string;
    applicantName: string;
    applicantEmail: string;
  } | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!token) {
      return;
    }

    fetch(`/api/committee/access-approval?token=${encodeURIComponent(token)}`, {
      cache: "no-store",
    })
      .then((res) => res.json() as Promise<InspectResult>)
      .then((data) => setInspectState(data))
      .catch(() =>
        setInspectState({
          valid: false,
          error: "Network error while verifying approval link.",
        })
      )
      .finally(() => setLoading(false));
  }, [token]);

  const handleConfirm = async () => {
    setSubmitting(true);
    setError("");
    try {
      const res = await fetch("/api/committee/access-approval", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      const json = (await res.json()) as {
        ok?: boolean;
        decision?: string;
        applicantName?: string;
        applicantEmail?: string;
        error?: string;
      };
      if (!res.ok || !json.ok) {
        setError(json.error ?? "Unable to apply approval decision.");
        return;
      }
      setDoneResult({
        decision: json.decision ?? "updated",
        applicantName: json.applicantName ?? "Applicant",
        applicantEmail: json.applicantEmail ?? "",
      });
    } catch {
      setError("Network error while confirming decision.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Card className="mx-auto max-w-lg">
      <CardHeader className="border-b border-slate-100">
        <div className="flex items-center gap-2 text-navy-800">
          <ShieldCheck className="h-5 w-5" />
          <CardTitle>Committee Authorization Confirmation</CardTitle>
        </div>
      </CardHeader>
      <CardContent className="space-y-4 pt-6 text-sm">
        {loading ? (
          <div className="space-y-2">
            <div className="h-5 w-48 animate-pulse rounded bg-slate-200" />
            <div className="h-16 animate-pulse rounded-xl bg-slate-100" />
          </div>
        ) : doneResult ? (
          <div className="space-y-4">
            <StatusNotice title="Decision Recorded" variant="success">
              {doneResult.decision === "rejected" ? (
                <span>
                  Rejected committee access request for{" "}
                  <strong>{doneResult.applicantName}</strong> (
                  {doneResult.applicantEmail}).
                </span>
              ) : (
                <span>
                  <strong>{doneResult.applicantName}</strong> (
                  {doneResult.applicantEmail}) is now active as{" "}
                  <strong>
                    {doneResult.decision === "approved_admin"
                      ? "Admin"
                      : "Committee Officer"}
                  </strong>
                  . They can now sign in and register their browser RSA key.
                </span>
              )}
            </StatusNotice>
            <LinkButton href="/committee/dashboard" variant="primary" size="md">
              Open Committee Dashboard
            </LinkButton>
          </div>
        ) : !inspectState?.valid || !inspectState.action ? (
          <div className="space-y-4">
            <StatusNotice title="Invalid or Expired Link" variant="warning">
              <div className="flex items-start gap-2">
                <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-amber-800" />
                <span>
                  {inspectState?.error ??
                    "This approval link is invalid, expired, or already used."}
                </span>
              </div>
            </StatusNotice>
            <LinkButton href="/committee/dashboard" variant="outline" size="md">
              Manage Requests in Dashboard
            </LinkButton>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-xs text-slate-700">
              <p>
                <span className="font-semibold text-slate-900">Applicant:</span>{" "}
                {inspectState.applicantName}
              </p>
              <p className="mt-1">
                <span className="font-semibold text-slate-900">Email:</span>{" "}
                {inspectState.applicantEmail}
              </p>
              <p className="mt-1">
                <span className="font-semibold text-slate-900">Action:</span>{" "}
                {ACTION_LABELS[inspectState.action]}
              </p>
            </div>

            {error ? (
              <StatusNotice title="Authorization Failed" variant="warning">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4" />
                  <span>{error}</span>
                </div>
              </StatusNotice>
            ) : null}

            <Button
              type="button"
              variant={
                inspectState.action === "reject" ? "outline" : "primary"
              }
              size="lg"
              disabled={submitting}
              onClick={() => void handleConfirm()}
              className="w-full"
            >
              <CheckCircle2 className="h-4 w-4" />
              {submitting
                ? "Applying Decision..."
                : ACTION_LABELS[inspectState.action]}
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
