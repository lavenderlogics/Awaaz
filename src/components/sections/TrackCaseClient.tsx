"use client";

import { CheckCircle2, Clock, Search, Shield } from "lucide-react";
import { type FormEvent, useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { FormField, Input } from "@/components/ui/FormField";
import { StatusNotice } from "@/components/ui/StatusNotice";
import { PLANNED_CASE_STAGES } from "@/lib/constants";

/** Case tracking UI shell with planned lifecycle preview (no fake backend lookups). */
export function TrackCaseClient() {
  const [caseId, setCaseId] = useState("");
  const [error, setError] = useState("");
  const [lookupAttempted, setLookupAttempted] = useState(false);

  const handleLookup = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = caseId.trim();

    if (!trimmed) {
      setError("Please enter a Case ID to inspect the lookup flow.");
      setLookupAttempted(false);
      return;
    }

    setError("");
    setLookupAttempted(true);
  };

  return (
    <div className="space-y-8">
      <Card>
        <CardHeader className="border-b border-slate-100">
          <CardTitle>Look Up Complaint Status</CardTitle>
          <p className="mt-1 text-sm text-slate-600">
            Enter the reference Case ID issued when a report is logged.
          </p>
        </CardHeader>
        <CardContent className="pt-6">
          <form
            onSubmit={handleLookup}
            className="flex flex-col gap-4 sm:flex-row sm:items-end"
            noValidate
          >
            <div className="flex-1">
              <FormField
                id="caseId"
                label="Case Reference ID"
                hint="Planned format example: AWZ-2026-XXXXXX"
                error={error}
              >
                <Input
                  id="caseId"
                  type="text"
                  className="font-mono uppercase"
                  placeholder="Enter Case ID..."
                  value={caseId}
                  onChange={(e) => setCaseId(e.target.value)}
                />
              </FormField>
            </div>
            <Button type="submit" variant="primary" size="lg" className="sm:mb-6">
              <Search className="h-4 w-4" />
              Check Status
            </Button>
          </form>

          {lookupAttempted ? (
            <StatusNotice
              title="Case Lookup Pending Supabase Integration"
              variant="warning"
              className="mt-6"
            >
              Lookup was requested for{" "}
              <code className="rounded bg-amber-100 px-1.5 py-0.5 font-mono text-xs font-semibold">
                {caseId.trim().toUpperCase()}
              </code>
              . Live database queries are not connected yet, so no real or mock
              case status is returned.
            </StatusNotice>
          ) : null}
        </CardContent>
      </Card>

      <Card subtle>
        <CardHeader className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle>Planned Review Lifecycle</CardTitle>
            <p className="mt-1 text-sm text-slate-600">
              Structure of the status timeline that will display once backend
              tracking is connected.
            </p>
          </div>
          <Badge variant="outline">Template Layout</Badge>
        </CardHeader>
        <CardContent className="pt-2">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {PLANNED_CASE_STAGES.map((stage, index) => (
              <div
                key={stage.id}
                className="relative rounded-xl border border-slate-200 bg-white p-4 shadow-2xs"
              >
                <div className="flex items-center justify-between">
                  <span className="inline-flex h-7 w-7 items-center justify-center rounded-lg bg-navy-50 font-mono text-xs font-bold text-navy-900">
                    0{index + 1}
                  </span>
                  {index === 0 ? (
                    <Shield className="h-4 w-4 text-navy-700" />
                  ) : index === PLANNED_CASE_STAGES.length - 1 ? (
                    <CheckCircle2 className="h-4 w-4 text-slate-400" />
                  ) : (
                    <Clock className="h-4 w-4 text-slate-400" />
                  )}
                </div>
                <h4 className="mt-3 text-sm font-semibold text-slate-900">
                  {stage.label}
                </h4>
                <p className="mt-1.5 text-xs leading-relaxed text-slate-600">
                  {stage.description}
                </p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
