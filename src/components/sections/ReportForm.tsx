"use client";

import { Check, Copy, FileUp, RotateCcw, Send, X } from "lucide-react";
import { type ChangeEvent, type FormEvent, useState } from "react";
import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { FormField, Input, Select, Textarea } from "@/components/ui/FormField";
import { StatusNotice } from "@/components/ui/StatusNotice";
import { INCIDENT_CATEGORIES, URGENCY_LEVELS } from "@/lib/constants";
import {
  encryptComplaintInBrowser,
  encryptEvidenceBytesInBrowser,
  type PublicCommitteeRecipient,
} from "@/lib/security/client-crypto";
import {
  ALLOWED_EVIDENCE_MIME_TYPES,
  MAX_EVIDENCE_BYTES,
  MAX_EVIDENCE_FILES,
} from "@/lib/security/validation";

interface ReportFormState {
  category: string;
  urgency: string;
  incidentDate: string;
  location: string;
  description: string;
  additionalContext: string;
}

interface SubmissionSuccess {
  complaintId: string;
  caseCode: string;
  recoverySecret: string;
  evidenceCount: number;
}

const INITIAL_STATE: ReportFormState = {
  category: "",
  urgency: "standard",
  incidentDate: "",
  location: "",
  description: "",
  additionalContext: "",
};

/**
 * Anonymous client-encrypted complaint intake form.
 * Encrypts complaint payload and evidence files inside the browser via Web Crypto
 * before sending any data to POST /api/complaints.
 */
export function ReportForm() {
  const [form, setForm] = useState<ReportFormState>(INITIAL_STATE);
  const [files, setFiles] = useState<File[]>([]);
  const [errors, setErrors] = useState<
    Partial<Record<keyof ReportFormState, string>>
  >({});
  const [serverError, setServerError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [successData, setSuccessData] = useState<SubmissionSuccess | null>(
    null
  );
  const [copiedField, setCopiedField] = useState<"case" | "recovery" | null>(
    null
  );

  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    const selected = Array.from(event.target.files ?? []);
    if (selected.length === 0) return;
    setFiles((prev) => [...prev, ...selected].slice(0, MAX_EVIDENCE_FILES));
    event.target.value = "";
  };

  const removeFile = (index: number) => {
    setFiles((prev) => prev.filter((_, idx) => idx !== index));
  };

  const copyText = async (value: string, field: "case" | "recovery") => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 2000);
    } catch {
      // Clipboard API may be unavailable in restricted contexts.
    }
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const nextErrors: Partial<Record<keyof ReportFormState, string>> = {};

    if (!form.category) {
      nextErrors.category = "Please select an incident category.";
    }
    if (!form.incidentDate) {
      nextErrors.incidentDate =
        "Please provide the approximate date of the incident.";
    }
    if (!form.location.trim()) {
      nextErrors.location = "Please specify where the incident occurred.";
    }
    if (form.description.trim().length < 20) {
      nextErrors.description =
        "Please provide at least 20 characters describing what happened.";
    }

    setErrors(nextErrors);
    setServerError("");
    if (Object.keys(nextErrors).length > 0) {
      return;
    }

    for (const file of files) {
      if (file.size > MAX_EVIDENCE_BYTES) {
        setServerError(`File "${file.name}" exceeds the 5 MB limit.`);
        return;
      }
      if (!ALLOWED_EVIDENCE_MIME_TYPES.has(file.type)) {
        setServerError(
          `Unsupported file type (${file.type || "unknown"}). Allowed: PNG, JPEG, WEBP, PDF, TXT.`
        );
        return;
      }
    }

    setIsSubmitting(true);

    try {
      // 1. Fetch validated active committee public keys
      const keysRes = await fetch("/api/committee/public-keys", {
        cache: "no-store",
      });
      const keysJson = (await keysRes.json()) as {
        members?: PublicCommitteeRecipient[];
        error?: string;
      };

      if (!keysRes.ok || !Array.isArray(keysJson.members)) {
        setServerError(
          keysJson.error ??
            "Unable to load committee encryption keys. Submission halted safely."
        );
        return;
      }

      const recipients = keysJson.members;
      if (recipients.length < 2) {
        setServerError(
          "At least 2 committee public keys are required for browser encryption. Submission halted safely."
        );
        return;
      }

      // 2. Generate complaint ID (used as AES-GCM AAD) and encrypt payload in browser
      const complaintId = window.crypto.randomUUID();
      const sensitivePayload = {
        detailedCategory: form.category,
        urgency: form.urgency,
        incidentDate: form.incidentDate,
        location: form.location.trim(),
        description: form.description.trim(),
        additionalContext: form.additionalContext.trim(),
        evidenceFileNames: files.map((f) => f.name),
      };

      const envelope = await encryptComplaintInBrowser({
        complaintId,
        payload: sensitivePayload,
        recipients,
      });

      // 3. Encrypt every evidence file individually in browser with unique IV & DEK
      const evidenceMeta: Array<{ fileId: string; mimeType: string }> = [];
      const encryptedEvidenceFiles: Array<{ fileId: string; blob: Blob }> = [];

      for (const file of files) {
        const fileId = window.crypto.randomUUID();
        const rawBytes = new Uint8Array(await file.arrayBuffer());
        const encryptedResult = await encryptEvidenceBytesInBrowser({
          fileBytes: rawBytes,
          mimeType: file.type,
          complaintId,
          fileId,
          recipients,
        });
        rawBytes.fill(0);

        evidenceMeta.push({
          fileId: encryptedResult.fileId,
          mimeType: encryptedResult.mimeType,
        });
        const copy = new Uint8Array(encryptedResult.encryptedBytes.byteLength);
        copy.set(encryptedResult.encryptedBytes);
        encryptedEvidenceFiles.push({
          fileId: encryptedResult.fileId,
          blob: new Blob([copy.buffer], { type: "application/octet-stream" }),
        });
      }

      // 4. Send ONLY ciphertext envelope and encrypted evidence blobs to server
      const body = new FormData();
      body.set("complaintId", complaintId);
      body.set("category", form.category);
      body.set("encryptedPayload", JSON.stringify(envelope));
      body.set("evidenceMeta", JSON.stringify(evidenceMeta));

      for (const item of encryptedEvidenceFiles) {
        body.append("evidence", item.blob, `${item.fileId}.enc`);
      }

      const res = await fetch("/api/complaints", {
        method: "POST",
        body,
      });
      const json = (await res.json()) as Record<string, unknown>;

      if (!res.ok) {
        setServerError(
          typeof json.error === "string"
            ? json.error
            : "Unable to submit encrypted report."
        );
        return;
      }

      setSuccessData({
        complaintId: String(json.complaintId ?? complaintId),
        caseCode: String(json.caseCode ?? ""),
        recoverySecret: String(json.recoverySecret ?? ""),
        evidenceCount: Number(json.evidenceCount ?? 0),
      });
      setForm(INITIAL_STATE);
      setFiles([]);
    } catch {
      // Never fall back to unencrypted or server-side submission
      setServerError(
        "Client-side encryption failed in your browser. No complaint data was transmitted."
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleReset = () => {
    setForm(INITIAL_STATE);
    setFiles([]);
    setErrors({});
    setServerError("");
    setSuccessData(null);
  };

  return (
    <Card>
      <CardHeader className="border-b border-slate-100">
        <CardTitle>Incident Report Details</CardTitle>
        <p className="mt-1 text-sm text-slate-600">
          Do not include your name, student ID, or personal phone number unless
          you choose to share it later.
        </p>
      </CardHeader>
      <CardContent className="pt-6">
        {successData ? (
          <div className="space-y-6">
            <StatusNotice
              title="Encrypted Complaint Submitted Successfully"
              variant="success"
            >
              Your report payload was encrypted inside your browser with{" "}
              <strong>AES-256-GCM</strong> and split across committee keys
              before transmission. Save your Case ID and Recovery Secret
              now—only their cryptographic hashes are stored, so they cannot be
              recovered if lost.
            </StatusNotice>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="rounded-xl border border-navy-700/20 bg-navy-50/70 p-4">
                <p className="text-xs font-semibold tracking-wider text-navy-800 uppercase">
                  Case ID (For Status Tracking)
                </p>
                <div className="mt-2 flex items-center justify-between gap-2">
                  <code className="font-mono text-base font-bold text-navy-950">
                    {successData.caseCode}
                  </code>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => copyText(successData.caseCode, "case")}
                  >
                    {copiedField === "case" ? (
                      <Check className="h-3.5 w-3.5 text-emerald-700" />
                    ) : (
                      <Copy className="h-3.5 w-3.5" />
                    )}
                    {copiedField === "case" ? "Copied" : "Copy"}
                  </Button>
                </div>
              </div>

              <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                <p className="text-xs font-semibold tracking-wider text-slate-600 uppercase">
                  Recovery Secret (For Follow-Up Evidence)
                </p>
                <div className="mt-2 flex items-center justify-between gap-2">
                  <code className="font-mono text-base font-bold text-slate-950">
                    {successData.recoverySecret}
                  </code>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      copyText(successData.recoverySecret, "recovery")
                    }
                  >
                    {copiedField === "recovery" ? (
                      <Check className="h-3.5 w-3.5 text-emerald-700" />
                    ) : (
                      <Copy className="h-3.5 w-3.5" />
                    )}
                    {copiedField === "recovery" ? "Copied" : "Copy"}
                  </Button>
                </div>
              </div>
            </div>

            <p className="text-xs text-slate-500">
              Encrypted evidence files stored: {successData.evidenceCount}
            </p>

            <Button type="button" variant="outline" onClick={handleReset}>
              Submit Another Anonymous Report
            </Button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-6" noValidate>
            <div className="grid gap-5 sm:grid-cols-2">
              <FormField
                id="category"
                label="Incident Category"
                required
                error={errors.category}
              >
                <Select
                  id="category"
                  value={form.category}
                  onChange={(e) =>
                    setForm((prev) => ({ ...prev, category: e.target.value }))
                  }
                  disabled={isSubmitting}
                >
                  <option value="">Select a category...</option>
                  {INCIDENT_CATEGORIES.map((category) => (
                    <option key={category} value={category}>
                      {category}
                    </option>
                  ))}
                </Select>
              </FormField>

              <FormField
                id="urgency"
                label="Urgency Level"
                hint="Encrypted inside the report payload for committee review."
              >
                <Select
                  id="urgency"
                  value={form.urgency}
                  onChange={(e) =>
                    setForm((prev) => ({ ...prev, urgency: e.target.value }))
                  }
                  disabled={isSubmitting}
                >
                  {URGENCY_LEVELS.map((level) => (
                    <option key={level.value} value={level.value}>
                      {level.label}
                    </option>
                  ))}
                </Select>
              </FormField>
            </div>

            <div className="grid gap-5 sm:grid-cols-2">
              <FormField
                id="incidentDate"
                label="Date of Incident"
                required
                error={errors.incidentDate}
              >
                <Input
                  id="incidentDate"
                  type="date"
                  value={form.incidentDate}
                  onChange={(e) =>
                    setForm((prev) => ({
                      ...prev,
                      incidentDate: e.target.value,
                    }))
                  }
                  disabled={isSubmitting}
                />
              </FormField>

              <FormField
                id="location"
                label="Campus Location or Platform"
                required
                hint="Example: Hostel Block B, Main Canteen, or WhatsApp Group."
                error={errors.location}
              >
                <Input
                  id="location"
                  type="text"
                  placeholder="e.g., North Hostel Corridor, 2nd Floor"
                  value={form.location}
                  onChange={(e) =>
                    setForm((prev) => ({ ...prev, location: e.target.value }))
                  }
                  disabled={isSubmitting}
                />
              </FormField>
            </div>

            <FormField
              id="description"
              label="What Happened?"
              required
              hint="Describe the sequence of events clearly. Avoid including identifying metadata about yourself."
              error={errors.description}
            >
              <Textarea
                id="description"
                placeholder="Provide a factual account of the incident, approximate time, and any ongoing risk..."
                value={form.description}
                onChange={(e) =>
                  setForm((prev) => ({ ...prev, description: e.target.value }))
                }
                disabled={isSubmitting}
              />
            </FormField>

            <FormField
              id="additionalContext"
              label="Involved Individuals or Witnesses (Optional)"
              hint="Optional details such as roles, batch, or whether bystanders were present."
            >
              <Textarea
                id="additionalContext"
                className="min-h-24"
                placeholder="Optional context to help committee members verify or investigate..."
                value={form.additionalContext}
                onChange={(e) =>
                  setForm((prev) => ({
                    ...prev,
                    additionalContext: e.target.value,
                  }))
                }
                disabled={isSubmitting}
              />
            </FormField>

            <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50/70 p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-start gap-3">
                  <FileUp className="mt-0.5 h-5 w-5 shrink-0 text-navy-700" />
                  <div className="space-y-1">
                    <p className="text-sm font-medium text-slate-800">
                      Attach Encrypted Evidence (Optional)
                    </p>
                    <p className="text-xs leading-relaxed text-slate-600">
                      Up to 3 files (PNG, JPEG, WEBP, PDF, TXT &middot; max 5 MB
                      each). Encrypted in your browser before upload to{" "}
                      <code className="font-mono">awaaz-evidence</code>.
                    </p>
                  </div>
                </div>
                <label className="inline-flex cursor-pointer items-center justify-center rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-navy-900 shadow-2xs transition hover:bg-slate-50">
                  Select Files
                  <input
                    type="file"
                    multiple
                    accept="image/png,image/jpeg,image/webp,application/pdf,text/plain"
                    className="sr-only"
                    onChange={handleFileChange}
                    disabled={isSubmitting || files.length >= MAX_EVIDENCE_FILES}
                  />
                </label>
              </div>

              {files.length > 0 ? (
                <ul className="mt-3 space-y-2 border-t border-slate-200 pt-3">
                  {files.map((file, idx) => (
                    <li
                      key={`${file.name}-${idx}`}
                      className="flex items-center justify-between rounded-lg bg-white px-3 py-2 text-xs text-slate-700"
                    >
                      <span className="truncate font-medium">
                        {file.name} ({Math.ceil(file.size / 1024)} KB)
                      </span>
                      <button
                        type="button"
                        onClick={() => removeFile(idx)}
                        className="ml-2 text-slate-400 hover:text-red-700"
                        aria-label={`Remove ${file.name}`}
                      >
                        <X className="h-4 w-4" />
                      </button>
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>

            {serverError ? (
              <StatusNotice title="Submission Error" variant="warning">
                {serverError}
              </StatusNotice>
            ) : null}

            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-5">
              <Button
                type="button"
                variant="ghost"
                onClick={handleReset}
                disabled={isSubmitting}
              >
                <RotateCcw className="h-4 w-4" />
                Clear Form
              </Button>
              <Button
                type="submit"
                variant="primary"
                size="lg"
                disabled={isSubmitting}
              >
                <Send className="h-4 w-4" />
                {isSubmitting
                  ? "Encrypting in Browser..."
                  : "Submit Anonymous Report"}
              </Button>
            </div>
          </form>
        )}
      </CardContent>
    </Card>
  );
}
