"use client";

import { FileUp, RotateCcw, Send } from "lucide-react";
import { type FormEvent, useState } from "react";
import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { FormField, Input, Select, Textarea } from "@/components/ui/FormField";
import { StatusNotice } from "@/components/ui/StatusNotice";
import { INCIDENT_CATEGORIES, URGENCY_LEVELS } from "@/lib/constants";

interface ReportFormState {
  category: string;
  urgency: string;
  incidentDate: string;
  location: string;
  description: string;
  additionalContext: string;
}

const INITIAL_STATE: ReportFormState = {
  category: "",
  urgency: "standard",
  incidentDate: "",
  location: "",
  description: "",
  additionalContext: "",
};

/** Client-side anonymous report intake form (UI setup prior to Supabase integration). */
export function ReportForm() {
  const [form, setForm] = useState<ReportFormState>(INITIAL_STATE);
  const [errors, setErrors] = useState<Partial<Record<keyof ReportFormState, string>>>({});
  const [validatedPreview, setValidatedPreview] = useState(false);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const nextErrors: Partial<Record<keyof ReportFormState, string>> = {};

    if (!form.category) {
      nextErrors.category = "Please select an incident category.";
    }
    if (!form.incidentDate) {
      nextErrors.incidentDate = "Please provide the approximate date of the incident.";
    }
    if (!form.location.trim()) {
      nextErrors.location = "Please specify where the incident occurred.";
    }
    if (form.description.trim().length < 20) {
      nextErrors.description =
        "Please provide at least 20 characters describing what happened.";
    }

    setErrors(nextErrors);
    setValidatedPreview(Object.keys(nextErrors).length === 0);
  };

  const handleReset = () => {
    setForm(INITIAL_STATE);
    setErrors({});
    setValidatedPreview(false);
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
              hint="Helps the committee prioritize safety responses once backend triage is enabled."
            >
              <Select
                id="urgency"
                value={form.urgency}
                onChange={(e) =>
                  setForm((prev) => ({ ...prev, urgency: e.target.value }))
                }
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
                  setForm((prev) => ({ ...prev, incidentDate: e.target.value }))
                }
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
            />
          </FormField>

          <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50/70 p-4">
            <div className="flex items-start gap-3">
              <FileUp className="mt-0.5 h-5 w-5 shrink-0 text-navy-700" />
              <div className="space-y-1">
                <p className="text-sm font-medium text-slate-800">
                  Evidence Attachment (Planned)
                </p>
                <p className="text-xs leading-relaxed text-slate-600">
                  File upload UI is reserved for future Supabase Storage
                  integration. No files are uploaded or processed in this initial
                  setup.
                </p>
              </div>
            </div>
          </div>

          {validatedPreview ? (
            <StatusNotice
              title="Form Validated Locally (Backend Not Connected)"
              variant="warning"
            >
              All required fields are filled out properly, but{" "}
              <strong>no report was submitted or saved</strong>. Database
              storage and case ID generation will be enabled once Supabase is
              integrated.
            </StatusNotice>
          ) : null}

          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-5">
            <Button type="button" variant="ghost" onClick={handleReset}>
              <RotateCcw className="h-4 w-4" />
              Clear Form
            </Button>
            <Button type="submit" variant="primary" size="lg">
              <Send className="h-4 w-4" />
              Validate Form (Backend Pending)
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
