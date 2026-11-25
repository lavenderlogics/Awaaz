"use client";

import {
  CheckCircle2,
  ClipboardList,
  Clock,
  Database,
  Filter,
  Inbox,
  Search,
  ShieldAlert,
} from "lucide-react";
import { useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { Input, Select } from "@/components/ui/FormField";
import { StatusNotice } from "@/components/ui/StatusNotice";
import { INCIDENT_CATEGORIES, PLANNED_CASE_STAGES } from "@/lib/constants";

const SUMMARY_METRICS = [
  { label: "Total Complaints", icon: ClipboardList },
  { label: "Pending Triage", icon: Clock },
  { label: "High Urgency", icon: ShieldAlert },
  { label: "Resolved Cases", icon: CheckCircle2 },
];

/** Committee dashboard UI shell prepared for future Supabase queries. */
export function CommitteeDashboardClient() {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("all");
  const [selectedStatus, setSelectedStatus] = useState("all");

  return (
    <div className="space-y-8">
      <StatusNotice title="Dashboard Shell — Supabase Not Connected" variant="navy">
        This workspace displays the committee triage layout, filters, and
        integration structure. Live case counts and records are intentionally
        left empty until Supabase Auth, Database, and Row-Level Security are
        configured.
      </StatusNotice>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {SUMMARY_METRICS.map((metric) => {
          const Icon = metric.icon;
          return (
            <Card key={metric.label}>
              <CardContent className="p-5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold tracking-wider text-slate-500 uppercase">
                    {metric.label}
                  </span>
                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-navy-50 text-navy-800">
                    <Icon className="h-4 w-4" />
                  </span>
                </div>
                <p className="mt-3 font-display text-3xl font-bold text-slate-950">
                  &mdash;
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  Awaiting live database query
                </p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="border-b border-slate-100">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <CardTitle>Incoming Complaint Queue</CardTitle>
                <p className="mt-1 text-sm text-slate-600">
                  Filter controls ready to bind to committee report queries.
                </p>
              </div>
              <Badge variant="slate">0 Records Loaded</Badge>
            </div>

            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              <div className="relative">
                <Search className="pointer-events-none absolute top-3 left-3 h-4 w-4 text-slate-400" />
                <Input
                  type="text"
                  placeholder="Search Case ID or location..."
                  className="pl-9"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  aria-label="Search cases"
                />
              </div>
              <Select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                aria-label="Filter by category"
              >
                <option value="all">All Categories</option>
                {INCIDENT_CATEGORIES.map((category) => (
                  <option key={category} value={category}>
                    {category}
                  </option>
                ))}
              </Select>
              <Select
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value)}
                aria-label="Filter by status"
              >
                <option value="all">All Statuses</option>
                {PLANNED_CASE_STAGES.map((stage) => (
                  <option key={stage.id} value={stage.id}>
                    {stage.label}
                  </option>
                ))}
              </Select>
            </div>
          </CardHeader>

          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-slate-200 bg-slate-50/80 text-xs font-semibold tracking-wider text-slate-600 uppercase">
                  <tr>
                    <th className="px-6 py-3.5">Case ID</th>
                    <th className="px-6 py-3.5">Category</th>
                    <th className="px-6 py-3.5">Location</th>
                    <th className="px-6 py-3.5">Urgency</th>
                    <th className="px-6 py-3.5">Status</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td colSpan={5} className="px-6 py-14 text-center">
                      <div className="mx-auto flex max-w-sm flex-col items-center space-y-2.5">
                        <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-navy-50 text-navy-800">
                          <Inbox className="h-6 w-6" />
                        </span>
                        <p className="text-sm font-semibold text-slate-900">
                          No live cases connected
                        </p>
                        <p className="text-xs leading-relaxed text-slate-500">
                          Active filters:{" "}
                          <span className="font-mono text-slate-700">
                            {selectedCategory} / {selectedStatus}
                          </span>
                          {searchQuery ? ` / "${searchQuery}"` : ""}. Connect
                          Supabase to populate verified committee records.
                        </p>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        <Card subtle>
          <CardHeader>
            <div className="flex items-center gap-2 text-navy-800">
              <Database className="h-4 w-4" />
              <span className="text-xs font-semibold tracking-wider uppercase">
                Next Milestone
              </span>
            </div>
            <CardTitle className="mt-2">Planned Integration Hooks</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm text-slate-600">
            <div className="rounded-xl border border-slate-200 bg-white p-3.5">
              <p className="font-semibold text-slate-900">
                1. Supabase Auth &amp; Roles
              </p>
              <p className="mt-1 text-xs leading-relaxed">
                Gate this route behind authenticated committee sessions before
                loading any complaint records.
              </p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-3.5">
              <p className="font-semibold text-slate-900">
                2. Complaints &amp; Updates Tables
              </p>
              <p className="mt-1 text-xs leading-relaxed">
                Store structured report submissions and append-only status
                transitions mapped to Case IDs.
              </p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-3.5">
              <div className="flex items-center gap-1.5 font-semibold text-slate-900">
                <Filter className="h-3.5 w-3.5 text-navy-700" />
                3. Row-Level Security (RLS)
              </div>
              <p className="mt-1 text-xs leading-relaxed">
                Restrict read/write access on case queues strictly to authorized
                committee officers.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
