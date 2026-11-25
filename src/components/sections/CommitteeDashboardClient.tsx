"use client";

import {
  CheckCircle2,
  ClipboardList,
  Clock,
  Database,
  Filter,
  Inbox,
  LogOut,
  Search,
  ShieldAlert,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button, LinkButton } from "@/components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { Input, Select } from "@/components/ui/FormField";
import { StatusNotice } from "@/components/ui/StatusNotice";
import { INCIDENT_CATEGORIES, PLANNED_CASE_STAGES } from "@/lib/constants";
import { createClient } from "@/lib/supabase/client";

export interface CommitteeComplaintRow {
  id: string;
  caseId: string;
  category: string;
  location: string;
  urgency: string;
  status: string;
}

interface CommitteeDashboardClientProps {
  userEmail: string | null;
  complaints: CommitteeComplaintRow[];
  queryError: string | null;
}

const SUMMARY_METRICS = [
  { key: "total", label: "Total Complaints", icon: ClipboardList },
  { key: "pending", label: "Pending Triage", icon: Clock },
  { key: "urgent", label: "High Urgency", icon: ShieldAlert },
  { key: "resolved", label: "Resolved Cases", icon: CheckCircle2 },
] as const;

/** Committee dashboard workspace connected to Supabase Auth and live query results. */
export function CommitteeDashboardClient({
  userEmail,
  complaints,
  queryError,
}: CommitteeDashboardClientProps) {
  const router = useRouter();
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("all");
  const [selectedStatus, setSelectedStatus] = useState("all");
  const [isSigningOut, setIsSigningOut] = useState(false);

  const filteredComplaints = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    return complaints.filter((row) => {
      const matchesCategory =
        selectedCategory === "all" || row.category === selectedCategory;
      const matchesStatus =
        selectedStatus === "all" ||
        row.status.toLowerCase() === selectedStatus.toLowerCase();
      const matchesQuery =
        !query ||
        row.caseId.toLowerCase().includes(query) ||
        row.location.toLowerCase().includes(query) ||
        row.category.toLowerCase().includes(query);
      return matchesCategory && matchesStatus && matchesQuery;
    });
  }, [complaints, searchQuery, selectedCategory, selectedStatus]);

  const metricCounts = useMemo(() => {
    if (!userEmail) {
      return { total: null, pending: null, urgent: null, resolved: null };
    }
    return {
      total: complaints.length,
      pending: complaints.filter((c) =>
        ["submitted", "pending", "under_review"].includes(c.status.toLowerCase())
      ).length,
      urgent: complaints.filter((c) =>
        ["elevated", "immediate", "high", "critical"].includes(
          c.urgency.toLowerCase()
        )
      ).length,
      resolved: complaints.filter((c) =>
        ["resolved", "closed"].includes(c.status.toLowerCase())
      ).length,
    };
  }, [complaints, userEmail]);

  const handleSignOut = async () => {
    setIsSigningOut(true);
    try {
      const supabase = createClient();
      await supabase.auth.signOut();
      router.push("/committee/login");
      router.refresh();
    } finally {
      setIsSigningOut(false);
    }
  };

  return (
    <div className="space-y-8">
      {userEmail ? (
        <StatusNotice title="Connected as Committee Officer" variant="navy">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <span>
              Authenticated via Supabase Auth as <strong>{userEmail}</strong>.
              {queryError ? ` Query note: ${queryError}` : ""}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={handleSignOut}
              disabled={isSigningOut}
            >
              <LogOut className="h-3.5 w-3.5" />
              {isSigningOut ? "Signing Out..." : "Sign Out"}
            </Button>
          </div>
        </StatusNotice>
      ) : (
        <StatusNotice title="Committee Sign-In Required for Live Records" variant="warning">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <span>
              Supabase is connected, and Row-Level Security blocks anonymous
              reads on <code className="font-mono">complaints</code>. Sign in
              with a committee account to query records.
            </span>
            <LinkButton href="/committee/login" variant="primary" size="sm">
              Sign In
            </LinkButton>
          </div>
        </StatusNotice>
      )}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {SUMMARY_METRICS.map((metric) => {
          const Icon = metric.icon;
          const value = metricCounts[metric.key];
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
                  {value === null ? "\u2014" : value}
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  {userEmail ? "Live Supabase count" : "Requires committee session"}
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
                  Filter controls bound to loaded committee records.
                </p>
              </div>
              <Badge variant="slate">
                {filteredComplaints.length} Record
                {filteredComplaints.length === 1 ? "" : "s"}
              </Badge>
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
                <tbody className="divide-y divide-slate-100">
                  {filteredComplaints.length > 0 ? (
                    filteredComplaints.map((row) => (
                      <tr key={row.id} className="hover:bg-slate-50/70">
                        <td className="px-6 py-4 font-mono text-xs font-semibold text-navy-900">
                          {row.caseId}
                        </td>
                        <td className="px-6 py-4 text-slate-800">{row.category}</td>
                        <td className="px-6 py-4 text-slate-600">{row.location}</td>
                        <td className="px-6 py-4">
                          <Badge variant="outline">{row.urgency}</Badge>
                        </td>
                        <td className="px-6 py-4">
                          <Badge variant="navy">{row.status}</Badge>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={5} className="px-6 py-14 text-center">
                        <div className="mx-auto flex max-w-sm flex-col items-center space-y-2.5">
                          <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-navy-50 text-navy-800">
                            <Inbox className="h-6 w-6" />
                          </span>
                          <p className="text-sm font-semibold text-slate-900">
                            {userEmail
                              ? "No matching complaints found"
                              : "Sign in to load committee records"}
                          </p>
                          <p className="text-xs leading-relaxed text-slate-500">
                            Active filters:{" "}
                            <span className="font-mono text-slate-700">
                              {selectedCategory} / {selectedStatus}
                            </span>
                            {searchQuery ? ` / "${searchQuery}"` : ""}.
                          </p>
                        </div>
                      </td>
                    </tr>
                  )}
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
                Supabase Status
              </span>
            </div>
            <CardTitle className="mt-2">Connected Integration</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm text-slate-600">
            <div className="rounded-xl border border-slate-200 bg-white p-3.5">
              <p className="font-semibold text-slate-900">
                1. Client &amp; SSR Auth
              </p>
              <p className="mt-1 text-xs leading-relaxed">
                Configured in <code className="font-mono">src/lib/supabase/</code>{" "}
                with session refresh in <code className="font-mono">src/proxy.ts</code>.
              </p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-3.5">
              <p className="font-semibold text-slate-900">
                2. Row-Level Security Active
              </p>
              <p className="mt-1 text-xs leading-relaxed">
                Detected RLS protection on <code className="font-mono">complaints</code>,{" "}
                <code className="font-mono">committee_members</code>, and{" "}
                <code className="font-mono">audit_logs</code>.
              </p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-3.5">
              <div className="flex items-center gap-1.5 font-semibold text-slate-900">
                <Filter className="h-3.5 w-3.5 text-navy-700" />
                3. Schema Mapping Ready
              </div>
              <p className="mt-1 text-xs leading-relaxed">
                Share your SQL column definitions to bind{" "}
                <code className="font-mono">/report</code> inserts and{" "}
                <code className="font-mono">/track</code> Case ID lookups.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
