import type { Metadata } from "next";
import {
  Code2,
  Database,
  Layers,
  Shield,
  ShieldCheck,
  Workflow,
} from "lucide-react";
import { LinkButton } from "@/components/ui/Button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { StatusNotice } from "@/components/ui/StatusNotice";

export const metadata: Metadata = {
  title: "About Awaaz",
  description:
    "Learn about the Awaaz cybersecurity hackathon project, its mission, technology stack, and planned roadmap.",
};

const STACK_ITEMS = [
  {
    icon: Layers,
    name: "Next.js App Router & React",
    detail: "Modular routing across student intake, case tracking, and committee views.",
  },
  {
    icon: Code2,
    name: "TypeScript & Tailwind CSS",
    detail: "Strict type safety paired with a clean navy-and-white cybersecurity UI system.",
  },
  {
    icon: Database,
    name: "Supabase (Upcoming Phase)",
    detail: "Planned for PostgreSQL persistence, committee authentication, and Row-Level Security.",
  },
];

const ROADMAP_PHASES = [
  {
    phase: "Phase 1 — Current Setup",
    status: "Completed",
    items: [
      "Next.js App Router, TypeScript, and Tailwind CSS architecture",
      "Reusable UI component library, responsive Navbar, and Footer",
      "All six core pages (/ , /report, /track, /committee/login, /committee/dashboard, /about)",
    ],
  },
  {
    phase: "Phase 2 — Backend & Security Integration",
    status: "Planned",
    items: [
      "Connect Supabase database schema for reports and Case ID status timelines",
      "Configure Supabase Auth and Row-Level Security for committee roles",
      "Implement server-side validation, rate limiting, and metadata minimization",
    ],
  },
];

export default function AboutPage() {
  return (
    <div>
      <PageHeader
        eyebrow="About the Project"
        title="Why Awaaz Exists"
        description="A cybersecurity hackathon initiative focused on helping college students report ragging and harassment without fear of retaliation."
        badgeText="Hackathon Project"
        actions={
          <LinkButton href="/report" variant="primary" size="md">
            View Report Form
          </LinkButton>
        }
      />

      <section className="mx-auto max-w-6xl space-y-16 px-4 py-12 sm:px-6 sm:py-16 lg:px-8">
        <div className="grid gap-8 lg:grid-cols-12">
          <div className="space-y-4 lg:col-span-7">
            <SectionHeader
              eyebrow="Mission"
              title="Closing the gap between campus incidents and safe reporting"
              subtitle="Many students stay silent about ragging or harassment because traditional channels require exposing their identity early in the process."
            />
            <p className="text-sm leading-relaxed text-slate-600 sm:text-base">
              Awaaz is designed to separate incident intake from student
              identity while still giving campus anti-ragging committees
              actionable, structured context and giving reporters a transparent
              Case ID workflow to monitor progress.
            </p>
          </div>

          <Card subtle className="lg:col-span-5">
            <CardHeader>
              <div className="flex items-center gap-2 text-navy-800">
                <ShieldCheck className="h-5 w-5" />
                <CardTitle className="text-base">
                  Honest Scope Statement
                </CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-3 text-sm leading-relaxed text-slate-600">
              <p>
                This repository currently contains only the{" "}
                <strong className="text-slate-900">initial frontend setup</strong>.
              </p>
              <p>
                Backend persistence, authentication, and cryptographic or
                storage protections are intentionally left for the upcoming
                Supabase integration phase and are not simulated with fake data.
              </p>
            </CardContent>
          </Card>
        </div>

        <div>
          <SectionHeader
            eyebrow="Technology"
            title="Core Platform Stack"
            subtitle="Lean, maintainable tools chosen for rapid hackathon iteration and clean production scalability."
          />
          <div className="mt-8 grid gap-6 md:grid-cols-3">
            {STACK_ITEMS.map((item) => {
              const Icon = item.icon;
              return (
                <Card key={item.name} interactive>
                  <CardHeader>
                    <span className="mb-3 flex h-10 w-10 items-center justify-center rounded-xl bg-navy-50 text-navy-800">
                      <Icon className="h-5 w-5" />
                    </span>
                    <CardTitle>{item.name}</CardTitle>
                    <CardDescription>{item.detail}</CardDescription>
                  </CardHeader>
                </Card>
              );
            })}
          </div>
        </div>

        <div>
          <SectionHeader
            eyebrow="Roadmap"
            title="Development Milestones"
            subtitle="Clear separation between the initial UI foundation and upcoming backend security work."
          />
          <div className="mt-8 grid gap-6 md:grid-cols-2">
            {ROADMAP_PHASES.map((group) => (
              <Card key={group.phase}>
                <CardHeader className="border-b border-slate-100">
                  <div className="flex items-center justify-between">
                    <CardTitle className="flex items-center gap-2 text-base">
                      {group.status === "Completed" ? (
                        <Shield className="h-4 w-4 text-navy-700" />
                      ) : (
                        <Workflow className="h-4 w-4 text-slate-500" />
                      )}
                      {group.phase}
                    </CardTitle>
                    <span className="rounded-full bg-navy-50 px-2.5 py-0.5 text-xs font-semibold text-navy-900">
                      {group.status}
                    </span>
                  </div>
                </CardHeader>
                <CardContent className="pt-4">
                  <ul className="space-y-2.5 text-sm text-slate-600">
                    {group.items.map((point) => (
                      <li key={point} className="flex items-start gap-2.5">
                        <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-navy-700" />
                        <span>{point}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>

        <StatusNotice title="Ready for Next Milestone" variant="navy">
          Once Supabase is provisioned, the next step is wiring server actions /
          route handlers, Row-Level Security policies, and Case ID generation
          into the existing components.
        </StatusNotice>
      </section>
    </div>
  );
}
