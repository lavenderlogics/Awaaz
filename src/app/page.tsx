import {
  ArrowRight,
  CheckCircle2,
  ClipboardList,
  EyeOff,
  FileSearch,
  Lock,
  Shield,
  ShieldCheck,
  Users,
} from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { LinkButton } from "@/components/ui/Button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/Card";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { StatusNotice } from "@/components/ui/StatusNotice";

const ARCHITECTURE_PILLARS = [
  {
    icon: EyeOff,
    title: "Minimal Identity Intake",
    description:
      "The student reporting flow is structured so complaints can be filed without collecting names, roll numbers, or personal phone numbers.",
  },
  {
    icon: FileSearch,
    title: "Case-ID Status Tracking",
    description:
      "Designed around a standalone reference Case ID so students can follow committee review stages without maintaining a student account.",
  },
  {
    icon: Lock,
    title: "Role-Separated Committee Access",
    description:
      "A dedicated login and triage dashboard separates public reporting routes from authorized anti-ragging committee workflows.",
  },
];

const WORKFLOW_STEPS = [
  {
    step: "01",
    title: "Document the Incident",
    description:
      "Select the category, campus location, date, and factual description using the structured anonymous intake form.",
  },
  {
    step: "02",
    title: "Retain Your Case ID",
    description:
      "Once backend persistence is connected, each submission will issue a unique Case ID for follow-up status checks.",
  },
  {
    step: "03",
    title: "Committee Review & Updates",
    description:
      "Authorized campus committee officers review queued reports, initiate action, and post status updates by Case ID.",
  },
];

export default function HomePage() {
  return (
    <div>
      {/* Hero Section */}
      <section className="relative overflow-hidden border-b border-slate-200 bg-navy-hero">
        <div className="bg-cyber-grid pointer-events-none absolute inset-0 opacity-70" />
        <div className="relative mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-24 lg:px-8">
          <div className="grid items-center gap-12 lg:grid-cols-12">
            <div className="space-y-6 lg:col-span-7">
              <div className="flex flex-wrap items-center gap-2.5">
                <Badge variant="navy">
                  <ShieldCheck className="h-3.5 w-3.5" />
                  Campus Anti-Ragging &amp; Safety Platform
                </Badge>
                <Badge variant="outline">Hackathon Setup v0.1</Badge>
              </div>

              <h1 className="text-4xl font-bold tracking-tight text-slate-950 sm:text-5xl lg:leading-[1.12]">
                Speak up safely. Report campus ragging without fear.
              </h1>

              <p className="max-w-xl text-base leading-relaxed text-slate-600 sm:text-lg">
                Awaaz gives college students a structured, low-friction way to
                report ragging or harassment anonymously and follow committee
                progress through a dedicated Case ID workflow.
              </p>

              <div className="flex flex-wrap items-center gap-3.5 pt-1">
                <LinkButton href="/report" variant="primary" size="lg">
                  Submit Anonymous Report
                  <ArrowRight className="h-4 w-4" />
                </LinkButton>
                <LinkButton href="/track" variant="outline" size="lg">
                  Track Case Status
                </LinkButton>
              </div>

              <p className="text-xs leading-relaxed text-slate-500">
                Current scope: Initial Next.js frontend architecture. Supabase
                database, authentication, and backend security controls will be
                integrated in the next phase.
              </p>
            </div>

            <div className="lg:col-span-5">
              <Card className="border-navy-700/15 bg-white/95 shadow-lg shadow-navy-950/5">
                <CardHeader className="border-b border-slate-100 pb-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                      <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-navy-900 text-white">
                        <Shield className="h-4 w-4" />
                      </span>
                      <div>
                        <CardTitle className="text-base">
                          Platform Architecture
                        </CardTitle>
                        <p className="text-xs text-slate-500">
                          Initial Route &amp; UI Overview
                        </p>
                      </div>
                    </div>
                    <Badge variant="amber">UI Ready</Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3.5 pt-5">
                  <div className="flex items-start justify-between gap-3 rounded-xl border border-slate-200 bg-slate-50/70 p-3.5">
                    <div className="flex items-start gap-3">
                      <ClipboardList className="mt-0.5 h-4 w-4 text-navy-700" />
                      <div>
                        <p className="text-sm font-semibold text-slate-900">
                          Anonymous Intake Form
                        </p>
                        <p className="text-xs text-slate-600">
                          Structured incident reporting at /report
                        </p>
                      </div>
                    </div>
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-navy-700" />
                  </div>

                  <div className="flex items-start justify-between gap-3 rounded-xl border border-slate-200 bg-slate-50/70 p-3.5">
                    <div className="flex items-start gap-3">
                      <FileSearch className="mt-0.5 h-4 w-4 text-navy-700" />
                      <div>
                        <p className="text-sm font-semibold text-slate-900">
                          Case Reference Lookup
                        </p>
                        <p className="text-xs text-slate-600">
                          Lifecycle tracking shell at /track
                        </p>
                      </div>
                    </div>
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-navy-700" />
                  </div>

                  <div className="flex items-start justify-between gap-3 rounded-xl border border-slate-200 bg-slate-50/70 p-3.5">
                    <div className="flex items-start gap-3">
                      <Users className="mt-0.5 h-4 w-4 text-navy-700" />
                      <div>
                        <p className="text-sm font-semibold text-slate-900">
                          Committee Triage Workspace
                        </p>
                        <p className="text-xs text-slate-600">
                          Auth &amp; queue views at /committee/*
                        </p>
                      </div>
                    </div>
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-navy-700" />
                  </div>

                  <StatusNotice
                    title="Supabase Client &amp; Auth Connected"
                    variant="info"
                  >
                    Committee authentication is wired via Supabase. Student
                    report submission and Case ID lookup queries are ready to
                    bind once table column definitions are mapped.
                  </StatusNotice>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* Design Pillars */}
      <section className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
        <SectionHeader
          eyebrow="Security-Oriented Design"
          title="Built to lower reporting barriers for students"
          subtitle="Every route separates student intake from committee review so campuses can adopt a transparent, accountable process."
        />

        <div className="mt-10 grid gap-6 md:grid-cols-3">
          {ARCHITECTURE_PILLARS.map((pillar) => {
            const Icon = pillar.icon;
            return (
              <Card key={pillar.title} interactive>
                <CardHeader>
                  <span className="mb-3 flex h-11 w-11 items-center justify-center rounded-xl bg-navy-50 text-navy-800">
                    <Icon className="h-5 w-5" />
                  </span>
                  <CardTitle>{pillar.title}</CardTitle>
                  <CardDescription>{pillar.description}</CardDescription>
                </CardHeader>
              </Card>
            );
          })}
        </div>
      </section>

      {/* Workflow Section */}
      <section className="border-y border-slate-200 bg-slate-50/70">
        <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
          <SectionHeader
            eyebrow="Reporting Flow"
            title="How Awaaz is structured to work"
            subtitle="A straightforward three-stage workflow connecting student reports with campus anti-ragging committees."
            align="center"
          />

          <div className="mt-12 grid gap-6 md:grid-cols-3">
            {WORKFLOW_STEPS.map((item) => (
              <Card key={item.step} className="bg-white">
                <CardHeader>
                  <span className="inline-flex w-fit rounded-lg bg-navy-900 px-2.5 py-1 font-mono text-xs font-semibold text-white">
                    STEP {item.step}
                  </span>
                  <CardTitle className="mt-4">{item.title}</CardTitle>
                  <CardDescription>{item.description}</CardDescription>
                </CardHeader>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Portal Quick Links */}
      <section className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
        <div className="grid gap-6 lg:grid-cols-2">
          <Card className="border-navy-700/20 bg-gradient-to-br from-white to-navy-50/60">
            <CardHeader>
              <Badge variant="navy" className="w-fit">
                For Students
              </Badge>
              <CardTitle className="mt-3 text-xl">
                Report an incident or check your Case ID
              </CardTitle>
              <CardDescription>
                Access the structured complaint form or preview how Case ID
                status tracking works across review stages.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-3">
              <LinkButton href="/report" variant="primary" size="md">
                Open Report Form
              </LinkButton>
              <LinkButton href="/track" variant="outline" size="md">
                Track a Case
              </LinkButton>
            </CardContent>
          </Card>

          <Card className="border-slate-200 bg-gradient-to-br from-white to-slate-50">
            <CardHeader>
              <Badge variant="slate" className="w-fit">
                For Campus Committees
              </Badge>
              <CardTitle className="mt-3 text-xl">
                Authorized Anti-Ragging Committee Portal
              </CardTitle>
              <CardDescription>
                Inspect the committee sign-in experience and review queue layout
                prepared for upcoming Supabase Auth integration.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-3">
              <LinkButton href="/committee/login" variant="secondary" size="md">
                Committee Login
              </LinkButton>
              <LinkButton href="/about" variant="outline" size="md">
                Read About Awaaz
              </LinkButton>
            </CardContent>
          </Card>
        </div>
      </section>
    </div>
  );
}
