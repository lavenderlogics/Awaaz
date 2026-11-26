import {
  ArrowRight,
  CheckCircle2,
  ClipboardList,
  EyeOff,
  FileSearch,
  KeyRound,
  Lock,
  PhoneCall,
  Shield,
  ShieldAlert,
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
    title: "Zero-Identity Browser Intake",
    description:
      "Complaints and attached evidence are encrypted locally with AES-256-GCM inside your browser without requiring student login, names, or roll numbers.",
  },
  {
    icon: FileSearch,
    title: "Hash-Only Case Tracking",
    description:
      "Your Case ID and Recovery Secret are stored solely as SHA-256 hashes so you can track review progress and upload encrypted follow-up evidence anonymously.",
  },
  {
    icon: Lock,
    title: "2-of-N Committee Threshold",
    description:
      "Decryption keys are split via Shamir Secret Sharing over GF(256). No server admin or single committee officer can ever unlock a complaint alone.",
  },
];

const WORKFLOW_STEPS = [
  {
    step: "01",
    icon: ClipboardList,
    title: "Encrypt & Submit Anonymously",
    description:
      "Document the incident and attach files. Your browser encrypts everything with AES-256-GCM and splits the key across committee public keys before upload.",
  },
  {
    step: "02",
    icon: KeyRound,
    title: "Save Your Case ID & Secret",
    description:
      "Download your local receipt containing your unique Case ID and Recovery Secret (stored only as cryptographic hashes) for private follow-up.",
  },
  {
    step: "03",
    icon: Users,
    title: "Two-Officer Verification & Action",
    description:
      "Two authorized committee officers forward encrypted Shamir shares inside their browsers, decrypt locally, and post Case ID status updates.",
  },
];

const EMERGENCY_CHANNELS = [
  {
    title: "UGC Anti-Ragging Helpline",
    contact: "1800-180-5522",
    href: "tel:18001805522",
    detail: "24x7 toll-free national helpline for immediate ragging intervention.",
  },
  {
    title: "Emergency Police & Medical",
    contact: "112",
    href: "tel:112",
    detail: "Call immediately if anyone faces physical danger or urgent medical risk.",
  },
  {
    title: "Campus Security & Counseling",
    contact: "24x7 Campus Desk",
    href: "/report",
    detail: "Contact your hostel warden or campus security first, then file on Awaaz.",
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
                <Badge variant="outline">Zero-Knowledge Encrypted</Badge>
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
                  Report Anonymously
                  <ArrowRight className="h-4 w-4" />
                </LinkButton>
                <LinkButton href="/track" variant="outline" size="lg">
                  Track Complaint
                </LinkButton>
              </div>

              <div className="flex flex-wrap gap-2 pt-1 text-xs text-slate-600">
                <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-white/90 px-3 py-1 font-medium">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-700" />
                  Zero Student Login
                </span>
                <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-white/90 px-3 py-1 font-medium">
                  <Lock className="h-3.5 w-3.5 text-navy-700" />
                  AES-256-GCM in Browser
                </span>
                <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-white/90 px-3 py-1 font-medium">
                  <KeyRound className="h-3.5 w-3.5 text-navy-700" />
                  2-of-N Shamir Split
                </span>
              </div>

              <p className="text-xs leading-relaxed text-slate-500">
                End-to-end browser security: reports and evidence are encrypted
                in your browser with AES-256-GCM, split via 2-of-N Shamir Secret
                Sharing, and decrypted solely inside authorized officers&apos;
                browsers.
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
                          Zero-Knowledge Security Overview
                        </p>
                      </div>
                    </div>
                    <Badge variant="emerald">Encrypted Live</Badge>
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
                          Browser-side AES-256-GCM &amp; AWZ1 encryption at /report
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
                          Hashed Case ID &amp; Recovery Secret tracking at /track
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
                          IndexedDB keys &amp; 2-of-N share forwarding at /committee/*
                        </p>
                      </div>
                    </div>
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-navy-700" />
                  </div>

                  <StatusNotice
                    title="Supabase Auth, Storage &amp; Audit Connected"
                    variant="info"
                  >
                    Student reports are encrypted inside the browser before
                    reaching PostgreSQL, backed by Supabase Auth, encrypted
                    evidence storage, and SHA-256 hash-chained audit logs.
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
            {WORKFLOW_STEPS.map((item) => {
              const StepIcon = item.icon;
              return (
                <Card key={item.step} className="relative bg-white">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <span className="inline-flex w-fit rounded-lg bg-navy-900 px-2.5 py-1 font-mono text-xs font-semibold text-white">
                        STEP {item.step}
                      </span>
                      <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-navy-50 text-navy-800">
                        <StepIcon className="h-4 w-4" />
                      </span>
                    </div>
                    <CardTitle className="mt-4">{item.title}</CardTitle>
                    <CardDescription>{item.description}</CardDescription>
                  </CardHeader>
                </Card>
              );
            })}
          </div>
        </div>
      </section>

      {/* Emergency Help Section */}
      <section className="mx-auto max-w-6xl px-4 pt-14 sm:px-6 sm:pt-16 lg:px-8">
        <div className="rounded-2xl border border-amber-200 bg-amber-50/60 p-6 sm:p-8">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-start gap-3">
              <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-amber-100 text-amber-800">
                <ShieldAlert className="h-5 w-5" />
              </span>
              <div>
                <p className="text-xs font-semibold tracking-wider text-amber-900 uppercase">
                  Immediate Safety &amp; Emergency Support
                </p>
                <h2 className="mt-0.5 text-lg font-bold text-slate-950 sm:text-xl">
                  Facing active intimidation or physical threat right now?
                </h2>
              </div>
            </div>
            <LinkButton href="/report" variant="outline" size="sm">
              File Anonymous Report
            </LinkButton>
          </div>

          <div className="mt-6 grid gap-4 md:grid-cols-3">
            {EMERGENCY_CHANNELS.map((channel) => (
              <a
                key={channel.title}
                href={channel.href}
                className="block rounded-xl border border-amber-200/80 bg-white p-4 shadow-2xs transition hover:border-amber-300 hover:bg-amber-50/30"
              >
                <div className="flex items-center justify-between gap-2">
                  <p className="text-xs font-semibold tracking-wider text-slate-600 uppercase">
                    {channel.title}
                  </p>
                  <PhoneCall className="h-4 w-4 text-amber-700" />
                </div>
                <p className="mt-1.5 font-mono text-lg font-bold text-navy-950">
                  {channel.contact}
                </p>
                <p className="mt-1 text-xs leading-relaxed text-slate-600">
                  {channel.detail}
                </p>
              </a>
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
                Submit an end-to-end encrypted complaint or check real-time Case
                ID status updates across committee review stages.
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
                Sign in with Supabase Auth to verify keys, forward threshold
                Shamir shares, and decrypt complaints strictly inside your
                browser.
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
