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
    "Learn about Awaaz, its zero-knowledge cryptographic architecture, technology stack, and live committee security workflow.",
};

const STACK_ITEMS = [
  {
    icon: Layers,
    name: "Next.js App Router & React",
    detail: "Modular routing and API handlers across student intake, Case ID tracking, and committee triage.",
  },
  {
    icon: Code2,
    name: "TypeScript & Web Crypto API",
    detail: "Strict type safety paired with browser-native AES-256-GCM, RSA-OAEP-256, 2-of-N Shamir sharing, and IndexedDB.",
  },
  {
    icon: Database,
    name: "Supabase & Hash-Chained Audit",
    detail: "PostgreSQL ciphertext persistence, Supabase Auth for committee officers, private evidence buckets, and SHA-256 audit logs.",
  },
];

const ARCHITECTURE_MODULES = [
  {
    phase: "Browser-Side Complaint & Evidence Encryption",
    status: "Live",
    items: [
      "Complaints encrypted in-browser with AES-256-GCM bound to complaint UUID AAD",
      "DEK split via 2-of-N Shamir Secret Sharing over GF(256) and wrapped with committee RSA-OAEP-256 keys",
      "AWZ1 encrypted evidence blobs and SHA-256 hashed Case ID / Recovery Secret credentials",
    ],
  },
  {
    phase: "Threshold Committee Unlock & Audit Trail",
    status: "Live",
    items: [
      "Non-extractable RSA-OAEP private CryptoKeys persisted strictly inside browser IndexedDB",
      "Co-approver encrypted share forwarding and in-browser AES-256 key reconstruction",
      "Supabase Auth with committee role verification and tamper-evident SHA-256 audit logs",
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
                  Zero-Knowledge Security Guarantee
                </CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-3 text-sm leading-relaxed text-slate-600">
              <p>
                Awaaz is{" "}
                <strong className="text-slate-900">fully operational end-to-end</strong>{" "}
                with live Supabase PostgreSQL storage, committee authentication,
                and browser-native Web Crypto encryption.
              </p>
              <p>
                Plaintext complaint narratives, raw evidence files, committee
                private keys, decrypted Shamir shares, and reconstructed AES-256
                keys never leave authorized browsers.
              </p>
            </CardContent>
          </Card>
        </div>

        <div>
          <SectionHeader
            eyebrow="Technology"
            title="Core Platform Stack"
            subtitle="Production cryptographic primitives paired with PostgreSQL persistence and strict API boundaries."
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
            eyebrow="Security Controls"
            title="Implemented Cryptographic Architecture"
            subtitle="Every protection below is active across student complaint intake and committee dashboard decryption."
          />
          <div className="mt-8 grid gap-6 md:grid-cols-2">
            {ARCHITECTURE_MODULES.map((group) => (
              <Card key={group.phase}>
                <CardHeader className="border-b border-slate-100">
                  <div className="flex items-center justify-between">
                    <CardTitle className="flex items-center gap-2 text-base">
                      {group.status === "Live" ? (
                        <Shield className="h-4 w-4 text-navy-700" />
                      ) : (
                        <Workflow className="h-4 w-4 text-slate-500" />
                      )}
                      {group.phase}
                    </CardTitle>
                    <span className="rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-semibold text-emerald-800">
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

        <StatusNotice title="Full Backend &amp; Cryptographic Pipeline Active" variant="navy">
          All core routes (/, /report, /track, /committee/login,
          /committee/dashboard, /about) are wired to live Supabase PostgreSQL
          tables, private encrypted evidence buckets, SHA-256 audit logging, and
          2-of-N browser-side threshold decryption.
        </StatusNotice>
      </section>
    </div>
  );
}
