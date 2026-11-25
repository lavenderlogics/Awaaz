import { PhoneCall, Shield } from "lucide-react";
import Link from "next/link";

const STUDENT_LINKS = [
  { label: "Home", href: "/" },
  { label: "Submit Anonymous Report", href: "/report" },
  { label: "Track Case Status", href: "/track" },
  { label: "About Awaaz", href: "/about" },
];

const COMMITTEE_LINKS = [
  { label: "Committee Login", href: "/committee/login" },
  { label: "Committee Dashboard", href: "/committee/dashboard" },
];

/** Global responsive footer with platform links and honest setup status. */
export function Footer() {
  return (
    <footer className="border-t border-slate-200 bg-slate-50/80">
      <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6 lg:px-8">
        <div className="grid gap-10 md:grid-cols-2 lg:grid-cols-4">
          <div className="space-y-3 lg:col-span-2">
            <Link href="/" className="inline-flex items-center gap-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-navy-900 text-white">
                <Shield className="h-4 w-4" />
              </span>
              <span className="font-display text-base font-bold text-navy-950">
                Awaaz
              </span>
            </Link>
            <p className="max-w-md text-sm leading-relaxed text-slate-600">
              A campus safety and anti-ragging reporting platform built for
              students to raise concerns responsibly and track committee review
              progress.
            </p>
            <p className="max-w-md text-xs leading-relaxed text-slate-500">
              Initial frontend architecture only. Backend persistence,
              authentication, and database security policies will be integrated
              with Supabase in the next milestone.
            </p>
          </div>

          <div>
            <h3 className="text-xs font-semibold tracking-wider text-navy-900 uppercase">
              Student Portal
            </h3>
            <ul className="mt-3.5 space-y-2.5">
              {STUDENT_LINKS.map((link) => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-sm text-slate-600 transition-colors hover:text-navy-900"
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <h3 className="text-xs font-semibold tracking-wider text-navy-900 uppercase">
              Committee &amp; Help
            </h3>
            <ul className="mt-3.5 space-y-2.5">
              {COMMITTEE_LINKS.map((link) => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-sm text-slate-600 transition-colors hover:text-navy-900"
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
            <div className="mt-5 rounded-xl border border-slate-200 bg-white p-3 text-xs leading-relaxed text-slate-600">
              <div className="flex items-center gap-1.5 font-semibold text-navy-900">
                <PhoneCall className="h-3.5 w-3.5 text-navy-700" />
                Immediate Danger
              </div>
              <p className="mt-1">
                If you face an active physical threat, contact campus security
                or local emergency services directly.
              </p>
            </div>
          </div>
        </div>

        <div className="mt-10 flex flex-col items-start justify-between gap-3 border-t border-slate-200 pt-6 text-xs text-slate-500 sm:flex-row sm:items-center">
          <p>
            Awaaz &mdash; Cybersecurity Hackathon Project (Initial Setup)
          </p>
          <p>Next.js App Router &middot; TypeScript &middot; Tailwind CSS</p>
        </div>
      </div>
    </footer>
  );
}
