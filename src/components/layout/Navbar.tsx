"use client";

import { Lock, Menu, Shield, X } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { LinkButton } from "@/components/ui/Button";
import { NAV_LINKS } from "@/lib/constants";

/** Responsive top navigation bar with mobile menu drawer. */
export function Navbar() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  const isActive = (href: string) =>
    href === "/" ? pathname === "/" : pathname.startsWith(href);

  return (
    <header className="sticky top-0 z-40 border-b border-slate-200/90 bg-white/95 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6 lg:px-8">
        <Link
          href="/"
          className="flex items-center gap-2.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-navy-700 focus-visible:rounded-lg"
          onClick={() => setMobileOpen(false)}
        >
          <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-navy-700 to-navy-950 text-white shadow-sm">
            <Shield className="h-5 w-5" />
          </span>
          <span className="flex flex-col leading-none">
            <span className="font-display text-lg font-bold tracking-tight text-navy-950">
              Awaaz
            </span>
            <span className="text-[11px] font-medium tracking-wider text-slate-500 uppercase">
              Campus Safety
            </span>
          </span>
        </Link>

        <nav
          aria-label="Primary navigation"
          className="hidden items-center gap-1 md:flex"
        >
          {NAV_LINKS.map((item) => {
            const active = isActive(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`rounded-lg px-3.5 py-2 text-sm font-medium transition-colors ${
                  active
                    ? "bg-navy-50 text-navy-900"
                    : "text-slate-600 hover:bg-slate-50 hover:text-navy-900"
                }`}
              >
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="hidden items-center gap-2.5 md:flex">
          <LinkButton href="/committee/login" variant="outline" size="sm">
            <Lock className="h-3.5 w-3.5 text-navy-700" />
            Committee Login
          </LinkButton>
          <LinkButton href="/report" variant="primary" size="sm">
            Submit Report
          </LinkButton>
        </div>

        <button
          type="button"
          className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-slate-200 text-slate-700 transition hover:bg-slate-50 md:hidden"
          onClick={() => setMobileOpen((prev) => !prev)}
          aria-expanded={mobileOpen}
          aria-label={mobileOpen ? "Close navigation menu" : "Open navigation menu"}
        >
          {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>

      {mobileOpen ? (
        <div className="border-t border-slate-200 bg-white px-4 py-4 md:hidden">
          <nav aria-label="Mobile navigation" className="flex flex-col gap-1">
            {NAV_LINKS.map((item) => {
              const active = isActive(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={() => setMobileOpen(false)}
                  className={`rounded-lg px-3.5 py-2.5 text-sm font-medium transition-colors ${
                    active
                      ? "bg-navy-50 text-navy-900"
                      : "text-slate-700 hover:bg-slate-50 hover:text-navy-900"
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>
          <div className="mt-4 flex flex-col gap-2.5 border-t border-slate-100 pt-4">
            <LinkButton
              href="/committee/login"
              variant="outline"
              size="md"
              className="w-full"
              onClick={() => setMobileOpen(false)}
            >
              <Lock className="h-4 w-4 text-navy-700" />
              Committee Login
            </LinkButton>
            <LinkButton
              href="/report"
              variant="primary"
              size="md"
              className="w-full"
              onClick={() => setMobileOpen(false)}
            >
              Submit Report
            </LinkButton>
          </div>
        </div>
      ) : null}
    </header>
  );
}
