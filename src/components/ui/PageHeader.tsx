import type { ReactNode } from "react";
import { Badge } from "@/components/ui/Badge";

interface PageHeaderProps {
  eyebrow: string;
  title: string;
  description: string;
  badgeText?: string;
  actions?: ReactNode;
}

/** Shared top banner for interior pages with subtle navy-tinted gradient. */
export function PageHeader({
  eyebrow,
  title,
  description,
  badgeText,
  actions,
}: PageHeaderProps) {
  return (
    <section className="relative overflow-hidden border-b border-slate-200 bg-navy-hero">
      <div className="bg-cyber-grid pointer-events-none absolute inset-0 opacity-60" />
      <div className="relative mx-auto max-w-6xl px-4 py-12 sm:px-6 sm:py-16 lg:px-8">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-2xl space-y-4">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="text-xs font-semibold tracking-[0.16em] text-navy-700 uppercase">
                {eyebrow}
              </span>
              {badgeText ? <Badge variant="navy">{badgeText}</Badge> : null}
            </div>
            <h1 className="text-3xl font-bold tracking-tight text-slate-950 sm:text-4xl">
              {title}
            </h1>
            <p className="text-base leading-relaxed text-slate-600 sm:text-lg">
              {description}
            </p>
          </div>
          {actions ? (
            <div className="flex flex-wrap items-center gap-3">{actions}</div>
          ) : null}
        </div>
      </div>
    </section>
  );
}
