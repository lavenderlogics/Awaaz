import type { ReactNode } from "react";

type BadgeVariant = "navy" | "slate" | "outline" | "amber" | "emerald";

interface BadgeProps {
  children: ReactNode;
  variant?: BadgeVariant;
  className?: string;
}

const VARIANT_CLASSES: Record<BadgeVariant, string> = {
  navy: "bg-navy-100 text-navy-900 border-navy-700/15",
  slate: "bg-slate-100 text-slate-700 border-slate-200",
  outline: "bg-white text-navy-900 border-slate-300",
  amber: "bg-amber-50 text-amber-800 border-amber-200",
  emerald: "bg-emerald-50 text-emerald-800 border-emerald-200",
};

/** Compact status or category label badge. */
export function Badge({
  children,
  variant = "navy",
  className = "",
}: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold tracking-wide ${VARIANT_CLASSES[variant]} ${className}`}
    >
      {children}
    </span>
  );
}
