import type { HTMLAttributes, ReactNode } from "react";

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  children: ReactNode;
  interactive?: boolean;
  subtle?: boolean;
}

/** Modern container card with crisp borders and optional hover elevation. */
export function Card({
  children,
  interactive = false,
  subtle = false,
  className = "",
  ...props
}: CardProps) {
  const surface = subtle
    ? "bg-slate-50/75 border-slate-200/90"
    : "bg-white border-slate-200 shadow-xs";
  const hover = interactive
    ? "transition-all duration-200 hover:-translate-y-0.5 hover:border-navy-700/30 hover:shadow-md"
    : "";

  return (
    <div
      className={`rounded-2xl border ${surface} ${hover} ${className}`}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardHeader({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={`p-6 pb-3 ${className}`}>{children}</div>;
}

export function CardTitle({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <h3
      className={`text-lg font-semibold tracking-tight text-slate-900 ${className}`}
    >
      {children}
    </h3>
  );
}

export function CardDescription({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <p className={`mt-1.5 text-sm leading-relaxed text-slate-600 ${className}`}>
      {children}
    </p>
  );
}

export function CardContent({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={`p-6 pt-3 ${className}`}>{children}</div>;
}
