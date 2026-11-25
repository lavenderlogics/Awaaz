import type { ReactNode } from "react";

interface SectionHeaderProps {
  eyebrow?: string;
  title: string;
  subtitle?: string;
  align?: "left" | "center";
  action?: ReactNode;
}

/** Consistent section heading block for landing and informational sections. */
export function SectionHeader({
  eyebrow,
  title,
  subtitle,
  align = "left",
  action,
}: SectionHeaderProps) {
  const isCentered = align === "center";

  return (
    <div
      className={`flex flex-col gap-4 ${
        isCentered
          ? "mx-auto max-w-2xl items-center text-center"
          : "sm:flex-row sm:items-end sm:justify-between"
      }`}
    >
      <div className={isCentered ? "space-y-3" : "max-w-2xl space-y-2.5"}>
        {eyebrow ? (
          <p className="text-xs font-semibold tracking-[0.16em] text-navy-700 uppercase">
            {eyebrow}
          </p>
        ) : null}
        <h2 className="text-2xl font-bold tracking-tight text-slate-950 sm:text-3xl">
          {title}
        </h2>
        {subtitle ? (
          <p className="text-base leading-relaxed text-slate-600">{subtitle}</p>
        ) : null}
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}
