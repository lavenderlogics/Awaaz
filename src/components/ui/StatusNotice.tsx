import { AlertTriangle, CheckCircle2, Info, ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";

type NoticeVariant = "info" | "warning" | "navy" | "success";

interface StatusNoticeProps {
  title: string;
  children: ReactNode;
  variant?: NoticeVariant;
  className?: string;
}

const NOTICE_STYLES: Record<
  NoticeVariant,
  { container: string; iconColor: string; titleColor: string }
> = {
  info: {
    container: "border-navy-700/20 bg-navy-50/70 text-slate-700",
    iconColor: "text-navy-700",
    titleColor: "text-navy-950",
  },
  warning: {
    container: "border-amber-200 bg-amber-50/80 text-amber-900",
    iconColor: "text-amber-700",
    titleColor: "text-amber-950",
  },
  navy: {
    container:
      "border-navy-800/20 bg-gradient-to-r from-navy-50 to-slate-50 text-slate-700",
    iconColor: "text-navy-800",
    titleColor: "text-navy-950",
  },
  success: {
    container: "border-emerald-200 bg-emerald-50/80 text-emerald-900",
    iconColor: "text-emerald-700",
    titleColor: "text-emerald-950",
  },
};

/** Honest system/integration callout banner for UI setup and status notices. */
export function StatusNotice({
  title,
  children,
  variant = "info",
  className = "",
}: StatusNoticeProps) {
  const styles = NOTICE_STYLES[variant];
  const Icon =
    variant === "warning"
      ? AlertTriangle
      : variant === "navy"
        ? ShieldAlert
        : variant === "success"
          ? CheckCircle2
          : Info;

  return (
    <div
      className={`flex gap-3.5 rounded-xl border p-4 text-sm leading-relaxed ${styles.container} ${className}`}
    >
      <Icon className={`mt-0.5 h-5 w-5 shrink-0 ${styles.iconColor}`} />
      <div className="w-full space-y-1">
        <p className={`font-semibold ${styles.titleColor}`}>{title}</p>
        <div>{children}</div>
      </div>
    </div>
  );
}
