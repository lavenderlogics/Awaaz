import Link from "next/link";
import type { AnchorHTMLAttributes, ButtonHTMLAttributes, ReactNode } from "react";

type ButtonVariant = "primary" | "secondary" | "outline" | "ghost";
type ButtonSize = "sm" | "md" | "lg";

const BASE_CLASSES =
  "inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-navy-700 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 cursor-pointer";

const VARIANT_CLASSES: Record<ButtonVariant, string> = {
  primary:
    "bg-gradient-to-b from-navy-800 to-navy-950 text-white shadow-sm hover:from-navy-700 hover:to-navy-900 border border-navy-900",
  secondary:
    "bg-navy-50 text-navy-900 hover:bg-navy-100 border border-navy-700/15",
  outline:
    "bg-white text-slate-800 hover:bg-slate-50 hover:text-navy-900 border border-slate-300 shadow-2xs",
  ghost: "bg-transparent text-slate-700 hover:bg-slate-100 hover:text-navy-900",
};

const SIZE_CLASSES: Record<ButtonSize, string> = {
  sm: "h-9 px-3.5 text-sm",
  md: "h-10.5 px-4.5 text-sm",
  lg: "h-12 px-6 text-base",
};

export function getButtonClasses(
  variant: ButtonVariant = "primary",
  size: ButtonSize = "md",
  className = ""
): string {
  return `${BASE_CLASSES} ${VARIANT_CLASSES[variant]} ${SIZE_CLASSES[size]} ${className}`;
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  children: ReactNode;
}

/** Standard action button using the Awaaz navy design system. */
export function Button({
  variant = "primary",
  size = "md",
  className = "",
  type = "button",
  children,
  ...props
}: ButtonProps) {
  return (
    <button
      type={type}
      className={getButtonClasses(variant, size, className)}
      {...props}
    >
      {children}
    </button>
  );
}

interface LinkButtonProps
  extends Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "href"> {
  href: string;
  variant?: ButtonVariant;
  size?: ButtonSize;
  children: ReactNode;
}

/** Next.js navigation link styled as a button. */
export function LinkButton({
  href,
  variant = "primary",
  size = "md",
  className = "",
  children,
  ...props
}: LinkButtonProps) {
  return (
    <Link
      href={href}
      className={getButtonClasses(variant, size, className)}
      {...props}
    >
      {children}
    </Link>
  );
}
