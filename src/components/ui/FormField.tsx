import type {
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from "react";

interface FormFieldProps {
  id: string;
  label: string;
  hint?: string;
  required?: boolean;
  error?: string;
  children: ReactNode;
}

const CONTROL_BASE_CLASSES =
  "w-full rounded-xl border border-slate-300 bg-white px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 shadow-2xs transition focus:border-navy-700 focus:outline-none focus:ring-3 focus:ring-navy-700/15 disabled:cursor-not-allowed disabled:bg-slate-50 disabled:text-slate-500";

/** Accessible wrapper for form controls with label, hint, and validation state. */
export function FormField({
  id,
  label,
  hint,
  required = false,
  error,
  children,
}: FormFieldProps) {
  return (
    <div className="space-y-1.5">
      <label
        htmlFor={id}
        className="block text-sm font-medium text-slate-800"
      >
        {label}
        {required ? (
          <span className="ml-1 text-navy-700" aria-hidden="true">
            *
          </span>
        ) : null}
      </label>
      {children}
      {error ? (
        <p className="text-xs font-medium text-red-700" role="alert">
          {error}
        </p>
      ) : hint ? (
        <p className="text-xs leading-relaxed text-slate-500">{hint}</p>
      ) : null}
    </div>
  );
}

export function Input({
  className = "",
  ...props
}: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={`${CONTROL_BASE_CLASSES} ${className}`} {...props} />;
}

export function Textarea({
  className = "",
  ...props
}: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={`${CONTROL_BASE_CLASSES} min-h-32 resize-y ${className}`}
      {...props}
    />
  );
}

export function Select({
  className = "",
  children,
  ...props
}: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={`${CONTROL_BASE_CLASSES} ${className}`} {...props}>
      {children}
    </select>
  );
}
