import type { Metadata } from "next";
import { ResetPasswordForm } from "@/components/sections/ResetPasswordForm";
import { PageHeader } from "@/components/ui/PageHeader";
import { isSupabaseConfigured } from "@/lib/supabase/config";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = {
  title: "Reset Password",
  description: "Set a new password for your Awaaz committee account.",
};

export default async function ResetPasswordPage() {
  const configured = isSupabaseConfigured();
  let userEmail: string | null = null;

  if (configured) {
    try {
      const supabase = await createClient();
      const {
        data: { user },
      } = await supabase.auth.getUser();
      userEmail = user?.email ?? null;
    } catch {
      userEmail = null;
    }
  }

  return (
    <div>
      <PageHeader
        eyebrow="Account Recovery"
        title="Reset Committee Password"
        description="Complete password recovery after clicking the verification link sent to your email."
        badgeText="Supabase Auth"
      />

      <section className="mx-auto max-w-4xl px-4 py-12 sm:px-6 sm:py-16 lg:px-8">
        <ResetPasswordForm
          hasActiveSession={Boolean(userEmail)}
          userEmail={userEmail}
        />
      </section>
    </div>
  );
}
