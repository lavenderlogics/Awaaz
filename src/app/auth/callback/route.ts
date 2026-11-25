import type { EmailOtpType } from "@supabase/supabase-js";
import { NextResponse } from "next/server";
import { isSupabaseConfigured } from "@/lib/supabase/config";
import { createClient } from "@/lib/supabase/server";

function sanitizeRedirectPath(rawNext: string | null): string {
  if (!rawNext || !rawNext.startsWith("/") || rawNext.startsWith("//")) {
    return "/committee/dashboard";
  }
  return rawNext;
}

/** Handles Supabase email verification / PKCE callbacks and sets the session cookie. */
export async function GET(request: Request) {
  const requestUrl = new URL(request.url);
  const origin = requestUrl.origin;
  const code = requestUrl.searchParams.get("code");
  const tokenHash = requestUrl.searchParams.get("token_hash");
  const type = requestUrl.searchParams.get("type") as EmailOtpType | null;
  const nextPath = sanitizeRedirectPath(requestUrl.searchParams.get("next"));

  if (!isSupabaseConfigured()) {
    return NextResponse.redirect(
      `${origin}/committee/login?error=${encodeURIComponent(
        "Supabase environment variables are not configured."
      )}`
    );
  }

  const supabase = await createClient();

  if (code) {
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (!error) {
      return NextResponse.redirect(`${origin}${nextPath}`);
    }
    return NextResponse.redirect(
      `${origin}/committee/login?error=${encodeURIComponent(error.message)}`
    );
  }

  if (tokenHash && type) {
    const { error } = await supabase.auth.verifyOtp({ token_hash: tokenHash, type });
    if (!error) {
      return NextResponse.redirect(`${origin}${nextPath}`);
    }
    return NextResponse.redirect(
      `${origin}/committee/login?error=${encodeURIComponent(error.message)}`
    );
  }

  return NextResponse.redirect(
    `${origin}/committee/login?error=${encodeURIComponent(
      "Invalid or expired email verification link. Please sign in or request a new link."
    )}`
  );
}
