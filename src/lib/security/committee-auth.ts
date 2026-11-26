import "server-only";
import { NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  isServiceRoleConfigured,
  isSupabaseConfigured,
} from "@/lib/supabase/config";
import { createClient } from "@/lib/supabase/server";

export interface CommitteeMemberRecord {
  user_id: string;
  full_name: string;
  role: string;
  public_key: string | null;
  is_active: boolean | null;
}

export type CommitteeAuthResult =
  | {
      ok: true;
      userId: string;
      email: string | null;
      member: CommitteeMemberRecord;
    }
  | { ok: false; response: NextResponse };

/**
 * Verifies the authenticated Supabase Auth user from session cookies and checks
 * active membership in `committee_members`. Never trusts client-supplied roles or IDs.
 */
export async function requireCommitteeMember(): Promise<CommitteeAuthResult> {
  if (!isSupabaseConfigured() || !isServiceRoleConfigured()) {
    return {
      ok: false,
      response: NextResponse.json(
        {
          error:
            "Server Supabase configuration is incomplete (missing service-role or public env vars).",
        },
        { status: 503 }
      ),
    };
  }

  const supabase = await createClient();
  const {
    data: { user },
    error: authError,
  } = await supabase.auth.getUser();

  if (authError || !user) {
    return {
      ok: false,
      response: NextResponse.json(
        { error: "Authentication required." },
        { status: 401 }
      ),
    };
  }

  const admin = createAdminClient();
  const { data: member, error: memberError } = await admin
    .from("committee_members")
    .select("user_id, full_name, role, public_key, is_active")
    .eq("user_id", user.id)
    .maybeSingle();

  if (memberError) {
    return {
      ok: false,
      response: NextResponse.json(
        { error: "Failed to verify committee membership." },
        { status: 500 }
      ),
    };
  }

  if (!member || member.is_active !== true) {
    return {
      ok: false,
      response: NextResponse.json(
        {
          error:
            "Your account is not registered as an active member in committee_members.",
        },
        { status: 403 }
      ),
    };
  }

  return {
    ok: true,
    userId: user.id,
    email: user.email ?? null,
    member: member as CommitteeMemberRecord,
  };
}
