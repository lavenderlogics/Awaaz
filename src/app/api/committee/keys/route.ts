import { NextResponse } from "next/server";
import { requireCommitteeMember } from "@/lib/security/committee-auth";
import { isValidRsaPublicKeyPem } from "@/lib/security/crypto";
import { createAdminClient } from "@/lib/supabase/admin";

/** Registers the authenticated committee member's RSA-2048 public key in `committee_members`. */
export async function POST(request: Request) {
  const auth = await requireCommitteeMember();
  if (!auth.ok) {
    return auth.response;
  }

  let body: { publicKeyPem?: unknown };
  try {
    body = (await request.json()) as { publicKeyPem?: unknown };
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  if (
    typeof body.publicKeyPem !== "string" ||
    !isValidRsaPublicKeyPem(body.publicKeyPem.trim())
  ) {
    return NextResponse.json(
      { error: "Please provide a valid RSA public key in PEM (SPKI) format." },
      { status: 400 }
    );
  }

  const admin = createAdminClient();
  const { error } = await admin
    .from("committee_members")
    .update({ public_key: body.publicKeyPem.trim() })
    .eq("user_id", auth.member.user_id);

  if (error) {
    return NextResponse.json(
      { error: `Failed to save public key: ${error.message}` },
      { status: 500 }
    );
  }

  return NextResponse.json({
    ok: true,
    memberId: auth.member.user_id,
  });
}
