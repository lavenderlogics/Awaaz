import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import { createAdminApprovalToken } from "@/lib/security/approval-tokens";

export interface AdminNotificationResult {
  notifiedAdminCount: number;
  emailSent: boolean;
  emailConfigured: boolean;
  reason?: string;
}

function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/**
 * Sends a single-use, HMAC-signed authorization confirmation email to active committee
 * admins whenever a new committee applicant registers.
 */
export async function notifyAdminsOfPendingApplicant(
  admin: SupabaseClient,
  params: {
    origin: string;
    applicantUserId: string;
    applicantEmail: string;
    applicantName: string;
  }
): Promise<AdminNotificationResult> {
  const resendApiKey = process.env.RESEND_API_KEY?.trim();
  const fromEmail =
    process.env.RESEND_FROM_EMAIL?.trim() ||
    "Awaaz Committee Security <onboarding@resend.dev>";

  const { data: adminRows } = await admin
    .from("committee_members")
    .select("user_id")
    .eq("role", "admin")
    .eq("is_active", true);

  const adminIds = new Set((adminRows ?? []).map((r) => r.user_id));
  const recipientAdmins: Array<{ userId: string; email: string }> = [];

  if (adminIds.size > 0) {
    const { data: usersPage } = await admin.auth.admin.listUsers({
      page: 1,
      perPage: 200,
    });
    for (const user of usersPage?.users ?? []) {
      if (adminIds.has(user.id) && user.email) {
        recipientAdmins.push({ userId: user.id, email: user.email });
      }
    }
  }

  const overrideEmail = process.env.ADMIN_NOTIFICATION_EMAIL?.trim();
  if (
    overrideEmail &&
    !recipientAdmins.some(
      (a) => a.email.toLowerCase() === overrideEmail.toLowerCase()
    )
  ) {
    const fallbackAdminId =
      recipientAdmins[0]?.userId ?? Array.from(adminIds)[0] ?? "";
    if (fallbackAdminId) {
      recipientAdmins.push({ userId: fallbackAdminId, email: overrideEmail });
    }
  }

  if (!resendApiKey) {
    return {
      notifiedAdminCount: recipientAdmins.length,
      emailSent: false,
      emailConfigured: false,
      reason:
        "RESEND_API_KEY is not configured; applicant queued in dashboard Pending Approvals.",
    };
  }

  if (recipientAdmins.length === 0) {
    return {
      notifiedAdminCount: 0,
      emailSent: false,
      emailConfigured: true,
      reason: "No active admin email addresses found.",
    };
  }

  let sentCount = 0;
  let lastError: string | undefined;

  for (const target of recipientAdmins) {
    try {
      const [approveMemberToken, approveAdminToken, rejectToken] =
        await Promise.all([
          createAdminApprovalToken({
            applicantUserId: params.applicantUserId,
            applicantEmail: params.applicantEmail,
            applicantName: params.applicantName,
            action: "approve_member",
            adminMemberId: target.userId,
          }),
          createAdminApprovalToken({
            applicantUserId: params.applicantUserId,
            applicantEmail: params.applicantEmail,
            applicantName: params.applicantName,
            action: "approve_admin",
            adminMemberId: target.userId,
          }),
          createAdminApprovalToken({
            applicantUserId: params.applicantUserId,
            applicantEmail: params.applicantEmail,
            applicantName: params.applicantName,
            action: "reject",
            adminMemberId: target.userId,
          }),
        ]);

      const approveOfficerUrl = `${params.origin}/committee/approve?token=${encodeURIComponent(approveMemberToken)}`;
      const approveAdminUrl = `${params.origin}/committee/approve?token=${encodeURIComponent(approveAdminToken)}`;
      const rejectUrl = `${params.origin}/committee/approve?token=${encodeURIComponent(rejectToken)}`;
      const dashboardUrl = `${params.origin}/committee/dashboard`;

      const safeName = escapeHtml(params.applicantName);
      const safeEmail = escapeHtml(params.applicantEmail);

      const html = `
        <div style="font-family:system-ui,-apple-system,sans-serif;max-width:560px;margin:0 auto;padding:24px;color:#0f172a;border:1px solid #e2e8f0;border-radius:12px;">
          <h2 style="margin:0 0 8px;color:#0f294a;">Awaaz Committee Access Request</h2>
          <p style="margin:0 0 16px;font-size:14px;color:#475569;">
            A new user has registered for committee portal access and requires your authorization before accessing any encrypted complaints.
          </p>
          <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 16px;margin-bottom:20px;font-size:13px;">
            <p style="margin:4px 0;"><strong>Full Name:</strong> ${safeName}</p>
            <p style="margin:4px 0;"><strong>Email:</strong> ${safeEmail}</p>
            <p style="margin:4px 0;"><strong>User ID:</strong> <code>${escapeHtml(params.applicantUserId)}</code></p>
          </div>
          <p style="margin:0 0 12px;font-size:13px;font-weight:600;">Choose an action (single-use links, expire in 48h):</p>
          <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px;">
            <a href="${approveOfficerUrl}" style="display:inline-block;padding:10px 16px;background:#0f294a;color:#ffffff;text-decoration:none;border-radius:8px;font-size:13px;font-weight:600;">Approve as Officer</a>
            <a href="${approveAdminUrl}" style="display:inline-block;padding:10px 16px;background:#047857;color:#ffffff;text-decoration:none;border-radius:8px;font-size:13px;font-weight:600;">Approve as Admin</a>
            <a href="${rejectUrl}" style="display:inline-block;padding:10px 16px;background:#b91c1c;color:#ffffff;text-decoration:none;border-radius:8px;font-size:13px;font-weight:600;">Reject Request</a>
          </div>
          <p style="margin:0;font-size:12px;color:#64748b;">
            Or manage pending approvals directly inside <a href="${dashboardUrl}">Committee Dashboard</a>.
          </p>
        </div>
      `;

      const res = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${resendApiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: fromEmail,
          to: [target.email],
          subject: `Awaaz Committee Approval Needed: ${params.applicantName}`,
          html,
        }),
      });

      if (res.ok) {
        sentCount += 1;
      } else {
        const errText = await res.text();
        lastError = `Resend HTTP ${res.status}: ${errText.slice(0, 120)}`;
      }
    } catch (err) {
      lastError = err instanceof Error ? err.message : "Failed to send email.";
    }
  }

  return {
    notifiedAdminCount: sentCount,
    emailSent: sentCount > 0,
    emailConfigured: true,
    ...(sentCount === 0 && lastError ? { reason: lastError } : {}),
  };
}
