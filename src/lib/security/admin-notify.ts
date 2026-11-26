import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import nodemailer from "nodemailer";
import { createAdminApprovalToken } from "@/lib/security/approval-tokens";

export const DEFAULT_APPROVER_EMAIL = "agrawalvantika@gmail.com";

export type AdminNotificationRequestType = "new_signup" | "admin_upgrade";

export interface AdminNotificationResult {
  notifiedAdminCount: number;
  targetAdminEmail: string;
  emailSent: boolean;
  emailConfigured: boolean;
  deliveryChannel?: "smtp" | "resend";
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

export function isEmailTransportConfigured(): boolean {
  const hasSmtp = Boolean(
    process.env.SMTP_USER?.trim() && process.env.SMTP_PASS?.trim()
  );
  const hasResend = Boolean(process.env.RESEND_API_KEY?.trim());
  return hasSmtp || hasResend;
}

async function sendEmailViaConfiguredTransport(params: {
  to: string;
  subject: string;
  html: string;
}): Promise<{ ok: true; channel: "smtp" | "resend" } | { ok: false; error: string }> {
  const smtpUser = process.env.SMTP_USER?.trim();
  const smtpHost = process.env.SMTP_HOST?.trim() || "smtp.gmail.com";
  const rawSmtpPass = process.env.SMTP_PASS?.trim() ?? "";
  const smtpPass =
    smtpHost.toLowerCase() === "smtp.gmail.com"
      ? rawSmtpPass.replace(/\s+/g, "")
      : rawSmtpPass;
  const smtpPort = Number.parseInt(process.env.SMTP_PORT?.trim() || "465", 10);

  if (smtpUser && smtpPass) {
    try {
      const transporter = nodemailer.createTransport({
        host: smtpHost,
        port: Number.isFinite(smtpPort) ? smtpPort : 465,
        secure: smtpPort === 465,
        auth: {
          user: smtpUser,
          pass: smtpPass,
        },
      });

      const fromAddress =
        process.env.SMTP_FROM?.trim() || `Awaaz Committee Security <${smtpUser}>`;

      await transporter.sendMail({
        from: fromAddress,
        to: params.to,
        subject: params.subject,
        html: params.html,
      });

      return { ok: true, channel: "smtp" };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : "SMTP delivery failed.",
      };
    }
  }

  const resendApiKey = process.env.RESEND_API_KEY?.trim();
  if (resendApiKey) {
    const fromEmail =
      process.env.RESEND_FROM_EMAIL?.trim() ||
      "Awaaz Committee Security <onboarding@resend.dev>";
    try {
      const res = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${resendApiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: fromEmail,
          to: [params.to],
          subject: params.subject,
          html: params.html,
        }),
      });
      if (res.ok) {
        return { ok: true, channel: "resend" };
      }
      const errText = await res.text();
      return {
        ok: false,
        error: `Resend HTTP ${res.status}: ${errText.slice(0, 140)}`,
      };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : "Resend delivery failed.",
      };
    }
  }

  return {
    ok: false,
    error: "No SMTP or Resend email credentials configured on server.",
  };
}

/**
 * Sends a single-use, HMAC-signed authorization confirmation email to the
 * designated administrator (`agrawalvantika@gmail.com` by default) whenever a new
 * committee applicant signs up or an existing officer requests admin access.
 */
export async function notifyAdminsOfPendingApplicant(
  admin: SupabaseClient,
  params: {
    origin: string;
    applicantUserId: string;
    applicantEmail: string;
    applicantName: string;
    requestType?: AdminNotificationRequestType;
  }
): Promise<AdminNotificationResult> {
  const targetAdminEmail =
    process.env.ADMIN_NOTIFICATION_EMAIL?.trim().toLowerCase() ||
    DEFAULT_APPROVER_EMAIL;
  const requestType = params.requestType ?? "new_signup";

  const { data: adminRows } = await admin
    .from("committee_members")
    .select("user_id")
    .eq("role", "admin")
    .eq("is_active", true);

  const activeAdminIds = (adminRows ?? []).map((r) => r.user_id);
  let targetAdminMemberId = activeAdminIds[0] ?? "";

  if (activeAdminIds.length > 0) {
    const { data: usersPage } = await admin.auth.admin.listUsers({
      page: 1,
      perPage: 200,
    });
    const activeSet = new Set(activeAdminIds);
    const exactMatch = (usersPage?.users ?? []).find(
      (u) =>
        activeSet.has(u.id) &&
        (u.email ?? "").toLowerCase() === targetAdminEmail
    );
    if (exactMatch) {
      targetAdminMemberId = exactMatch.id;
    }
  }

  if (!isEmailTransportConfigured()) {
    return {
      notifiedAdminCount: targetAdminMemberId ? 1 : 0,
      targetAdminEmail,
      emailSent: false,
      emailConfigured: false,
      reason: `Configure SMTP_USER/SMTP_PASS (Gmail App Password) or RESEND_API_KEY so approval emails deliver to ${targetAdminEmail}.`,
    };
  }

  if (!targetAdminMemberId) {
    return {
      notifiedAdminCount: 0,
      targetAdminEmail,
      emailSent: false,
      emailConfigured: true,
      reason: "No active admin account exists in committee_members to sign approval tokens.",
    };
  }

  try {
    const [approveMemberToken, approveAdminToken, rejectToken] =
      await Promise.all([
        requestType === "new_signup"
          ? createAdminApprovalToken({
              applicantUserId: params.applicantUserId,
              applicantEmail: params.applicantEmail,
              applicantName: params.applicantName,
              action: "approve_member",
              adminMemberId: targetAdminMemberId,
            })
          : Promise.resolve(null),
        createAdminApprovalToken({
          applicantUserId: params.applicantUserId,
          applicantEmail: params.applicantEmail,
          applicantName: params.applicantName,
          action: "approve_admin",
          adminMemberId: targetAdminMemberId,
        }),
        createAdminApprovalToken({
          applicantUserId: params.applicantUserId,
          applicantEmail: params.applicantEmail,
          applicantName: params.applicantName,
          action: "reject",
          adminMemberId: targetAdminMemberId,
        }),
      ]);

    const approveOfficerUrl = approveMemberToken
      ? `${params.origin}/committee/approve?token=${encodeURIComponent(approveMemberToken)}`
      : null;
    const approveAdminUrl = `${params.origin}/committee/approve?token=${encodeURIComponent(approveAdminToken)}`;
    const rejectUrl = `${params.origin}/committee/approve?token=${encodeURIComponent(rejectToken)}`;
    const dashboardUrl = `${params.origin}/committee/dashboard`;

    const safeName = escapeHtml(params.applicantName);
    const safeEmail = escapeHtml(params.applicantEmail);
    const heading =
      requestType === "admin_upgrade"
        ? "Awaaz Admin Role Upgrade Request"
        : "Awaaz Committee Access Request";
    const summaryText =
      requestType === "admin_upgrade"
        ? "An active committee officer has requested Administrator privileges and requires your confirmation:"
        : "A new user has registered for committee portal access and requires your authorization before accessing any encrypted complaints:";

    const html = `
      <div style="font-family:system-ui,-apple-system,sans-serif;max-width:560px;margin:0 auto;padding:24px;color:#0f172a;border:1px solid #e2e8f0;border-radius:12px;">
        <h2 style="margin:0 0 8px;color:#0f294a;">${heading}</h2>
        <p style="margin:0 0 16px;font-size:14px;color:#475569;">${summaryText}</p>
        <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 16px;margin-bottom:20px;font-size:13px;">
          <p style="margin:4px 0;"><strong>Full Name:</strong> ${safeName}</p>
          <p style="margin:4px 0;"><strong>Applicant Email:</strong> ${safeEmail}</p>
          <p style="margin:4px 0;"><strong>User ID:</strong> <code>${escapeHtml(params.applicantUserId)}</code></p>
        </div>
        <p style="margin:0 0 12px;font-size:13px;font-weight:600;">Choose an action (single-use links, expire in 48h):</p>
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px;">
          ${
            approveOfficerUrl
              ? `<a href="${approveOfficerUrl}" style="display:inline-block;padding:10px 16px;background:#0f294a;color:#ffffff;text-decoration:none;border-radius:8px;font-size:13px;font-weight:600;">Approve as Officer</a>`
              : ""
          }
          <a href="${approveAdminUrl}" style="display:inline-block;padding:10px 16px;background:#047857;color:#ffffff;text-decoration:none;border-radius:8px;font-size:13px;font-weight:600;">Approve as Admin</a>
          <a href="${rejectUrl}" style="display:inline-block;padding:10px 16px;background:#b91c1c;color:#ffffff;text-decoration:none;border-radius:8px;font-size:13px;font-weight:600;">Reject Request</a>
        </div>
        <p style="margin:0;font-size:12px;color:#64748b;">
          Or manage pending requests directly in <a href="${dashboardUrl}">Committee Dashboard</a>.
        </p>
      </div>
    `;

    const subject =
      requestType === "admin_upgrade"
        ? `Awaaz Admin Verification Needed: ${params.applicantName} (${params.applicantEmail})`
        : `Awaaz Committee Approval Needed: ${params.applicantName} (${params.applicantEmail})`;

    const sendRes = await sendEmailViaConfiguredTransport({
      to: targetAdminEmail,
      subject,
      html,
    });

    if (!sendRes.ok) {
      return {
        notifiedAdminCount: 0,
        targetAdminEmail,
        emailSent: false,
        emailConfigured: true,
        reason: sendRes.error,
      };
    }

    return {
      notifiedAdminCount: 1,
      targetAdminEmail,
      emailSent: true,
      emailConfigured: true,
      deliveryChannel: sendRes.channel,
    };
  } catch (err) {
    return {
      notifiedAdminCount: 0,
      targetAdminEmail,
      emailSent: false,
      emailConfigured: true,
      reason: err instanceof Error ? err.message : "Failed to notify admin.",
    };
  }
}
