import { SERVER_HOSTS } from '@core/constant/servers';
import { fetchWithToken } from '@core/util/fetchWithToken';
import type { ResultError } from '@core/util/result';
import type { BaseFetchErrorCode } from '@core/util/safeFetch';

/** One account as the self-host admin panel lists it. */
export type SelfHostUser = {
  user_id: string;
  email: string;
  created_at: string | null;
  is_admin: boolean;
  disabled: boolean;
  is_self: boolean;
};

export type SelfHostSignupPolicy = 'open' | 'invite_only';

/** An address allowed to sign up. */
export type SelfHostAllowedEmail = {
  email: string;
  created_at: string;
  last_invited_at: string | null;
  /** Sending it a server invitation before this time is refused; absent when it can be sent now. */
  invitable_at: string | null;
};

export type SelfHostSignups = {
  policy: SelfHostSignupPolicy;
  allowed_emails: SelfHostAllowedEmail[];
};

export type SelfHostAuditAction =
  | 'root_claimed'
  | 'admin_granted'
  | 'admin_revoked'
  | 'user_disabled'
  | 'user_enabled'
  | 'signup_policy_changed'
  | 'allowed_email_added'
  | 'allowed_email_removed'
  | 'allowed_email_invited'
  | 'invite_link_revoked'
  | 'team_invite_revoked'
  | 'team_invite_resent'
  | 'captured_mail_deleted'
  | 'captured_mail_cleared';

/** A workspace's shareable invite link. */
export type SelfHostInviteLink = {
  team_id: string;
  team_name: string;
  token: string;
  created_at: string;
  /** Macro user id of whoever created or last replaced it. */
  created_by: string | null;
};

/** A workspace email invite nobody has answered yet. */
export type SelfHostPendingInvite = {
  invite_id: string;
  team_id: string;
  team_name: string;
  email: string;
  invited_by: string;
  created_at: string;
  last_sent_at: string;
  /** Emailing it again before this time is refused unless sent now on purpose. */
  resendable_at: string;
};

export type SelfHostInvites = {
  links: SelfHostInviteLink[];
  invites: SelfHostPendingInvite[];
};

/** What a revoke-all did: how many succeeded, and which failed and why. */
export type SelfHostRevokedAll = {
  revoked: number;
  failed: { target: string; error: string }[];
};

/** A message the server sent, held by the mail capture instead of delivered. */
export type SelfHostMail = {
  id: string;
  from: string;
  to: string[];
  subject: string;
  created_at: string;
  snippet: string;
};

export type SelfHostMailPage = { messages: SelfHostMail[]; total: number };

/** `html` is untrusted: render it only in a sandboxed frame. */
export type SelfHostMailMessage = SelfHostMail & {
  text: string | null;
  html: string | null;
};

/** One recorded admin action. `actor` is absent for system actions. */
export type SelfHostAuditEntry = {
  id: number;
  created_at: string;
  actor: string | null;
  action: SelfHostAuditAction;
  target: string | null;
  details: Record<string, unknown>;
  status: 'pending' | 'succeeded' | 'failed';
  error: string | null;
  completed_at: string | null;
};

export type SelfHostAuditPage = {
  entries: SelfHostAuditEntry[];
  /** Cursor for the next, older page; absent once a page comes back empty. */
  next_before: number | null;
};

export type SelfHostAuditFilter = {
  action?: SelfHostAuditAction;
  search?: string;
};

const auditParams = (filter: SelfHostAuditFilter, before?: number) => {
  const params = new URLSearchParams();
  if (filter.action) params.set('action', filter.action);
  if (filter.search?.trim()) params.set('search', filter.search.trim());
  if (before !== undefined) params.set('before', String(before));
  return params.toString();
};

type SelfHostErrorCode = 'SELFHOST_REJECTED';

const base = `${SERVER_HOSTS['auth-service']}/selfhost/admin`;

/** The admin API explains refusals (last admin, own account) in `message`. */
async function readError(
  response: Response
): Promise<ResultError<BaseFetchErrorCode | SelfHostErrorCode>> {
  const body: unknown = await response.json().catch(() => undefined);
  const message =
    typeof body === 'object' &&
    body !== null &&
    'message' in body &&
    typeof body.message === 'string'
      ? body.message
      : `Request failed (${response.status})`;
  return { code: 'SELFHOST_REJECTED', message };
}

const send = (method: 'POST' | 'PUT', body: unknown) => ({
  method,
  body: JSON.stringify(body),
  headers: { 'Content-Type': 'application/json' },
  errorResponseHandler: readError,
});

/** Admin-only calls. Errors come back as `Result`s, as with the other clients. */
export const selfHostClient = {
  users: () =>
    fetchWithToken<{ users: SelfHostUser[] }, SelfHostErrorCode>(
      `${base}/users`,
      { errorResponseHandler: readError }
    ),
  setAdmin: (userId: string, admin: boolean) =>
    fetchWithToken<object, SelfHostErrorCode>(
      `${base}/users/admin`,
      send('POST', { user_id: userId, admin })
    ),
  setDisabled: (userId: string, disabled: boolean) =>
    fetchWithToken<object, SelfHostErrorCode>(
      `${base}/users/disabled`,
      send('POST', { user_id: userId, disabled })
    ),
  signups: () =>
    fetchWithToken<SelfHostSignups, SelfHostErrorCode>(`${base}/signups`, {
      errorResponseHandler: readError,
    }),
  setPolicy: (policy: SelfHostSignupPolicy) =>
    fetchWithToken<object, SelfHostErrorCode>(
      `${base}/signups/policy`,
      send('PUT', { policy })
    ),
  addAllowedEmail: (email: string, notify: boolean) =>
    fetchWithToken<object, SelfHostErrorCode>(
      `${base}/signups/allowed_emails`,
      send('POST', { email, notify })
    ),
  /** Emails an allowed address an invitation to sign up. */
  inviteAllowedEmail: (email: string) =>
    fetchWithToken<object, SelfHostErrorCode>(
      `${base}/signups/allowed_emails/invite`,
      send('POST', { email })
    ),
  invites: () =>
    fetchWithToken<SelfHostInvites, SelfHostErrorCode>(`${base}/invites`, {
      errorResponseHandler: readError,
    }),
  revokeInviteLink: (teamId: string) =>
    fetchWithToken<object, SelfHostErrorCode>(
      `${base}/invites/links/revoke`,
      send('POST', { team_id: teamId })
    ),
  revokeAllInviteLinks: () =>
    fetchWithToken<SelfHostRevokedAll, SelfHostErrorCode>(
      `${base}/invites/links/revoke_all`,
      send('POST', {})
    ),
  revokeInvite: (inviteId: string) =>
    fetchWithToken<object, SelfHostErrorCode>(
      `${base}/invites/revoke`,
      send('POST', { invite_id: inviteId })
    ),
  revokeAllInvites: () =>
    fetchWithToken<SelfHostRevokedAll, SelfHostErrorCode>(
      `${base}/invites/revoke_all`,
      send('POST', {})
    ),
  /** `now` sends it even inside its resend window. */
  resendInvite: (inviteId: string, now: boolean) =>
    fetchWithToken<object, SelfHostErrorCode>(
      `${base}/invites/resend`,
      send('POST', { invite_id: inviteId, now })
    ),
  removeAllowedEmail: (email: string) =>
    fetchWithToken<object, SelfHostErrorCode>(
      `${base}/signups/allowed_emails/remove`,
      send('POST', { email })
    ),
  audit: (filter: SelfHostAuditFilter, before?: number) =>
    fetchWithToken<SelfHostAuditPage, SelfHostErrorCode>(
      `${base}/audit?${auditParams(filter, before)}`,
      { errorResponseHandler: readError }
    ),
  /** Every matching entry as CSV bytes. */
  exportAudit: (filter: SelfHostAuditFilter) =>
    fetchWithToken<Uint8Array, SelfHostErrorCode>(
      `${base}/audit/export?${auditParams(filter)}`,
      { errorResponseHandler: readError }
    ),
  /** Mail the server sent and the capture kept, newest first. */
  mail: (search: string, start: number) => {
    const params = new URLSearchParams({ start: String(start) });
    if (search.trim()) params.set('search', search.trim());
    return fetchWithToken<SelfHostMailPage, SelfHostErrorCode>(
      `${base}/mail?${params.toString()}`,
      { errorResponseHandler: readError }
    );
  },
  mailMessage: (id: string) =>
    fetchWithToken<SelfHostMailMessage, SelfHostErrorCode>(
      `${base}/mail/${encodeURIComponent(id)}`,
      { errorResponseHandler: readError }
    ),
  deleteMail: (id: string) =>
    fetchWithToken<object, SelfHostErrorCode>(
      `${base}/mail/delete`,
      send('POST', { id })
    ),
  clearMail: () =>
    fetchWithToken<object, SelfHostErrorCode>(
      `${base}/mail/clear`,
      send('POST', {})
    ),
};
