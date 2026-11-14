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

export type SelfHostSignups = {
  policy: SelfHostSignupPolicy;
  allowed_emails: { email: string; created_at: string }[];
};

export type SelfHostAuditAction =
  | 'root_claimed'
  | 'admin_granted'
  | 'admin_revoked'
  | 'user_disabled'
  | 'user_enabled'
  | 'signup_policy_changed'
  | 'allowed_email_added'
  | 'allowed_email_removed';

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
  addAllowedEmail: (email: string) =>
    fetchWithToken<object, SelfHostErrorCode>(
      `${base}/signups/allowed_emails`,
      send('POST', { email })
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
};
