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
};
