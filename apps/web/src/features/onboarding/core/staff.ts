import { SELF_HOSTED } from '@core/constant/selfHosted';
import { emailDomain } from './team';

const MACRO_STAFF_DOMAIN = 'macro.com';

/** Whether the address belongs to a Macro staff account (`@macro.com`). */
export function isMacroStaffEmail(address: string | undefined): boolean {
  return emailDomain(address) === MACRO_STAFF_DOMAIN;
}

/** Whether this account gets the Bypass button on the onboarding flow: staff, or anyone on a self-hosted install. */
export function canBypassOnboarding(address: string | undefined): boolean {
  return SELF_HOSTED || isMacroStaffEmail(address?.trim());
}
