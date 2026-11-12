/**
 * A self-hosted build (`VITE_SELF_HOSTED=true`): no billing, no product
 * analytics, admin-managed accounts. A deployment mode fixed at build time,
 * not a rollout flag, so it lives outside `featureFlags.ts` (whose module
 * many tests replace wholesale).
 */
export const SELF_HOSTED = import.meta.env.VITE_SELF_HOSTED === 'true';
