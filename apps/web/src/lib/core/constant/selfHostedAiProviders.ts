import { getWebOrigin } from '@core/util/webOrigin';
import { createSignal } from 'solid-js';
import { SELF_HOSTED } from './selfHosted';

/**
 * Which AI providers and integrations the self-hosted gateway has credentials
 * for. The gateway serves `GET /selfhost/config.json` on the app's origin:
 * `{"ai_providers":"anthropic,openai,","integrations":"github,google,"}`.
 * Outside a self-hosted build, before the config loads, or when it fails to
 * load, every provider and integration counts as available, which is the
 * upstream behavior. A field missing from the response leaves its list unknown.
 */

const CONFIG_PATH = '/selfhost/config.json';
const CONFIG_TIMEOUT_MS = 5000;

/** Provider that serves the `auto` model id on the backend. */
const AUTO_PROVIDER = 'google';

/** Integrations the self-host operator can enable by configuring credentials. */
export type IntegrationName = 'github' | 'google' | 'pipedream' | 'slack';

/** `null` = unknown (not self-hosted, not loaded, or the load failed). */
const [configuredProviders, setConfiguredProviders] =
  createSignal<ReadonlySet<string> | null>(null);
const [configuredIntegrations, setConfiguredIntegrations] =
  createSignal<ReadonlySet<string> | null>(null);

/** Parse a comma-separated list. An empty value means none. */
export function parseAiProviders(raw: string): ReadonlySet<string> {
  return parseCommaList(raw);
}

function parseCommaList(raw: string): ReadonlySet<string> {
  return new Set(
    raw
      .split(',')
      .map((item) => item.trim())
      .filter((item) => item.length > 0)
  );
}

/** The provider serving a model id: the text before `/`, with `auto` → google. */
export function providerOfModel(modelId: string): string {
  if (modelId === 'auto') return AUTO_PROVIDER;
  const slash = modelId.indexOf('/');
  return slash === -1 ? modelId : modelId.slice(0, slash);
}

/** Whether a provider has a key. Reactive: reads the loaded config signal. */
export function isAiProviderAvailable(provider: string): boolean {
  const providers = configuredProviders();
  return providers === null || providers.has(provider);
}

/** Whether a model's provider has a key. Reactive. */
export function isModelAvailable(modelId: string): boolean {
  return isAiProviderAvailable(providerOfModel(modelId));
}

/** Whether an integration has its credentials configured. Reactive. */
export function isIntegrationAvailable(name: IntegrationName): boolean {
  const integrations = configuredIntegrations();
  return integrations === null || integrations.has(name);
}

let loading: Promise<void> | undefined;

/**
 * Fetch the self-host config once. Idempotent. Resolves when the attempt
 * settles, so callers can await a decision that needs the config. A failed
 * fetch leaves every provider and integration available.
 */
export function loadSelfHostedAiProviders(): Promise<void> {
  if (!SELF_HOSTED) return Promise.resolve();
  loading ??= fetchConfig();
  return loading;
}

async function fetchConfig(): Promise<void> {
  try {
    const response = await fetch(`${getWebOrigin()}${CONFIG_PATH}`, {
      signal: AbortSignal.timeout(CONFIG_TIMEOUT_MS),
    });
    if (!response.ok) return;
    const body: unknown = await response.json();
    if (typeof body !== 'object' || body === null) return;
    if ('ai_providers' in body && typeof body.ai_providers === 'string') {
      setConfiguredProviders(parseCommaList(body.ai_providers));
    }
    if ('integrations' in body && typeof body.integrations === 'string') {
      setConfiguredIntegrations(parseCommaList(body.integrations));
    }
  } catch {
    // Unreachable or malformed config: keep every provider available.
  }
}
