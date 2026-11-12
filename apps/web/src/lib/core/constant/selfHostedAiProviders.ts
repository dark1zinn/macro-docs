import { getWebOrigin } from '@core/util/webOrigin';
import { createSignal } from 'solid-js';
import { SELF_HOSTED } from './selfHosted';

/**
 * Which AI providers the self-hosted gateway has keys for. The gateway serves
 * `GET /selfhost/config.json` on the app's origin:
 * `{"ai_providers":"anthropic,openai,"}`. Outside a self-hosted build, before
 * the config loads, or when it fails to load, every provider counts as
 * available, which is the upstream behavior.
 */

const CONFIG_PATH = '/selfhost/config.json';
const CONFIG_TIMEOUT_MS = 5000;

/** Provider that serves the `auto` model id on the backend. */
const AUTO_PROVIDER = 'google';

/** `null` = unknown (not self-hosted, not loaded, or the load failed). */
const [configuredProviders, setConfiguredProviders] =
  createSignal<ReadonlySet<string> | null>(null);

/** Parse the comma-separated provider list. An empty value means none. */
export function parseAiProviders(raw: string): ReadonlySet<string> {
  return new Set(
    raw
      .split(',')
      .map((provider) => provider.trim())
      .filter((provider) => provider.length > 0)
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

let loading: Promise<void> | undefined;

/**
 * Fetch the self-host provider config once. Idempotent. Resolves when the
 * attempt settles, so callers can await a decision that needs the config. A
 * failed fetch leaves every provider available.
 */
export function loadSelfHostedAiProviders(): Promise<void> {
  if (!SELF_HOSTED) return Promise.resolve();
  loading ??= fetchProviders();
  return loading;
}

async function fetchProviders(): Promise<void> {
  try {
    const response = await fetch(`${getWebOrigin()}${CONFIG_PATH}`, {
      signal: AbortSignal.timeout(CONFIG_TIMEOUT_MS),
    });
    if (!response.ok) return;
    const body: unknown = await response.json();
    if (
      typeof body !== 'object' ||
      body === null ||
      !('ai_providers' in body) ||
      typeof body.ai_providers !== 'string'
    ) {
      return;
    }
    setConfiguredProviders(parseAiProviders(body.ai_providers));
  } catch {
    // Unreachable or malformed config: keep every provider available.
  }
}
