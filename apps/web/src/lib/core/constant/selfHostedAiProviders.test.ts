import { beforeEach, describe, expect, it, vi } from 'vitest';
import type * as Module from './selfHostedAiProviders';

const env = vi.hoisted(() => ({ selfHosted: true }));

vi.mock('./selfHosted', () => ({
  get SELF_HOSTED() {
    return env.selfHosted;
  },
}));

vi.mock('@core/util/webOrigin', () => ({
  getWebOrigin: () => 'https://self.test',
}));

async function freshModule(): Promise<typeof Module> {
  vi.resetModules();
  return import('./selfHostedAiProviders');
}

function configResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

describe('parseAiProviders', () => {
  it('splits a comma list, ignoring blanks and a trailing comma', async () => {
    const { parseAiProviders } = await freshModule();
    expect([...parseAiProviders('anthropic,openai,')]).toEqual([
      'anthropic',
      'openai',
    ]);
    expect([...parseAiProviders(' google , cerebras ')]).toEqual([
      'google',
      'cerebras',
    ]);
  });

  it('treats an empty value as no providers', async () => {
    const { parseAiProviders } = await freshModule();
    expect(parseAiProviders('').size).toBe(0);
  });
});

describe('providerOfModel', () => {
  it('reads the provider prefix and maps auto to google', async () => {
    const { providerOfModel } = await freshModule();
    expect(providerOfModel('anthropic/claude-sonnet-5-5')).toBe('anthropic');
    expect(providerOfModel('cerebras/gpt-oss-120b')).toBe('cerebras');
    expect(providerOfModel('auto')).toBe('google');
  });
});

describe('self-hosted AI provider availability', () => {
  beforeEach(() => {
    env.selfHosted = true;
    vi.restoreAllMocks();
  });

  it('treats every provider as available before the config loads', async () => {
    const { isModelAvailable } = await freshModule();
    expect(isModelAvailable('openai/gpt-6-astra')).toBe(true);
  });

  it('filters providers once the config loads', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(configResponse({ ai_providers: 'anthropic,' }));
    const {
      loadSelfHostedAiProviders,
      isModelAvailable,
      isAiProviderAvailable,
    } = await freshModule();

    await loadSelfHostedAiProviders();

    expect(fetchMock).toHaveBeenCalledWith(
      'https://self.test/selfhost/config.json',
      expect.anything()
    );
    expect(isModelAvailable('anthropic/claude-sonnet-5-5')).toBe(true);
    expect(isModelAvailable('openai/gpt-6-astra')).toBe(false);
    expect(isModelAvailable('auto')).toBe(false);
    expect(isAiProviderAvailable('openai')).toBe(false);
  });

  it('requests the config only once', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(configResponse({ ai_providers: '' }));
    const { loadSelfHostedAiProviders } = await freshModule();

    await loadSelfHostedAiProviders();
    await loadSelfHostedAiProviders();

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('keeps every provider available when the fetch rejects', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('offline'));
    const { loadSelfHostedAiProviders, isModelAvailable } = await freshModule();

    await loadSelfHostedAiProviders();

    expect(isModelAvailable('openai/gpt-6-astra')).toBe(true);
  });

  it('keeps every provider available on a non-ok response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      configResponse({ ai_providers: '' }, 404)
    );
    const { loadSelfHostedAiProviders, isModelAvailable } = await freshModule();

    await loadSelfHostedAiProviders();

    expect(isModelAvailable('openai/gpt-6-astra')).toBe(true);
  });

  it('keeps every provider available on a malformed body', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      configResponse({ providers: 'openai' })
    );
    const { loadSelfHostedAiProviders, isModelAvailable } = await freshModule();

    await loadSelfHostedAiProviders();

    expect(isModelAvailable('openai/gpt-6-astra')).toBe(true);
  });

  it('never fetches or filters outside a self-hosted build', async () => {
    env.selfHosted = false;
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    const { loadSelfHostedAiProviders, isModelAvailable } = await freshModule();

    await loadSelfHostedAiProviders();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(isModelAvailable('openai/gpt-6-astra')).toBe(true);
  });
});
