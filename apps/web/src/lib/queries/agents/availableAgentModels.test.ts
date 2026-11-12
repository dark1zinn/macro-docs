import type { LoadAgentModelsResponse } from '@service-agent-harness/generated/schemas';
import { describe, expect, it, vi } from 'vitest';
import { availableAgentModels } from './availableAgentModels';

const configured = vi.hoisted(() => ({ providers: new Set<string>() }));

vi.mock('@core/constant/selfHostedAiProviders', () => ({
  isModelAvailable: (modelId: string) => {
    const provider = modelId === 'auto' ? 'google' : modelId.split('/')[0];
    return configured.providers.has(provider);
  },
}));

function catalog(
  currentModel: string | null | undefined,
  ids: string[]
): LoadAgentModelsResponse {
  return {
    status: 'ok',
    currentModel,
    models: ids.map((id) => ({ id, name: id })),
  } as unknown as LoadAgentModelsResponse;
}

describe('availableAgentModels', () => {
  it('drops models whose provider has no key', () => {
    configured.providers = new Set(['anthropic']);
    const result = availableAgentModels(
      catalog('anthropic/claude-sonnet-5-5', [
        'anthropic/claude-sonnet-5-5',
        'openai/gpt-6-astra',
        'auto',
      ])
    );
    expect(result.models.map((model) => model.id)).toEqual([
      'anthropic/claude-sonnet-5-5',
    ]);
    expect(result.currentModel).toBe('anthropic/claude-sonnet-5-5');
  });

  it('moves the current model to the first remaining one when it is dropped', () => {
    configured.providers = new Set(['openai']);
    const result = availableAgentModels(
      catalog('anthropic/claude-sonnet-5-5', [
        'anthropic/claude-sonnet-5-5',
        'openai/gpt-6-astra',
      ])
    );
    expect(result.currentModel).toBe('openai/gpt-6-astra');
  });

  it('sets the current model to null when no model remains', () => {
    configured.providers = new Set();
    const result = availableAgentModels(
      catalog('anthropic/claude-sonnet-5-5', ['anthropic/claude-sonnet-5-5'])
    );
    expect(result.models).toEqual([]);
    expect(result.currentModel).toBeNull();
  });

  it('keeps an absent current model absent', () => {
    configured.providers = new Set(['openai']);
    const result = availableAgentModels(
      catalog(undefined, ['openai/gpt-6-astra'])
    );
    expect(result.currentModel).toBeUndefined();
  });
});
