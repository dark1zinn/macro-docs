import { isModelAvailable } from '@core/constant/selfHostedAiProviders';
import type { LoadAgentModelsResponse } from '@service-agent-harness/generated/schemas';

/**
 * Drops catalog models whose provider the self-hosted gateway has no key for.
 * If the current model is dropped, it falls back to the first remaining model.
 */
export function availableAgentModels(
  response: LoadAgentModelsResponse
): LoadAgentModelsResponse {
  const models = response.models.filter((model) => isModelAvailable(model.id));
  const current = response.currentModel;
  const currentKept =
    current == null || models.some((model) => model.id === current);
  return {
    ...response,
    models,
    currentModel: currentKept ? current : (models[0]?.id ?? null),
  };
}
