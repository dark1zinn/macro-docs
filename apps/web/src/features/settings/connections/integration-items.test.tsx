import { cleanup, render, screen } from '@solidjs/testing-library';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAgentProviderItem } from './integration-items';
import { toConnectionsModel } from './model';
import {
  ConnectionsViewProvider,
  createConnectionsViewState,
} from './view-state';

const integrations = vi.hoisted(() => ({ pipedream: true }));

vi.mock('@core/constant/selfHostedAiProviders', () => ({
  isIntegrationAvailable: (name: string) =>
    name !== 'pipedream' || integrations.pipedream,
}));
vi.mock('./import-action', () => ({ ImportAction: () => null }));

function renderLinear(connected: boolean) {
  const model = toConnectionsModel({
    pipedream: connected
      ? [{ app_slug: 'linear', server_name: 'Linear', enabled: true }]
      : [],
    nativeMcp: [],
  });
  function LinearActions() {
    const item = useAgentProviderItem(() => model, 'linear');
    return <item.Actions />;
  }
  render(() => (
    <ConnectionsViewProvider value={createConnectionsViewState({})}>
      <LinearActions />
    </ConnectionsViewProvider>
  ));
}

describe('Pipedream-backed agent tool rows', () => {
  beforeEach(() => {
    integrations.pipedream = true;
  });
  afterEach(cleanup);

  it('offers Connect when Pipedream is configured', () => {
    renderLinear(false);
    expect(screen.getByRole('button', { name: 'Connect Linear' })).toBeTruthy();
  });

  it('hides Connect when Pipedream is not configured', () => {
    integrations.pipedream = false;
    renderLinear(false);
    expect(screen.queryByRole('button', { name: 'Connect Linear' })).toBeNull();
  });

  it('keeps Manage for a connection made before Pipedream was removed', () => {
    integrations.pipedream = false;
    renderLinear(true);
    expect(screen.getByRole('button', { name: 'Manage Linear' })).toBeTruthy();
  });
});
