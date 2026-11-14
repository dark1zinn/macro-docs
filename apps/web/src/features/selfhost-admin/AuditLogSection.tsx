import { downloadFile } from '@filesystem/download';
import CaretDownIcon from '@icon/system/regular/caret-down.svg';
import CheckIcon from '@icon/system/regular/check.svg';
import type { CollectionNode } from '@kobalte/core';
import { useSelfHostAuditQuery } from '@queries/auth/selfhost';
import {
  type SelfHostAuditAction,
  type SelfHostAuditEntry,
  type SelfHostAuditFilter,
  selfHostClient,
} from '@service-auth/selfhost';
import { Button, Input, Select } from '@ui';
import { createSignal, For, Show } from 'solid-js';
import {
  SettingsCard,
  SettingsRow,
  SettingsSection,
} from '../settings/primitives';

type ActionOption = { value: SelfHostAuditAction | 'all'; label: string };

const ACTIONS: ActionOption[] = [
  { value: 'all', label: 'All actions' },
  { value: 'admin_granted', label: 'Admin granted' },
  { value: 'admin_revoked', label: 'Admin removed' },
  { value: 'user_disabled', label: 'Account disabled' },
  { value: 'user_enabled', label: 'Account enabled' },
  { value: 'signup_policy_changed', label: 'Sign-up policy' },
  { value: 'allowed_email_added', label: 'Email allowed' },
  { value: 'allowed_email_removed', label: 'Email removed' },
  { value: 'root_claimed', label: 'Root admin claimed' },
];

const ITEM_CLASS =
  'flex items-center justify-between gap-3 rounded-md px-2 py-1.5 text-sm outline-none data-highlighted:bg-hover';

/** Profile and macro user ids are `macro|<email>`; show the email. */
const email = (id: string | null) => id?.replace(/^macro\|/, '') ?? '';

const when = (iso: string) =>
  new Date(iso).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  });

/** One sentence for an entry, such as "<admin> disabled <account>". */
export function describeAuditEntry(entry: SelfHostAuditEntry): string {
  const who = entry.actor ? email(entry.actor) : 'System';
  const target =
    typeof entry.details.email === 'string'
      ? entry.details.email
      : email(entry.target);
  switch (entry.action) {
    case 'root_claimed':
      return `${target} became the root admin`;
    case 'admin_granted':
      return `${who} made ${target} an admin`;
    case 'admin_revoked':
      return `${who} removed admin from ${target}`;
    case 'user_disabled':
      return `${who} disabled ${target}`;
    case 'user_enabled':
      return `${who} enabled ${target}`;
    case 'signup_policy_changed':
      return `${who} set sign-up to ${
        entry.details.policy === 'open' ? 'open' : 'invite only'
      }`;
    case 'allowed_email_added':
      return `${who} allowed ${target} to sign up`;
    case 'allowed_email_removed':
      return `${who} removed ${target} from allowed emails`;
  }
}

function outcome(entry: SelfHostAuditEntry) {
  switch (entry.status) {
    case 'succeeded':
      return undefined;
    case 'failed':
      return `Failed: ${entry.error ?? 'unknown reason'}`;
    case 'pending':
      return 'Outcome not recorded';
  }
}

/** Every admin action on this server, newest first, with filters and CSV export. */
export function AuditLogSection() {
  const [action, setAction] = createSignal(ACTIONS[0]!);
  const [search, setSearch] = createSignal('');
  const [appliedSearch, setAppliedSearch] = createSignal('');
  const [exportError, setExportError] = createSignal<string>();
  const [exporting, setExporting] = createSignal(false);

  const filter = (): SelfHostAuditFilter => {
    const selected = action().value;
    return {
      action: selected === 'all' ? undefined : selected,
      search: appliedSearch() || undefined,
    };
  };
  const audit = useSelfHostAuditQuery(filter);
  const entries = () => audit.data?.pages.flatMap((page) => page.entries) ?? [];

  const exportCsv = async () => {
    setExporting(true);
    setExportError(undefined);
    const result = await selfHostClient.exportAudit(filter());
    setExporting(false);
    if (result.isErr()) {
      setExportError(result.error[0]?.message ?? 'Export failed');
      return;
    }
    await downloadFile(
      new Blob([result.value.slice().buffer], { type: 'text/csv' }),
      'selfhost-audit-log.csv'
    );
  };

  return (
    <SettingsSection title="Audit log">
      <SettingsCard>
        <div class="flex flex-wrap items-center gap-2 p-4">
          <Select<ActionOption>
            options={ACTIONS}
            value={action()}
            onChange={(option) => option && setAction(option)}
            optionValue="value"
            optionTextValue="label"
            gutter={4}
            itemComponent={(props: { item: CollectionNode<ActionOption> }) => (
              <Select.Item item={props.item} class={ITEM_CLASS}>
                <Select.ItemLabel>{props.item.rawValue.label}</Select.ItemLabel>
                <Select.ItemIndicator>
                  <CheckIcon class="size-3" />
                </Select.ItemIndicator>
              </Select.Item>
            )}
          >
            <Select.Trigger
              aria-label="Action"
              class="flex h-8 w-44 items-center justify-between rounded-md border border-edge-muted px-2 text-sm text-ink-muted"
            >
              <Select.Value<ActionOption>>
                {(state) => state.selectedOption().label}
              </Select.Value>
              <CaretDownIcon class="size-3 shrink-0 text-ink-subtle" />
            </Select.Trigger>
            <Select.Content>
              <Select.Listbox />
            </Select.Content>
          </Select>
          <form
            class="flex gap-2"
            onSubmit={(event) => {
              event.preventDefault();
              setAppliedSearch(search().trim());
            }}
          >
            <Input
              type="search"
              size="sm"
              aria-label="Search by email"
              placeholder="Search by email"
              value={search()}
              onInput={(event) => setSearch(event.currentTarget.value)}
            />
            <Button type="submit" variant="secondary" size="sm">
              Search
            </Button>
          </form>
          <Button
            variant="ghost"
            size="sm"
            class="ml-auto"
            disabled={exporting()}
            onClick={() => {
              void exportCsv();
            }}
          >
            Export CSV
          </Button>
        </div>
        <Show when={exportError()}>
          {(message) => (
            <p class="px-4 py-2 text-sm text-failure" role="alert">
              {message()}
            </p>
          )}
        </Show>
        <Show
          when={entries().length > 0}
          fallback={
            <SettingsRow
              label={
                audit.isPending
                  ? 'Loading…'
                  : audit.isError
                    ? 'Could not load the audit log'
                    : 'No matching actions'
              }
              description={audit.error?.message}
            />
          }
        >
          <For each={entries()}>
            {(entry) => (
              <SettingsRow
                label={describeAuditEntry(entry)}
                description={[when(entry.created_at), outcome(entry)]
                  .filter(Boolean)
                  .join(' · ')}
                muted={entry.status !== 'succeeded'}
              />
            )}
          </For>
        </Show>
        <Show when={audit.hasNextPage}>
          <div class="flex justify-center p-2">
            <Button
              variant="ghost"
              size="sm"
              disabled={audit.isFetchingNextPage}
              onClick={() => {
                void audit.fetchNextPage();
              }}
            >
              Load more
            </Button>
          </div>
        </Show>
      </SettingsCard>
    </SettingsSection>
  );
}
