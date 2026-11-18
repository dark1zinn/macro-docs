import { toast } from '@core/component/Toast/Toast';
import { writeClipboardData } from '@core/util/dataTransfer';
import {
  useDeleteSelfHostMailMutation,
  useSelfHostMailMessageQuery,
  useSelfHostMailQuery,
} from '@queries/auth/selfhost';
import type { SelfHostMail } from '@service-auth/selfhost';
import { Button, confirmDialog, Input } from '@ui';
import { createSignal, For, Show } from 'solid-js';
import {
  SettingsCard,
  SettingsRow,
  SettingsSection,
} from '../settings/primitives';
import { time } from './InvitesSection';

/** The first 6-digit sign-in code in a message, if it holds one. */
const signInCode = (text: string | null | undefined) =>
  text?.match(/\b\d{6}\b/)?.[0];

async function copyCode(code: string) {
  if (await writeClipboardData({ 'text/plain': code })) {
    toast.success('Code copied');
  } else {
    toast.failure('Could not copy the code');
  }
}

/** One captured message, opened: its text, or its HTML in a frame that runs nothing. */
function MailBody(props: { id: string }) {
  const message = useSelfHostMailMessageQuery(() => props.id);
  return (
    <div class="flex flex-col gap-2 px-4 pb-4">
      <Show
        when={message.data}
        fallback={
          <p class="text-sm text-ink-muted">
            {message.isError
              ? (message.error?.message ?? 'Could not open the message')
              : 'Loading…'}
          </p>
        }
      >
        {(data) => (
          <>
            <Show when={signInCode(data().text ?? data().snippet)}>
              {(code) => (
                <div class="flex items-center gap-2">
                  <span class="font-mono text-lg tracking-widest text-ink">
                    {code()}
                  </span>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => {
                      void copyCode(code());
                    }}
                  >
                    Copy code
                  </Button>
                </div>
              )}
            </Show>
            <Show
              when={data().html}
              fallback={
                <pre class="max-h-96 overflow-auto whitespace-pre-wrap rounded-md border border-edge-muted p-3 text-xs text-ink">
                  {data().text ?? ''}
                </pre>
              }
            >
              {(html) => (
                <iframe
                  title={data().subject}
                  sandbox=""
                  srcdoc={html()}
                  class="h-96 w-full rounded-md border border-edge-muted bg-white"
                />
              )}
            </Show>
          </>
        )}
      </Show>
    </div>
  );
}

function MailRow(props: {
  mail: SelfHostMail;
  open: boolean;
  pending: boolean;
  onToggle: () => void;
  onDelete: () => void;
}) {
  return (
    <>
      <SettingsRow
        label={props.mail.subject || '(no subject)'}
        description={`To ${props.mail.to.join(', ')} · ${time(props.mail.created_at)}`}
        stackOnNarrow
      >
        <Button variant="secondary" size="sm" onClick={() => props.onToggle()}>
          {props.open ? 'Close' : 'Open'}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          disabled={props.pending}
          onClick={() => props.onDelete()}
        >
          Delete
        </Button>
      </SettingsRow>
      <Show when={props.open}>
        <MailBody id={props.mail.id} />
      </Show>
    </>
  );
}

/**
 * The mail this server sent, kept by its mail capture instead of delivered.
 * Admins read sign-in codes here and pass them on to the people signing up.
 */
export function MailSection() {
  const [search, setSearch] = createSignal('');
  const [appliedSearch, setAppliedSearch] = createSignal('');
  const [openId, setOpenId] = createSignal<string>();
  const mail = useSelfHostMailQuery(appliedSearch);
  const remove = useDeleteSelfHostMailMutation();
  const messages = () =>
    mail.data?.pages.flatMap((page) => page.messages) ?? [];

  const clearAll = async () => {
    const confirmed = await confirmDialog({
      title: 'Delete all captured mail?',
      body: 'Codes in it can no longer be read here.',
      confirmLabel: 'Delete all',
      tone: 'danger',
    });
    if (confirmed) remove.mutate(undefined);
  };

  return (
    <SettingsSection title="Server mail">
      <SettingsCard>
        <SettingsRow
          label="Mail the server sent"
          description="With the mail capture on, mail is kept here instead of delivered. Pass sign-in codes on to the people signing up."
          stackOnNarrow
        >
          <Button
            variant="ghost"
            size="sm"
            disabled={remove.isPending || messages().length === 0}
            onClick={() => {
              void clearAll();
            }}
          >
            Delete all
          </Button>
        </SettingsRow>
        <form
          class="flex gap-2 px-4 pb-2"
          onSubmit={(event) => {
            event.preventDefault();
            setAppliedSearch(search().trim());
          }}
        >
          <Input
            type="search"
            size="sm"
            aria-label="Search mail"
            placeholder="Search by recipient or subject"
            value={search()}
            onInput={(event) => setSearch(event.currentTarget.value)}
          />
          <Button type="submit" variant="secondary" size="sm">
            Search
          </Button>
        </form>
        <Show
          when={messages().length > 0}
          fallback={
            <SettingsRow
              label={
                mail.isPending
                  ? 'Loading…'
                  : mail.isError
                    ? 'Mail capture is unavailable'
                    : 'No mail'
              }
              description={
                mail.isError
                  ? `${mail.error?.message ?? ''}. Turn on the mailcatcher profile and send mail through it.`
                  : undefined
              }
              muted
            />
          }
        >
          <For each={messages()}>
            {(message) => (
              <MailRow
                mail={message}
                open={openId() === message.id}
                pending={remove.isPending}
                onToggle={() =>
                  setOpenId((id) =>
                    id === message.id ? undefined : message.id
                  )
                }
                onDelete={() => remove.mutate(message.id)}
              />
            )}
          </For>
        </Show>
        <Show when={mail.hasNextPage}>
          <div class="flex justify-center p-2">
            <Button
              variant="ghost"
              size="sm"
              disabled={mail.isFetchingNextPage}
              onClick={() => {
                void mail.fetchNextPage();
              }}
            >
              Load more
            </Button>
          </div>
        </Show>
        <Show when={remove.error}>
          {(error) => (
            <p class="px-4 py-2 text-sm text-failure" role="alert">
              {error().message}
            </p>
          )}
        </Show>
      </SettingsCard>
    </SettingsSection>
  );
}
