import { toast } from '@core/component/Toast/Toast';
import { writeClipboardData } from '@core/util/dataTransfer';
import {
  type SelfHostInviteAction,
  useSelfHostInviteActionMutation,
  useSelfHostInvitesQuery,
} from '@queries/auth/selfhost';
import type {
  SelfHostInviteLink,
  SelfHostPendingInvite,
} from '@service-auth/selfhost';
import { Button, confirmDialog } from '@ui';
import { createSignal, For, onCleanup, Show } from 'solid-js';
import {
  SettingsCard,
  SettingsRow,
  SettingsSection,
} from '../settings/primitives';
import { teamInviteLinkUrl } from '../settings/TeamInviteLinkSection';

/** Profile and macro user ids are `macro|<email>`; show the email. */
const email = (id: string | null) => id?.replace(/^macro\|/, '') ?? '';

const date = (iso: string) =>
  new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' });

const time = (iso: string) =>
  new Date(iso).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  });

/** The current time, ticking each minute so resend buttons unlock on their own. */
function useNow() {
  const [now, setNow] = createSignal(Date.now());
  const timer = setInterval(() => setNow(Date.now()), 60_000);
  onCleanup(() => clearInterval(timer));
  return now;
}

async function copyLink(token: string) {
  if (await writeClipboardData({ 'text/plain': teamInviteLinkUrl(token) })) {
    toast.success('Invite link copied');
  } else {
    toast.failure('Could not copy invite link');
  }
}

function LinkRow(props: {
  link: SelfHostInviteLink;
  pending: boolean;
  run: (action: SelfHostInviteAction) => void;
}) {
  const description = () =>
    [
      props.link.created_by
        ? `Created by ${email(props.link.created_by)}`
        : undefined,
      `on ${date(props.link.created_at)}`,
    ]
      .filter(Boolean)
      .join(' ');

  return (
    <SettingsRow
      label={props.link.team_name}
      description={description()}
      stackOnNarrow
    >
      <Button
        variant="secondary"
        size="sm"
        onClick={() => {
          void copyLink(props.link.token);
        }}
      >
        Copy link
      </Button>
      <Button
        variant="ghost"
        size="sm"
        disabled={props.pending}
        onClick={() =>
          props.run({ kind: 'revoke_link', teamId: props.link.team_id })
        }
      >
        Revoke
      </Button>
    </SettingsRow>
  );
}

function InviteRow(props: {
  invite: SelfHostPendingInvite;
  now: number;
  pending: boolean;
  run: (action: SelfHostInviteAction) => void;
}) {
  const canResend = () =>
    props.now >= new Date(props.invite.resendable_at).getTime();

  return (
    <SettingsRow
      label={props.invite.email}
      description={`${props.invite.team_name} · invited by ${email(
        props.invite.invited_by
      )} · last sent ${time(props.invite.last_sent_at)}`}
      stackOnNarrow
    >
      <Button
        variant="secondary"
        size="sm"
        disabled={props.pending || !canResend()}
        title={
          canResend()
            ? undefined
            : `Can be resent after ${time(props.invite.resendable_at)}`
        }
        onClick={() =>
          props.run({ kind: 'resend_invite', inviteId: props.invite.invite_id })
        }
      >
        Resend
      </Button>
      <Button
        variant="ghost"
        size="sm"
        disabled={props.pending}
        onClick={() =>
          props.run({ kind: 'revoke_invite', inviteId: props.invite.invite_id })
        }
      >
        Cancel
      </Button>
    </SettingsRow>
  );
}

/** Every workspace invite link and pending email invite on this server. */
export function InvitesSection() {
  const invites = useSelfHostInvitesQuery();
  const action = useSelfHostInviteActionMutation();
  const now = useNow();
  const run = (next: SelfHostInviteAction) => action.mutate(next);

  const revokeAll = async (kind: 'revoke_all_links' | 'revoke_all_invites') => {
    const links = kind === 'revoke_all_links';
    const confirmed = await confirmDialog({
      title: links
        ? 'Revoke every invite link?'
        : 'Cancel every pending invite?',
      body: links
        ? 'Links people have already shared stop working. Workspaces can create new ones.'
        : 'Nobody can join through these email invites any more.',
      confirmLabel: links ? 'Revoke all' : 'Cancel all',
      tone: 'danger',
    });
    if (confirmed) run({ kind });
  };

  const loading = (empty: string) =>
    invites.isPending
      ? 'Loading…'
      : invites.isError
        ? 'Could not load invites'
        : empty;

  return (
    <SettingsSection title="Invites">
      <SettingsCard>
        <SettingsRow
          label="Workspace invite links"
          description="Anyone signed in with a link joins its workspace."
        >
          <Button
            variant="ghost"
            size="sm"
            disabled={action.isPending || !invites.data?.links.length}
            onClick={() => {
              void revokeAll('revoke_all_links');
            }}
          >
            Revoke all
          </Button>
        </SettingsRow>
        <Show
          when={invites.data?.links.length}
          fallback={
            <SettingsRow
              label={loading('No invite links')}
              description={invites.error?.message}
              muted
            />
          }
        >
          <For each={invites.data?.links}>
            {(link) => (
              <LinkRow link={link} pending={action.isPending} run={run} />
            )}
          </For>
        </Show>
      </SettingsCard>
      <SettingsCard>
        <SettingsRow
          label="Pending email invites"
          description="People invited to a workspace who have not joined yet."
        >
          <Button
            variant="ghost"
            size="sm"
            disabled={action.isPending || !invites.data?.invites.length}
            onClick={() => {
              void revokeAll('revoke_all_invites');
            }}
          >
            Cancel all
          </Button>
        </SettingsRow>
        <Show
          when={invites.data?.invites.length}
          fallback={<SettingsRow label={loading('No pending invites')} muted />}
        >
          <For each={invites.data?.invites}>
            {(invite) => (
              <InviteRow
                invite={invite}
                now={now()}
                pending={action.isPending}
                run={run}
              />
            )}
          </For>
        </Show>
        <Show when={action.error}>
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
