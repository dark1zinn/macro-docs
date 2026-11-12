import {
  useAllowedEmailMutation,
  useSelfHostSignupsQuery,
  useSelfHostUsersQuery,
  useSetSelfHostAdminMutation,
  useSetSelfHostDisabledMutation,
  useSetSelfHostPolicyMutation,
} from '@queries/auth/selfhost';
import type { SelfHostUser } from '@service-auth/selfhost';
import { Button, Input, ToggleSwitch } from '@ui';
import { createSignal, For, Show } from 'solid-js';
import {
  ChoiceRow,
  SettingsCard,
  SettingsPage,
  SettingsRow,
  SettingsSection,
} from '../settings/primitives';

const joined = (iso: string) =>
  new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' });

/** The last failed mutation's server explanation, until the next attempt. */
function ErrorLine(props: { error: Error | null }) {
  return (
    <Show when={props.error}>
      {(error) => (
        <p class="px-4 py-2 text-sm text-failure" role="alert">
          {error().message}
        </p>
      )}
    </Show>
  );
}

function UserRow(props: { user: SelfHostUser }) {
  const setAdmin = useSetSelfHostAdminMutation();
  const setDisabled = useSetSelfHostDisabledMutation();
  const description = () =>
    [
      props.user.is_self ? 'You' : undefined,
      props.user.created_at
        ? `Joined ${joined(props.user.created_at)}`
        : undefined,
    ]
      .filter(Boolean)
      .join(' · ');

  return (
    <>
      <SettingsRow
        label={props.user.email}
        description={description()}
        muted={props.user.disabled}
        stackOnNarrow
      >
        <ToggleSwitch
          size="md"
          label="Admin"
          checked={props.user.is_admin}
          disabled={setAdmin.isPending}
          onChange={(admin) =>
            setAdmin.mutate({ userId: props.user.user_id, admin })
          }
        />
        <ToggleSwitch
          size="md"
          label="Disabled"
          checked={props.user.disabled}
          disabled={props.user.is_self || setDisabled.isPending}
          onChange={(disabled) =>
            setDisabled.mutate({ userId: props.user.user_id, disabled })
          }
        />
      </SettingsRow>
      <ErrorLine error={setAdmin.error ?? setDisabled.error} />
    </>
  );
}

function UsersSection() {
  const users = useSelfHostUsersQuery();

  return (
    <SettingsSection title="Users">
      <SettingsCard>
        <Show
          when={users.data?.users}
          fallback={
            <SettingsRow
              label={users.isError ? 'Could not load users' : 'Loading…'}
              description={users.error?.message}
            />
          }
        >
          {(list) => (
            <For each={list()}>{(user) => <UserRow user={user} />}</For>
          )}
        </Show>
      </SettingsCard>
    </SettingsSection>
  );
}

function SignupsSection() {
  const signups = useSelfHostSignupsQuery();
  const setPolicy = useSetSelfHostPolicyMutation();
  const allowedEmail = useAllowedEmailMutation();
  const [email, setEmail] = createSignal('');

  const add = (event: SubmitEvent) => {
    event.preventDefault();
    const value = email().trim();
    if (!value) return;
    allowedEmail.mutate(
      { email: value, remove: false },
      { onSuccess: () => setEmail('') }
    );
  };

  return (
    <SettingsSection title="Sign-up">
      <SettingsCard>
        <div class="flex flex-col gap-2 p-4">
          <ChoiceRow
            name="selfhost-signup-policy"
            value="invite_only"
            title="Invite only"
            description="New accounts need an allowed email below or a pending team invite."
            checked={signups.data?.policy === 'invite_only'}
            disabled={setPolicy.isPending}
            onChange={() => setPolicy.mutate('invite_only')}
          />
          <ChoiceRow
            name="selfhost-signup-policy"
            value="open"
            title="Open"
            description="Anyone who can reach this server can create an account."
            checked={signups.data?.policy === 'open'}
            disabled={setPolicy.isPending}
            onChange={() => setPolicy.mutate('open')}
          />
        </div>
        <ErrorLine error={setPolicy.error} />
      </SettingsCard>
      <SettingsCard>
        <SettingsRow
          label="Allowed emails"
          description="These addresses may create an account while sign-up is invite only."
          stackOnNarrow
        >
          <form class="flex gap-2" onSubmit={add}>
            <Input
              type="email"
              size="sm"
              placeholder="person@example.com"
              value={email()}
              onInput={(event) => setEmail(event.currentTarget.value)}
            />
            <Button
              type="submit"
              variant="secondary"
              size="sm"
              disabled={allowedEmail.isPending}
            >
              Allow
            </Button>
          </form>
        </SettingsRow>
        <For each={signups.data?.allowed_emails ?? []}>
          {(entry) => (
            <SettingsRow
              label={entry.email}
              description={`Added ${joined(entry.created_at)}`}
            >
              <Button
                variant="ghost"
                size="sm"
                disabled={allowedEmail.isPending}
                onClick={() =>
                  allowedEmail.mutate({ email: entry.email, remove: true })
                }
              >
                Remove
              </Button>
            </SettingsRow>
          )}
        </For>
        <ErrorLine error={allowedEmail.error} />
      </SettingsCard>
    </SettingsSection>
  );
}

/** Root administration of a self-hosted install: accounts and sign-up. */
export function SelfHostAdmin() {
  return (
    <SettingsPage
      title="Self-host"
      description="Manage the accounts on this server and who may sign up."
    >
      <UsersSection />
      <SignupsSection />
    </SettingsPage>
  );
}
