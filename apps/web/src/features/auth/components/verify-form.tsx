import ArrowLeft from '@icon/system/regular/arrow-left.svg';
import ArrowRight from '@icon/system/regular/arrow-right.svg';
import { createSignal, Show } from 'solid-js';
import { AuthButton, FormError, FormInput } from './form-fields';
import { OtpInput } from './otp-input';

/** Self-host: the server's setup token signs the first account in instead of a code. */
function SetupTokenEntry(props: {
  verifying: boolean;
  onSubmit: (token: string) => void;
}) {
  const [open, setOpen] = createSignal(false);
  const [token, setToken] = createSignal('');

  return (
    <Show
      when={open()}
      fallback={
        <p class="text-center text-xs text-ink-muted">
          Setting up this server?{' '}
          <button
            type="button"
            onClick={() => setOpen(true)}
            class="font-medium text-ink transition-colors hover:text-ink-muted"
          >
            Use the setup token
          </button>
        </p>
      }
    >
      <div class="flex flex-col gap-2">
        <FormInput
          id="setup-token"
          type="password"
          placeholder="Setup token"
          required={false}
          value={token()}
          onInput={setToken}
        />
        <AuthButton
          variant="secondary"
          disabled={props.verifying || !token().trim()}
          onClick={() => props.onSubmit(token())}
        >
          Sign in with setup token
        </AuthButton>
      </div>
    </Show>
  );
}

export function VerifyForm(props: {
  email: string;
  code: string;
  verifying: boolean;
  canVerify: boolean;
  resendIn: number;
  resending: boolean;
  error?: string;
  onCodeInput: (value: string) => void;
  onVerify: (code?: string) => void;
  /** Offered only on self-hosted servers. */
  onSetupToken?: (token: string) => void;
  onResend: () => void;
  onBack: () => void;
}) {
  return (
    <form
      class="flex flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        props.onVerify();
      }}
    >
      <p class="text-xs text-ink-muted leading-snug">
        Enter the 6-digit code we sent to{' '}
        <span class="text-ink font-medium break-all">{props.email}</span>.
      </p>
      <OtpInput
        value={props.code}
        disabled={props.verifying}
        onInput={props.onCodeInput}
        onComplete={(code) => props.onVerify(code)}
      />
      <p class="text-center text-xs text-ink-muted" aria-live="polite">
        Didn't receive a code?{' '}
        <button
          type="button"
          onClick={() => props.onResend()}
          disabled={props.resending || props.verifying || props.resendIn > 0}
          class="font-medium text-ink transition-colors hover:text-ink-muted disabled:text-ink-extra-muted"
        >
          <Show when={props.resendIn > 0} fallback="Resend">
            Resend ({props.resendIn})
          </Show>
        </button>
      </p>
      <FormError message={props.error} />
      <AuthButton type="submit" disabled={!props.canVerify}>
        Verify
        <ArrowRight class="size-5 shrink-0" />
      </AuthButton>
      <Show when={props.onSetupToken}>
        {(onSetupToken) => (
          <SetupTokenEntry
            verifying={props.verifying}
            onSubmit={(token) => onSetupToken()(token)}
          />
        )}
      </Show>
      <AuthButton variant="secondary" onClick={props.onBack}>
        <ArrowLeft class="size-5 shrink-0" />
        Change email
      </AuthButton>
    </form>
  );
}
