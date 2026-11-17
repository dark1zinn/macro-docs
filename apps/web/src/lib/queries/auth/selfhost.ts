import { throwOnErr } from '@core/util/result';
import { queryClient } from '@queries/client';
import {
  type SelfHostAuditFilter,
  type SelfHostSignupPolicy,
  selfHostClient,
} from '@service-auth/selfhost';
import {
  infiniteQueryOptions,
  queryOptions,
  useInfiniteQuery,
  useMutation,
  useQuery,
} from '@tanstack/solid-query';
import type { Accessor } from 'solid-js';

const selfHostKeys = {
  users: ['selfhost', 'admin', 'users'] as const,
  signups: ['selfhost', 'admin', 'signups'] as const,
  invites: ['selfhost', 'admin', 'invites'] as const,
  audit: ['selfhost', 'admin', 'audit'] as const,
  mail: ['selfhost', 'admin', 'mail'] as const,
};

/** Every admin action changes state and adds an audit entry. */
const invalidateAdmin = () =>
  Promise.all(
    Object.values(selfHostKeys).map((queryKey) =>
      queryClient.invalidateQueries({ queryKey })
    )
  );

const invitesQueryOptions = queryOptions({
  queryKey: selfHostKeys.invites,
  queryFn: () => throwOnErr(selfHostClient.invites),
});

/** Every workspace invite link and pending email invite on the server. */
export function useSelfHostInvitesQuery() {
  return useQuery(() => invitesQueryOptions);
}

export type SelfHostInviteAction =
  | { kind: 'revoke_link'; teamId: string }
  | { kind: 'revoke_all_links' }
  | { kind: 'revoke_invite'; inviteId: string }
  | { kind: 'revoke_all_invites' }
  | { kind: 'resend_invite'; inviteId: string; now: boolean }
  | { kind: 'invite_allowed_email'; email: string };

const runInviteAction = (action: SelfHostInviteAction) => {
  switch (action.kind) {
    case 'revoke_link':
      return selfHostClient.revokeInviteLink(action.teamId);
    case 'revoke_all_links':
      return selfHostClient.revokeAllInviteLinks();
    case 'revoke_invite':
      return selfHostClient.revokeInvite(action.inviteId);
    case 'revoke_all_invites':
      return selfHostClient.revokeAllInvites();
    case 'resend_invite':
      return selfHostClient.resendInvite(action.inviteId, action.now);
    case 'invite_allowed_email':
      return selfHostClient.inviteAllowedEmail(action.email);
  }
};

/** Revokes, resends or sends invites; refreshes the panel either way. */
export function useSelfHostInviteActionMutation() {
  return useMutation(() => ({
    mutationFn: (action: SelfHostInviteAction) =>
      throwOnErr(() => runInviteAction(action)),
    onSettled: invalidateAdmin,
  }));
}

const usersQueryOptions = queryOptions({
  queryKey: selfHostKeys.users,
  queryFn: () => throwOnErr(selfHostClient.users),
});

const signupsQueryOptions = queryOptions({
  queryKey: selfHostKeys.signups,
  queryFn: () => throwOnErr(selfHostClient.signups),
});

export function useSelfHostUsersQuery() {
  return useQuery(() => usersQueryOptions);
}

export function useSelfHostSignupsQuery() {
  return useQuery(() => signupsQueryOptions);
}

const auditQueryOptions = (filter: SelfHostAuditFilter) =>
  infiniteQueryOptions({
    queryKey: [...selfHostKeys.audit, filter] as const,
    queryFn: ({ pageParam }) =>
      throwOnErr(() => selfHostClient.audit(filter, pageParam)),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (lastPage) =>
      lastPage.entries.length > 0
        ? (lastPage.next_before ?? undefined)
        : undefined,
  });

/** Audit entries matching `filter`, newest first, a page at a time. */
export function useSelfHostAuditQuery(filter: Accessor<SelfHostAuditFilter>) {
  return useInfiniteQuery(() => auditQueryOptions(filter()));
}

export function useSetSelfHostAdminMutation() {
  return useMutation(() => ({
    mutationFn: (input: { userId: string; admin: boolean }) =>
      throwOnErr(() => selfHostClient.setAdmin(input.userId, input.admin)),
    onSettled: invalidateAdmin,
  }));
}

export function useSetSelfHostDisabledMutation() {
  return useMutation(() => ({
    mutationFn: (input: { userId: string; disabled: boolean }) =>
      throwOnErr(() =>
        selfHostClient.setDisabled(input.userId, input.disabled)
      ),
    onSettled: invalidateAdmin,
  }));
}

export function useSetSelfHostPolicyMutation() {
  return useMutation(() => ({
    mutationFn: (policy: SelfHostSignupPolicy) =>
      throwOnErr(() => selfHostClient.setPolicy(policy)),
    onSettled: invalidateAdmin,
  }));
}

export function useAllowedEmailMutation() {
  return useMutation(() => ({
    mutationFn: (input: { email: string; remove: boolean; notify?: boolean }) =>
      throwOnErr(() =>
        input.remove
          ? selfHostClient.removeAllowedEmail(input.email)
          : selfHostClient.addAllowedEmail(input.email, input.notify ?? false)
      ),
    onSettled: invalidateAdmin,
  }));
}

const MAIL_PAGE = 50;

const mailQueryOptions = (search: string) =>
  infiniteQueryOptions({
    queryKey: [...selfHostKeys.mail, 'list', search] as const,
    queryFn: ({ pageParam }) =>
      throwOnErr(() => selfHostClient.mail(search, pageParam)),
    initialPageParam: 0,
    getNextPageParam: (lastPage, pages) => {
      const loaded = pages.length * MAIL_PAGE;
      return lastPage.messages.length > 0 && loaded < lastPage.total
        ? loaded
        : undefined;
    },
    // New sign-in codes arrive while an admin waits for them.
    refetchInterval: 15_000,
  });

/** Captured outgoing mail matching `search`, newest first, a page at a time. */
export function useSelfHostMailQuery(search: Accessor<string>) {
  return useInfiniteQuery(() => mailQueryOptions(search()));
}

/** One captured message with its bodies; nothing is fetched while `id` is empty. */
export function useSelfHostMailMessageQuery(id: Accessor<string | undefined>) {
  return useQuery(() => ({
    queryKey: [...selfHostKeys.mail, 'message', id()] as const,
    queryFn: () => throwOnErr(() => selfHostClient.mailMessage(id() ?? '')),
    enabled: Boolean(id()),
  }));
}

/** Deletes one captured message, or every one when `id` is absent. */
export function useDeleteSelfHostMailMutation() {
  return useMutation(() => ({
    mutationFn: (id?: string) =>
      throwOnErr(() =>
        id ? selfHostClient.deleteMail(id) : selfHostClient.clearMail()
      ),
    onSettled: invalidateAdmin,
  }));
}
