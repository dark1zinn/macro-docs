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
  audit: ['selfhost', 'admin', 'audit'] as const,
};

/** Every admin action changes state and adds an audit entry. */
const invalidateAdmin = () =>
  Promise.all([
    queryClient.invalidateQueries({ queryKey: selfHostKeys.users }),
    queryClient.invalidateQueries({ queryKey: selfHostKeys.signups }),
    queryClient.invalidateQueries({ queryKey: selfHostKeys.audit }),
  ]);

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
    mutationFn: (input: { email: string; remove: boolean }) =>
      throwOnErr(() =>
        input.remove
          ? selfHostClient.removeAllowedEmail(input.email)
          : selfHostClient.addAllowedEmail(input.email)
      ),
    onSettled: invalidateAdmin,
  }));
}
