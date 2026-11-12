import { throwOnErr } from '@core/util/result';
import { queryClient } from '@queries/client';
import {
  type SelfHostSignupPolicy,
  selfHostClient,
} from '@service-auth/selfhost';
import { queryOptions, useMutation, useQuery } from '@tanstack/solid-query';

const selfHostKeys = {
  users: ['selfhost', 'admin', 'users'] as const,
  signups: ['selfhost', 'admin', 'signups'] as const,
};

const invalidateAdmin = () =>
  Promise.all([
    queryClient.invalidateQueries({ queryKey: selfHostKeys.users }),
    queryClient.invalidateQueries({ queryKey: selfHostKeys.signups }),
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

export function useSetSelfHostAdminMutation() {
  return useMutation(() => ({
    mutationFn: (input: { userId: string; admin: boolean }) =>
      throwOnErr(() => selfHostClient.setAdmin(input.userId, input.admin)),
    onSuccess: invalidateAdmin,
  }));
}

export function useSetSelfHostDisabledMutation() {
  return useMutation(() => ({
    mutationFn: (input: { userId: string; disabled: boolean }) =>
      throwOnErr(() =>
        selfHostClient.setDisabled(input.userId, input.disabled)
      ),
    onSuccess: invalidateAdmin,
  }));
}

export function useSetSelfHostPolicyMutation() {
  return useMutation(() => ({
    mutationFn: (policy: SelfHostSignupPolicy) =>
      throwOnErr(() => selfHostClient.setPolicy(policy)),
    onSuccess: invalidateAdmin,
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
    onSuccess: invalidateAdmin,
  }));
}
