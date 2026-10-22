import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../api";
import { useAuthStore } from "../auth";
import { gitIdentityKeys } from "./queries";

/**
 * Git credential mutations.
 *
 * None of them is optimistic. A key has to be registered on the provider
 * before it is usable, and the state that matters — "pending verification",
 * "ready", "revoked" — is the server's answer, not a guess the UI makes.
 * An optimistic row would show a credential as usable before the server
 * agreed that it is.
 */
function useInvalidateGitIdentities() {
  const queryClient = useQueryClient();
  const userID = useAuthStore((state) => state.user?.id ?? null);
  return () => {
    if (!userID) return;
    void queryClient.invalidateQueries({ queryKey: gitIdentityKeys.all(userID) });
  };
}

export function useGenerateGitIdentity() {
  const invalidate = useInvalidateGitIdentities();
  return useMutation({
    mutationFn: (input: { provider_id: string; request_id: string }) =>
      api.generateGitIdentity(input),
    onSettled: invalidate,
  });
}

export function useVerifyGitIdentity() {
  const invalidate = useInvalidateGitIdentities();
  return useMutation({
    mutationFn: (input: { identityId: string; generation: number }) =>
      api.verifyGitIdentity(input.identityId, input.generation),
    onSettled: invalidate,
  });
}

export function useRevokeGitIdentity() {
  const invalidate = useInvalidateGitIdentities();
  return useMutation({
    mutationFn: (identityId: string) => api.revokeGitIdentity(identityId),
    onSettled: invalidate,
  });
}

export function useCreateGitProvider() {
  const invalidate = useInvalidateGitIdentities();
  return useMutation({
    mutationFn: (input: {
      label: string;
      kind: string;
      host: string;
      port: number;
      host_pins: string[];
    }) => api.createGitProvider(input),
    onSettled: invalidate,
  });
}
