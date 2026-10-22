import { queryOptions } from "@tanstack/react-query";
import { api } from "../api";

/**
 * Git credential queries.
 *
 * The credential list is account-scoped, not workspace-scoped: a user's Git
 * key belongs to the person, and the same key is used by every workspace
 * their agents run in. The key is therefore namespaced by the signed-in user
 * and carries no workspace id.
 */
export const gitIdentityKeys = {
  all: (userID: string) => ["git-identities", userID] as const,
  list: (userID: string) => [...gitIdentityKeys.all(userID), "list"] as const,
};

export function gitIdentityListOptions(userID: string) {
  return queryOptions({
    queryKey: gitIdentityKeys.list(userID),
    queryFn: () => api.listGitIdentities(),
  });
}
