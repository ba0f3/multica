import { queryOptions } from "@tanstack/react-query";
import { api } from "../api";

export const gitIdentityKeys = { profile: (userId: string) => ["git-identities", userId] as const };
export const gitIdentityOptions = (userId: string) => queryOptions({
  queryKey: gitIdentityKeys.profile(userId), queryFn: () => api.getGitIdentities(), enabled: !!userId,
});
export type { GitIdentity, GitProfile } from "../api/git-schemas";
