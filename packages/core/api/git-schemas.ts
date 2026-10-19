import { z } from "zod";
import { parseWithFallback } from "./schema";

export const GitIdentitySchema = z.object({
  id: z.string().uuid(), user_id: z.string().uuid(), provider_id: z.string().uuid(),
  generation: z.number().int().positive(), public_key: z.string().regex(/^(?:ssh-ed25519 [A-Za-z0-9+/]+={0,2})?$/), fingerprint: z.string().regex(/^(?:SHA256:[A-Za-z0-9+/]+)?$/),
  state: z.string(), active: z.boolean().default(false), cleanup_pending: z.boolean().default(false),
  diagnostic: z.string().optional(), login: z.string().optional(), account_id: z.string().optional(),
  verified_at: z.string().optional(), consent_project_ids: z.array(z.string().uuid()).default([]),
});
export const GitProfileSchema = z.object({
  management_available: z.boolean().default(false),
  providers: z.array(z.object({ id: z.string().uuid(), label: z.string(), kind: z.string(), host: z.string(), port: z.number().int() })),
  projects: z.array(z.object({ id: z.string().uuid(), title: z.string() })).default([]),
  identities: z.array(GitIdentitySchema),
});
export type GitIdentity = z.infer<typeof GitIdentitySchema>;
export type GitProfile = z.infer<typeof GitProfileSchema>;
export const emptyGitProfile: GitProfile = { management_available: false, providers: [], projects: [], identities: [] };

export const GitRunSchema = z.object({
  execution_available: z.boolean().default(false),
  context: z.object({
    id: z.string().uuid(), attempt_id: z.string().uuid(), root_id: z.string().uuid(), parent_id: z.string(),
    policy_epoch: z.number().int().positive(), depth: z.number().int().nonnegative(), issued_at: z.string(), expires_at: z.string(),
    binding: z.object({ task_id: z.string().uuid(), agent_id: z.string().uuid(), runtime_id: z.string().uuid(), execution_workspace_id: z.string().uuid(), resource_workspace_id: z.string().uuid(), project_id: z.string().uuid(), originator_user_id: z.string().uuid(), originator_source: z.string(), parent_task_id: z.string() }),
  }),
  grant: z.object({
    id: z.string().uuid(), context_id: z.string().uuid(), provider_id: z.string().uuid(), repository_id: z.string().uuid(), identity_id: z.string().uuid(), credential_generation: z.number().int().positive(), epoch: z.number().int().positive(), operations: z.array(z.string()), write_refs: z.array(z.string()).nullable().default([]), issued_at: z.string(), expires_at: z.string(),
  }),
});
export type GitRun = z.infer<typeof GitRunSchema>;
export const GitOutputReceiptSchema = z.object({ id: z.string().uuid() });
export function parseGitOutputReceipt(raw: unknown): { id: string } {
  const checked = GitOutputReceiptSchema.safeParse(raw);
  const result = parseWithFallback<{ id: string } | null>(checked.success ? checked.data : undefined, GitOutputReceiptSchema, null, { endpoint: "/api/git-runs/*/outputs" });
  if (!result) throw new Error("Invalid Git output receipt");
  return result;
}
export interface GitRunRequest { agent_id: string; issue_id: string; repository_id: string; operations: ("read" | "write")[]; write_refs?: string[] }
export function parseGitRun(raw: unknown): GitRun {
  const checked = GitRunSchema.safeParse(raw);
  const result = parseWithFallback<GitRun | null>(checked.success ? checked.data : undefined, GitRunSchema, null, { endpoint: "/api/me/git-runs/*" });
  if (!result) throw new Error("Invalid Git run response");
  return result;
}
export function parseGitAcknowledgement(raw: unknown, field: "locally_revoked" | "cleanup_complete"): void {
  const schema = z.object({ [field]: z.literal(true) });
  const checked = schema.safeParse(raw);
  if (!parseWithFallback(checked.success ? checked.data : undefined, schema, null, { endpoint: "/api/me/git-identities/*" })) throw new Error("Invalid Git action response");
}

export function parseGitProfile(raw: unknown): GitProfile {
  // Schema logging must never receive an unexpected private field from a
  // malformed server response. Successful parsing strips unknown fields too.
  const checked = GitProfileSchema.safeParse(raw);
  return parseWithFallback(checked.success ? checked.data : undefined, GitProfileSchema, emptyGitProfile, { endpoint: "/api/me/git-identities" });
}
export function parseGitIdentity(raw: unknown): GitIdentity {
  const checked = GitIdentitySchema.safeParse(raw);
  const result = parseWithFallback<GitIdentity | null>(checked.success ? checked.data : undefined, GitIdentitySchema, null, { endpoint: "/api/me/git-identities/*" });
  if (!result) throw new Error("Invalid Git identity response");
  return result;
}
