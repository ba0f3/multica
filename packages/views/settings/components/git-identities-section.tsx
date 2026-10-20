"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Copy, KeyRound, ShieldCheck, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@multica/ui/components/ui/badge";
import { Button } from "@multica/ui/components/ui/button";
import { Input } from "@multica/ui/components/ui/input";
import { useAuthStore } from "@multica/core/auth";
import {
  gitIdentityListOptions,
  useGenerateGitIdentity,
  useRevokeGitIdentity,
  useVerifyGitIdentity,
} from "@multica/core/git-identities";
import type { GitIdentity, GitProvider } from "@multica/core/types";
import { createSafeId } from "@multica/core/utils";
import { useT } from "../../i18n";
import { SettingsCard, SettingsSection } from "./settings-layout";

/**
 * Per-user Git credentials.
 *
 * The browser only ever sees public keys. A private key is created on the
 * server, kept in the server's encrypted custody store, and is never part of
 * a response — so there is no view, download or export control here, and
 * there is nothing to copy but the public key.
 */
export function GitIdentitiesSection() {
  const { t } = useT("settings");
  const userID = useAuthStore((state) => state.user?.id ?? null);
  const { data } = useQuery({
    ...gitIdentityListOptions(userID ?? ""),
    enabled: !!userID,
  });
  const generate = useGenerateGitIdentity();
  const verify = useVerifyGitIdentity();
  const revoke = useRevokeGitIdentity();

  // One request id per provider attempt. It is reused until the call
  // succeeds so a retry after a failed request cannot create a second key.
  const [requestIDs, setRequestIDs] = useState<Record<string, string>>({});

  const providers = data?.providers ?? [];

  const identitiesByProvider = useMemo(() => {
    const grouped = new Map<string, GitIdentity[]>();
    for (const identity of data?.identities ?? []) {
      const bucket = grouped.get(identity.provider_id) ?? [];
      bucket.push(identity);
      grouped.set(identity.provider_id, bucket);
    }
    return grouped;
  }, [data?.identities]);

  if (!userID) return null;

  if (providers.length === 0) {
    return (
      <SettingsSection
        title={t(($) => $.git_identities.section_title)}
        description={t(($) => $.git_identities.no_providers)}
      >
        <SettingsCard>
          <div className="px-4 py-3.5 text-caption text-muted-foreground">
            {t(($) => $.git_identities.no_providers)}
          </div>
        </SettingsCard>
      </SettingsSection>
    );
  }

  const requestIDFor = (providerID: string) => {
    const existing = requestIDs[providerID];
    if (existing) return existing;
    const created = createSafeId();
    setRequestIDs((current) => ({ ...current, [providerID]: created }));
    return created;
  };

  const handleGenerate = (provider: GitProvider) => {
    const requestID = requestIDFor(provider.id);
    generate.mutate(
      {
        provider_id: provider.id,
        request_id: requestID,
        consent_project_ids: [],
      },
      {
        onSuccess: () => {
          setRequestIDs((current) => {
            const next = { ...current };
            delete next[provider.id];
            return next;
          });
        },
        onError: (error: unknown) => {
          toast.error(
            error instanceof Error
              ? error.message
              : t(($) => $.git_identities.toast_generate_failed),
          );
        },
      },
    );
  };

  const handleVerify = (identity: GitIdentity) => {
    verify.mutate(
      { identityId: identity.id, generation: identity.generation },
      {
        onError: (error: unknown) => {
          toast.error(
            error instanceof Error
              ? error.message
              : t(($) => $.git_identities.toast_verify_failed),
          );
        },
      },
    );
  };

  const handleRevoke = (identity: GitIdentity) => {
    revoke.mutate(identity.id, {
      onError: (error: unknown) => {
        toast.error(
          error instanceof Error
            ? error.message
            : t(($) => $.git_identities.toast_revoke_failed),
        );
      },
    });
  };

  return (
    <SettingsSection
      title={t(($) => $.git_identities.section_title)}
      description={t(($) => $.git_identities.section_description)}
    >
      <SettingsCard>
        {providers.map((provider) => {
          const providerIdentities = identitiesByProvider.get(provider.id) ?? [];
          return (
            <div key={provider.id} className="px-4 py-3.5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex min-w-0 items-center gap-2">
                  <KeyRound className="size-4 shrink-0 text-muted-foreground" />
                  <span className="truncate text-body font-medium">
                    {provider.label}
                  </span>
                  <span className="text-caption text-muted-foreground">
                    {provider.host}
                  </span>
                </div>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => handleGenerate(provider)}
                  disabled={generate.isPending}
                >
                  {t(($) => $.git_identities.generate)}
                </Button>
              </div>

              {providerIdentities.length === 0 ? (
                <p className="mt-2 text-caption text-muted-foreground">
                  {t(($) => $.git_identities.no_keys)}
                </p>
              ) : (
                <ul className="mt-3 space-y-3">
                  {providerIdentities.map((identity) => (
                    <li
                      key={`${identity.id}-${identity.generation}`}
                      className="rounded-md border border-surface-border p-3"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-mono text-caption text-muted-foreground">
                          {identity.fingerprint}
                        </span>
                        <GitIdentityStateBadge state={identity.state} />
                      </div>

                      <div className="mt-2 flex items-center gap-2">
                        <Input
                          readOnly
                          value={identity.public_key}
                          aria-label={t(($) => $.git_identities.public_key)}
                          className="font-mono text-caption"
                          onFocus={(event) => event.currentTarget.select()}
                        />
                        <Button
                          type="button"
                          size="icon"
                          variant="ghost"
                          aria-label={t(($) => $.git_identities.copy_public_key)}
                          onClick={() => {
                            void navigator.clipboard
                              ?.writeText(identity.public_key)
                              .then(() =>
                                toast.success(
                                  t(($) => $.git_identities.toast_copied),
                                ),
                              )
                              .catch(() =>
                                toast.error(
                                  t(($) => $.git_identities.toast_copy_failed),
                                ),
                              );
                          }}
                        >
                          <Copy className="size-4" />
                        </Button>
                      </div>

                      <div className="mt-2 flex flex-wrap items-center gap-2">
                        {identity.state === "pending_verification" ? (
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            onClick={() => handleVerify(identity)}
                            disabled={verify.isPending}
                          >
                            <ShieldCheck className="size-4" />
                            {t(($) => $.git_identities.verify)}
                          </Button>
                        ) : null}
                        {identity.state !== "revoked" ? (
                          <Button
                            type="button"
                            size="sm"
                            variant="ghost"
                            onClick={() => handleRevoke(identity)}
                            disabled={revoke.isPending}
                          >
                            <Trash2 className="size-4" />
                            {t(($) => $.git_identities.revoke)}
                          </Button>
                        ) : null}
                      </div>

                      {identity.state === "pending_verification" ? (
                        <p className="mt-2 text-caption text-muted-foreground">
                          {t(($) => $.git_identities.pending_hint)}
                        </p>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          );
        })}
      </SettingsCard>
    </SettingsSection>
  );
}

function GitIdentityStateBadge({ state }: { state: string }) {
  const { t } = useT("settings");
  switch (state) {
    case "ready":
      return (
        <Badge variant="secondary">{t(($) => $.git_identities.state_ready)}</Badge>
      );
    case "pending_verification":
      return (
        <Badge variant="outline">
          {t(($) => $.git_identities.state_pending)}
        </Badge>
      );
    case "revoked":
      return (
        <Badge variant="destructive">
          {t(($) => $.git_identities.state_revoked)}
        </Badge>
      );
    default:
      return <Badge variant="outline">{state}</Badge>;
  }
}
