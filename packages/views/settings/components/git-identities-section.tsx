"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@multica/core/api";
import { gitIdentityOptions } from "@multica/core/git-identities";
import { Button } from "@multica/ui/components/ui/button";
import { copyText } from "@multica/ui/lib/clipboard";
import { useT } from "../../i18n";
import { SettingsCard, SettingsSection } from "./settings-layout";

export function GitIdentitiesSection({ userId }: { userId: string }) {
  const { t } = useT("settings");
  const queryClient = useQueryClient();
  const options = gitIdentityOptions(userId);
  const query = useQuery(options);
  const [provider, setProvider] = useState("");
  const [projects, setProjects] = useState<string[]>([]);
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const [request, setRequest] = useState<{ intent: string; id: string } | null>(null);
  const [message, setMessage] = useState("");
  const action = useMutation({
    mutationFn: (work: () => Promise<unknown>) => work(),
    onSuccess: () => { setConfirmRevoke(null); setRequest(null); setMessage(""); },
    onError: (error) => setMessage(error instanceof Error && /git_(recent_auth|human_session)_required/.test(error.message) ? t(($) => $.git_identities.reauth) : t(($) => $.git_identities.failed)),
    onSettled: () => queryClient.invalidateQueries({ queryKey: options.queryKey }),
  });
  const profile = query.data;
  const available = profile?.management_available === true;
  const busy = action.isPending;
  const generate = (providerId: string, scope = projects) => {
    const intent = JSON.stringify([providerId, [...scope].sort()]);
    const id = request?.intent === intent ? request.id : crypto.randomUUID(); setRequest({ intent, id });
    action.mutate(() => api.generateGitIdentity(providerId, scope, id));
  };
  return <SettingsSection title={t(($) => $.git_identities.title)}>
    <SettingsCard>
      <div className="space-y-4 p-4">
        <p className="text-caption text-muted-foreground">{t(($) => $.git_identities.custody)}</p>
        {query.isPending && <p role="status">{t(($) => $.git_identities.loading)}</p>}
        {query.isError && <p role="alert">{t(($) => $.git_identities.failed)}</p>}
        {profile && !available && <p role="status">{t(($) => $.git_identities.unavailable)}</p>}
        <label className="block">{t(($) => $.git_identities.provider)}
          <select aria-label={t(($) => $.git_identities.provider)} value={provider} disabled={busy || !available} onChange={(event) => { setProvider(event.target.value); setRequest(null); }} className="ml-2 rounded border bg-background p-1">
            <option value="">{t(($) => $.git_identities.choose)}</option>
            {profile?.providers.map((p) => <option key={p.id} value={p.id}>{p.label} ({p.host})</option>)}
          </select>
        </label>
        <fieldset disabled={busy || !available} className="space-y-2">
          <legend>{t(($) => $.git_identities.projects)}</legend>
          {profile?.projects.map((project) => <label key={project.id} className="flex items-center gap-2">
            <input type="checkbox" checked={projects.includes(project.id)} onChange={(event) => { setProjects((old) => event.target.checked ? [...old, project.id] : old.filter((id) => id !== project.id)); setRequest(null); }} />{project.title}
          </label>)}
        </fieldset>
        <Button disabled={busy || !available || !provider} aria-busy={busy} onClick={() => generate(provider)}>{t(($) => $.git_identities.generate)}</Button>
        {message && <p role="alert">{message}</p>}
        <p className="text-caption text-muted-foreground">{t(($) => $.git_identities.registration)}</p>
        {profile?.identities.map((key) => <article key={`${key.id}:${key.generation}`} className="space-y-2 rounded border p-3">
          <p>{key.login || profile.providers.find((p) => p.id === key.provider_id)?.label} · {t(($) => $.git_identities.generation)} {key.generation}</p>
          <p role="status">{key.state}{key.active ? ` · ${t(($) => $.git_identities.active)}` : ""}</p>
          {key.public_key && <><textarea readOnly aria-label={t(($) => $.git_identities.public_key)} value={key.public_key} className="w-full resize-none break-all bg-muted p-2 text-caption" /><p className="break-all font-mono text-caption">{key.fingerprint}</p>
            <Button variant="outline" onClick={async () => { if (await copyText(key.public_key)) setMessage(t(($) => $.git_identities.copied)); }}>{t(($) => $.git_identities.copy)}</Button></>}
          {key.diagnostic && <p role="alert">{t(($) => $.git_identities.diagnostic)}</p>}
          <div className="flex flex-wrap gap-2">
            {key.state === "pending_verification" && <Button disabled={busy || !available} onClick={() => action.mutate(() => api.gitIdentityAction(key.id, key.generation, "verify"))}>{t(($) => $.git_identities.verify)}</Button>}
            {key.state === "ready" && !key.active && <Button disabled={busy || !available} onClick={() => action.mutate(() => api.gitIdentityAction(key.id, key.generation, "activate"))}>{t(($) => $.git_identities.activate)}</Button>}
            {key.active && <Button variant="outline" disabled={busy || !available} onClick={() => generate(key.provider_id, key.consent_project_ids)}>{t(($) => $.git_identities.rotate)}</Button>}
            {key.state !== "revoked" && <Button variant="outline" disabled={busy} onClick={() => setConfirmRevoke(`${key.id}:${key.generation}`)}>{t(($) => $.git_identities.revoke)}</Button>}
            {key.cleanup_pending && <><p role="status">{t(($) => $.git_identities.cleanup_pending)}</p><Button variant="outline" disabled={busy || !available} onClick={() => action.mutate(() => api.cleanupGitIdentity(key.id))}>{t(($) => $.git_identities.cleanup)}</Button></>}
          </div>
          {confirmRevoke === `${key.id}:${key.generation}` && <div className="space-y-2"><p>{t(($) => $.git_identities.revoke_warning)}</p><Button variant="destructive" disabled={busy} onClick={() => action.mutate(() => api.revokeGitIdentity(key.id))}>{t(($) => $.git_identities.confirm_revoke)}</Button><Button variant="outline" onClick={() => setConfirmRevoke(null)}>{t(($) => $.git_identities.cancel)}</Button></div>}
        </article>)}
      </div>
    </SettingsCard>
  </SettingsSection>;
}
