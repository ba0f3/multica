"use client";

import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@multica/ui/components/ui/button";
import { Input } from "@multica/ui/components/ui/input";
import { Label } from "@multica/ui/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@multica/ui/components/ui/select";
import { Textarea } from "@multica/ui/components/ui/textarea";
import { useConfigStore } from "@multica/core/config";
import { useCreateGitProvider } from "@multica/core/git-identities";
import { useT } from "../../i18n";
import { SettingsCard, SettingsSection } from "./settings-layout";

function parseHostPins(raw: string): string[] {
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

/**
 * Deployment-scoped Git SSH hosts. One configuration serves every workspace on
 * this server; users generate keys per provider below.
 */
export function GitProvidersAdminSection() {
  const { t } = useT("settings");
  const manageable = useConfigStore((s) => s.gitSshProvidersManageable);
  const create = useCreateGitProvider();

  const [label, setLabel] = useState("");
  const [kind, setKind] = useState<"github" | "gitea">("gitea");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("22");
  const [hostPins, setHostPins] = useState("");

  if (!manageable) return null;

  const handleSubmit = () => {
    const parsedPort = Number.parseInt(port, 10);
    const pins = parseHostPins(hostPins);
    if (!label.trim() || !host.trim() || !Number.isFinite(parsedPort) || pins.length === 0) {
      toast.error(t(($) => $.git_providers.toast_invalid));
      return;
    }
    create.mutate(
      {
        label: label.trim(),
        kind,
        host: host.trim(),
        port: parsedPort,
        host_pins: pins,
      },
      {
        onSuccess: () => {
          toast.success(t(($) => $.git_providers.toast_created));
          setLabel("");
          setHost("");
          setHostPins("");
        },
        onError: (error: unknown) => {
          toast.error(
            error instanceof Error
              ? error.message
              : t(($) => $.git_providers.toast_create_failed),
          );
        },
      },
    );
  };

  return (
    <SettingsSection
      title={t(($) => $.git_providers.section_title)}
      description={t(($) => $.git_providers.section_description)}
    >
      <SettingsCard>
        <div className="flex flex-col gap-3 px-4 py-3.5">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="git-provider-label">{t(($) => $.git_providers.label)}</Label>
              <Input
                id="git-provider-label"
                value={label}
                onChange={(event) => setLabel(event.target.value)}
                placeholder="Gitea local"
              />
            </div>
            <div className="space-y-1.5">
              <Label>{t(($) => $.git_providers.kind)}</Label>
              <Select value={kind} onValueChange={(value) => setKind(value as "github" | "gitea")}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="github">GitHub</SelectItem>
                  <SelectItem value="gitea">Gitea / Forgejo</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="git-provider-host">{t(($) => $.git_providers.host)}</Label>
              <Input
                id="git-provider-host"
                value={host}
                onChange={(event) => setHost(event.target.value)}
                placeholder="gitea.example.com"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="git-provider-port">{t(($) => $.git_providers.port)}</Label>
              <Input
                id="git-provider-port"
                inputMode="numeric"
                value={port}
                onChange={(event) => setPort(event.target.value)}
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="git-provider-pins">{t(($) => $.git_providers.host_pins)}</Label>
            <Textarea
              id="git-provider-pins"
              value={hostPins}
              onChange={(event) => setHostPins(event.target.value)}
              rows={4}
              placeholder="SHA256:…"
              className="font-mono text-caption"
            />
          </div>
          <div className="flex justify-end">
            <Button type="button" onClick={handleSubmit} disabled={create.isPending}>
              {t(($) => $.git_providers.add)}
            </Button>
          </div>
        </div>
      </SettingsCard>
    </SettingsSection>
  );
}
