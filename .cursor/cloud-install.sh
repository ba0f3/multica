#!/usr/bin/env bash
# Idempotent Cloud Agent install. Toolchains and packages only — no daemons.
# Go is linked into /usr/local/bin because login shells do not load nvm-style
# rc edits, and Ubuntu's /usr/bin/go is older than the module requirement.
set -euo pipefail

export PATH="/usr/local/bin:${PATH}"

# sudo drops DEBIAN_FRONTEND, and fuse3's conffile prompt otherwise blocks the build.
apt_get() {
  sudo DEBIAN_FRONTEND=noninteractive apt-get \
    -o Dpkg::Options::=--force-confdef \
    -o Dpkg::Options::=--force-confold \
    "$@"
}

if [ ! -f package.json ] || [ ! -f Makefile ]; then
  echo "Run cloud-install.sh from the repository root." >&2
  exit 1
fi

GO_VERSION=1.27.3
GO_SHA256=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40

if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go${GO_VERSION} "; then
  tmp="$(mktemp)"
  curl -fsSL -o "$tmp" "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
  echo "${GO_SHA256}  ${tmp}" | sha256sum -c -
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "$tmp"
  rm -f "$tmp"
fi
sudo ln -sfn /usr/local/go/bin/go /usr/local/bin/go
sudo ln -sfn /usr/local/go/bin/gofmt /usr/local/bin/gofmt
hash -r

apt_get update
# iproute2 provides `ss`. scripts/dev-env.sh uses it when lsof cannot see a
# Node listener, and without it `make up` rejects a healthy Next.js server.
apt_get install -y --no-install-recommends \
  ca-certificates curl gnupg build-essential fuse-overlayfs iptables iproute2

# Docker's apt repository, not Ubuntu's docker.io: `make up` calls
# `docker compose`, which the Compose v2 plugin provides.
if ! command -v docker >/dev/null 2>&1; then
  sudo install -m 0755 -d /etc/apt/keyrings
  if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
  fi
  codename="$(. /etc/os-release && printf '%s' "$VERSION_CODENAME")"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${codename} stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  apt_get update
  apt_get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

# overlay2 cannot mount on this VM's overlay-backed root. fuse-overlayfs can.
# cgroup-parent avoids cgroup v2 threaded-mode failures inside the agent VM.
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json >/dev/null <<'EOF'
{
  "storage-driver": "fuse-overlayfs",
  "cgroup-parent": "system.slice"
}
EOF

if [ -x /usr/sbin/iptables-legacy ]; then
  sudo update-alternatives --set iptables /usr/sbin/iptables-legacy
fi
if [ -x /usr/sbin/ip6tables-legacy ]; then
  sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
fi

sudo groupadd -f docker
sudo usermod -aG docker "$(id -un)"

pnpm install --frozen-lockfile
(cd server && go mod download)
(cd server && go build ./cmd/server ./cmd/migrate)
