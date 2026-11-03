#!/usr/bin/env bash
# Per-boot services. Safe to rerun: Docker is skipped when healthy, and
# `make up` reuses this checkout's database and any component already healthy.
set -euo pipefail

export PATH="/usr/local/bin:${PATH}"

if [ ! -f package.json ] || [ ! -f Makefile ]; then
  echo "Run cloud-start.sh from the repository root." >&2
  exit 1
fi

if [ -x /usr/sbin/iptables-legacy ]; then
  sudo update-alternatives --set iptables /usr/sbin/iptables-legacy
fi
if [ -x /usr/sbin/ip6tables-legacy ]; then
  sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
fi

docker_ready() {
  docker info >/dev/null 2>&1
}

if ! docker_ready && [ -S /var/run/docker.sock ]; then
  sudo chmod 666 /var/run/docker.sock || true
fi

if ! docker_ready; then
  # service(8) starts dockerd without systemd. Fall back to the binary when
  # the init script is missing, which is the usual nested-container case.
  if ! sudo service docker start; then
    sudo nohup dockerd >/var/log/dockerd.log 2>&1 &
  fi
fi

ready=0
for _ in $(seq 1 90); do
  if [ -S /var/run/docker.sock ]; then
    sudo chmod 666 /var/run/docker.sock || true
  fi
  if docker_ready; then
    ready=1
    break
  fi
  sleep 1
done

if [ "$ready" != 1 ]; then
  echo "Docker daemon did not become ready." >&2
  sudo tail -n 80 /var/log/dockerd.log >&2 || true
  exit 1
fi

make up
