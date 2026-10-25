# Task worker image for Docker-isolated agent attempts.
# Build from repo root:
#   docker build -f docker/task-worker/Dockerfile -t multica/task-worker:local .
FROM golang:1.27.3-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY server/go.mod server/go.sum ./server/
RUN cd server && go mod download
COPY server/ ./server/
ARG VERSION=dev
ARG COMMIT=unknown
RUN cd server && CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" -o /out/multica ./cmd/multica

# glibc-based runtime so host-discovered agent CLIs can be bind-mounted into
# the worker at run time (see sandbox.DockerAgentBinaryBind). Node 22 is the
# base so agents can build and test JS/TS projects without a host toolchain.
FROM node:22-bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates git git-lfs openssh-client bash ripgrep curl wget \
    build-essential pkg-config cmake autoconf automake libtool \
    python3 python3-pip python3-venv python3-dev \
    php-cli php-mbstring php-xml php-curl php-zip php-sqlite3 \
    unzip zip xz-utils bzip2 jq less procps sqlite3 postgresql-client \
    openssl libssl-dev zlib1g-dev libffi-dev libpq-dev libsqlite3-dev \
  && rm -rf /var/lib/apt/lists/*
# Go is copied from the builder stage (same release as the worker binary) so
# agents can build and test Go projects with the repository's toolchain.
COPY --from=builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
# Pin the package managers in a system-wide corepack home so the non-root task
# user uses the prepared versions instead of downloading the latest on first use.
ENV COREPACK_HOME=/usr/local/share/corepack
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN mkdir -p /usr/local/share/corepack \
  && corepack enable \
  && corepack prepare pnpm@9.15.0 --activate \
  && corepack prepare yarn@1.22.22 --activate
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
# The internal CA is baked into every worker image so agents can reach
# self-signed endpoints without per-daemon configuration. This is a fork
# customization: remove this file for an upstream or public build.
COPY docker/task-worker/ca/MUOI_TIEU_XANH.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates
COPY --from=builder /out/multica /usr/local/bin/multica
USER 65532:65532
WORKDIR /workspace/repo
# No ENTRYPOINT: `docker run <image> multica <worker-arg>` supplies argv (see sandbox.BuildDockerRunArgs).
