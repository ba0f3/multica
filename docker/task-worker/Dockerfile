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

# glibc-based runtime so host-discovered agent CLIs (codex, cursor, opencode) can
# be bind-mounted into the worker at run time (see sandbox.DockerAgentBinaryBind).
FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git openssh-client bash \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/multica /usr/local/bin/multica
USER 65532:65532
WORKDIR /workspace/repo
# No ENTRYPOINT: `docker run <image> multica <worker-arg>` supplies argv (see sandbox.BuildDockerRunArgs).
