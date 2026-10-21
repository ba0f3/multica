# Task worker image for Docker-isolated agent attempts.
# Build from repo root:
#   docker build -f docker/task-worker/Dockerfile -t multica/task-worker:local .
FROM golang:1.26.9-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY server/go.mod server/go.sum ./server/
RUN cd server && go mod download
COPY server/ ./server/
ARG VERSION=dev
ARG COMMIT=unknown
RUN cd server && CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" -o /out/multica ./cmd/multica

FROM alpine:3.21
RUN apk add --no-cache ca-certificates git openssh-client bash
COPY --from=builder /out/multica /usr/local/bin/multica
USER 65532:65532
WORKDIR /workspace/repo
ENTRYPOINT ["/usr/local/bin/multica"]
