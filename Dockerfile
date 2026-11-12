# syntax=docker/dockerfile:1

# The build stage runs on the builder's own platform and cross-compiles, so a
# multi-platform build needs no emulation. The SQLite driver is pure Go, so
# cgo stays off.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X tule.dev/identity/internal/util/buildinfo.Version=${VERSION}" \
    -o /out/tule-identity ./cmd \
 && mkdir -p /out/data

# Alpine rather than distroless, for a shell to debug in and wget for the
# health check.
FROM alpine:3.24
# 65532 is the distroless nonroot user's UID and GID, which keeps a volume
# written by this image usable by the other tule service images.
RUN addgroup -S -g 65532 nonroot && adduser -S -u 65532 -G nonroot nonroot
# gas/config reads .env from the working directory and refuses to when that is
# /, so the server must not start there.
WORKDIR /home/nonroot
LABEL org.opencontainers.image.source=https://github.com/tulehq/identity \
      org.opencontainers.image.description="AWS IAM- and STS-compatible identity service for local development and end-to-end tests" \
      org.opencontainers.image.licenses=MIT
COPY --from=build /out/tule-identity /tule-identity
COPY --from=build --chown=nonroot:nonroot /out/data /data

# TULE_Auth_AccessKeyID and TULE_Auth_SecretAccessKey, the root user's key,
# must be set at run time; the image ships no default so it cannot come up
# accepting a key everyone knows. Users, keys and role sessions live in one
# SQLite file on the /data volume.
ENV TULE_GasEnv=development \
    TULE_Store_Path=/data/identity.db

USER nonroot
EXPOSE 9030
VOLUME /data
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${TULE_Server_Port:-9030}/_ready" || exit 1
ENTRYPOINT ["/tule-identity"]
