# An image holding just the kuzl binary, for other images to copy it from:
#   COPY --from=ghcr.io/evadcmd/kuzl:<tag> /kuzl /usr/local/bin/kuzl
# Built on the build platform and cross-compiled with GOOS / GOARCH, so a
# multi-platform build doesn't run the Go toolchain under emulation.
# golang:1.27 follows the latest 1.27 patch. The go line in go.mod is the
# floor: the image sets GOTOOLCHAIN=local, so an older toolchain fails the
# build instead of compiling with it.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS TARGETARCH
# VERSION is what --version and the default User-Agent say.
ARG VERSION=dev
# POLICY is the network policy built in, as make build's: a path in the build
# context. As there, it can't be empty, since a binary without a policy allows
# no host. See policy.yaml.
ARG POLICY=policy.yaml
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The policy is checked with kuzl policy, as make build does, run with go run
# for the build platform: a binary for the target may not run here.
# A missing file is checked first: base64 < "$POLICY" failing inside the
# pipe doesn't fail the RUN, so the policy would come out empty.
RUN set -eu; \
    [ -n "$POLICY" ] || { echo "POLICY is empty: a binary without a policy allows no host" >&2; exit 1; }; \
    [ -f "$POLICY" ] || { echo "POLICY=$POLICY does not exist" >&2; exit 1; }; \
    ldflags="-s -w -X github.com/evadcmd/kuzl/internal/cli.version=$VERSION"; \
    ldflags="$ldflags -X github.com/evadcmd/kuzl/internal/config.builtin=$(base64 < "$POLICY" | tr -d '\n')"; \
    go run -ldflags "$ldflags" ./cmd/kuzl policy; \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
        go build -trimpath -ldflags "$ldflags" -o /out/kuzl ./cmd/kuzl

FROM scratch
# Links the GHCR package to this repo.
LABEL org.opencontainers.image.source=https://github.com/evadcmd/kuzl
COPY --from=build /out/kuzl /kuzl
