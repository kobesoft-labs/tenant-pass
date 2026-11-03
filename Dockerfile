# Reproducible, minimal images:
#   - static binaries (CGO disabled), built with -trimpath
#   - distroless "static" base: no shell, no package manager
#   - run as an unprivileged user (nonroot, uid 65532)
# Base images are pinned by digest; Dependabot updates them.
#
#   docker build --target tenant-pass         -t tenant-pass .
#   docker build --target tenant-pass-gateway -t tenant-pass-gateway .
#
# The two components hold different keys (the gateway signs passes;
# tenant-pass derives passwords). Run them as separate images, never in
# one container.

FROM golang:1.26-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=${VERSION}" -o /out/tenant-pass ./cmd/tenant-pass && \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=${VERSION}" -o /out/tenant-pass-gateway ./cmd/tenant-pass-gateway

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS tenant-pass-gateway
COPY --from=build /out/tenant-pass-gateway /usr/local/bin/tenant-pass-gateway
USER nonroot:nonroot
EXPOSE 9180
ENTRYPOINT ["/usr/local/bin/tenant-pass-gateway"]
CMD ["serve", "-config", "/etc/tenant-pass-gateway/config.json"]

# Last stage = default target.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS tenant-pass
COPY --from=build /out/tenant-pass /usr/local/bin/tenant-pass
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/tenant-pass"]
CMD ["serve", "-config", "/etc/tenant-pass/config.json"]
