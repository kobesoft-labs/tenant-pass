# Reproducible, minimal image:
#   - static binary (CGO disabled), built with -trimpath
#   - distroless "static" base: no shell, no package manager
#   - runs as an unprivileged user (nonroot, uid 65532)
# Base images are pinned by digest; Dependabot updates them.

FROM golang:1.26-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/tenant-pass ./cmd/tenant-pass

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/tenant-pass /usr/local/bin/tenant-pass
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/tenant-pass"]
CMD ["serve", "-config", "/etc/tenant-pass/config.json"]
