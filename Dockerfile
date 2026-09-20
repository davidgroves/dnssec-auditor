# Build a static dnssec-auditor binary.
FROM golang:1.25-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/davidgroves/dnssec-auditor/internal/version.Version=${VERSION} -X github.com/davidgroves/dnssec-auditor/internal/version.Commit=${COMMIT}" -o /out/dnssec-auditor ./cmd/dnssec-auditor

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /out/dnssec-auditor /dnssec-auditor
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/dnssec-auditor"]
CMD ["serve", "--config", "/etc/dnssec-auditor/config.yaml"]
