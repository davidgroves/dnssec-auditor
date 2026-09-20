# DNSSEC Auditor

A Go service that transfers DNS zones (AXFR/IXFR, TSIG, NOTIFY, catalog zones), verifies DNSSEC fully and incrementally in the style of Knot's `dnssec-validation`, and exposes zone state through a JSON API, Prometheus metrics, optional webhooks, and a TypeScript/Alpine.js UI.

## Features

- Config-declared zones and RFC 9432 catalog zones
- Named TSIG keys and named transfer servers
- NOTIFY listener (UDP/TCP) plus SOA-driven refresh with min/max clamp and jitter
- Full and incremental DNSSEC verification (NSEC / NSEC3 / opt-out, ZONEMD, hygiene)
- Parent DS chain-of-trust check (optional)
- Multi-primary serial-skew detection
- JSON API with OpenAPI 3.1 (`/openapi.json`, `/docs`), SSE events, Prometheus metrics
- `dnssec-auditor check` one-shot CLI for signer pipelines
- Single static backend binary; frontend served by nginx

## Quick start

```bash
go run ./cmd/dnssec-auditor serve --config examples/config.example.yaml
```

API listens on `:8080` (`/health`, `/ready`, `/metrics`, `/v1/zones`, `/v1/memory`, `/ui/config`).
OpenAPI 3.1 is at `/openapi.json`; interactive docs at `/docs`. Errors use `application/problem+json`.

Validate a zone file without running the daemon:

```bash
go run ./cmd/dnssec-auditor check --zone example.com. --file zone.db
```

## Configuration

See [examples/config.example.yaml](examples/config.example.yaml). Named `tsig_keys` and `servers` are referenced from `zones` and `catalogs`. Refresh intervals clamp the SOA REFRESH value between `refresh.min_interval` and `refresh.max_interval`.

## Example stack

A BIND 9.20 primary plus the auditor and UI (valid signed zones, unsigned, catalog, and a static pack of RRSIG / NSEC / NSEC3 / algorithm defects):

```bash
cd examples
docker compose up -d --build
```

Open http://localhost:8080 for the auditor UI and http://localhost:3000 for Grafana (LGTM all-in-one, dashboard preloaded). Details are in [examples/README.md](examples/README.md).

## Containers

Tagged releases (`v1.0`, `v1.2.3`, …) publish images to GHCR and create a GitHub Release:

```bash
docker pull ghcr.io/davidgroves/dnssec-auditor/backend:latest
docker pull ghcr.io/davidgroves/dnssec-auditor/frontend:latest
```

Build locally:

```bash
docker build -t dnssec-auditor .
docker build -f Dockerfile.frontend -t dnssec-auditor-frontend .
```

The backend image is a static binary (`gcr.io/distroless/static`). The frontend image is nginx proxying `/v1`, `/health`, `/metrics`, `/ui/config`, `/docs`, and `/openapi*` to `dnssec-auditor:8080`.

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md), [TESTING.md](TESTING.md), and [CLAUDE.md](CLAUDE.md). Architecture notes are in [ARCHITECTURE.md](ARCHITECTURE.md).
