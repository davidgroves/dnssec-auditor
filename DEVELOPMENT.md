# Development

## Prerequisites

- Go 1.25+
- Node 22+ (frontend)
- Docker (integration / interop e2e, optional)

## Backend

```bash
go test ./...
go run ./cmd/dnssec-auditor serve --config examples/config.example.yaml
# API: http://localhost:8080/v1/zones
# Docs: http://localhost:8080/docs
# Spec: http://localhost:8080/openapi.json
go run ./cmd/dnssec-auditor check --zone example.com. --file zone.db
go run ./cmd/zonegen --zone example.com. --delegations 8
go run ./cmd/zonegen -examples examples/bind/zones
go run ./cmd/testprimary --listen 127.0.0.1:5353 --zone example.com.
```

## Frontend

```bash
npm install
npm run dev          # Vite on :5173, proxies /v1 to :8080
npm test             # vitest
npm run typecheck
```

## Example compose stack

```bash
cd examples
docker compose up -d --build
```

See [examples/README.md](examples/README.md). Grafana (LGTM) is on http://localhost:3000.

## Tests

See [TESTING.md](TESTING.md) for layers, CI, and how `internal/testprimary` works (including wire UPDATE / DDNS).

```bash
./tests.sh                 # Go unit + frontend unit
./tests.sh --e2e           # in-process scenario suites (build tag e2e)
./tests.sh --e2e-large     # large-zone / incremental performance
```

## Layout

Backend source is `internal/` and `cmd/`. Frontend source is `frontend/` with Vite/Vitest/Playwright configs at the repo root.
