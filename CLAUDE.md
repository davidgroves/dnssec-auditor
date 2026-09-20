# LLM Context: DNSSEC Auditor

## Critical: Things to do when making changes

- Run `go test ./...` after backend changes.
- Run `./tests.sh` after any changes.
- When adding a feature, add tests (Go unit, Go e2e/integration, frontend unit, Playwright where UI changes).
- Prefer structured `logging.WideEvent` logs and Prometheus metrics in `internal/metrics`.

## Critical: File paths

```
cmd/dnssec-auditor/     # serve, check, version
internal/
  config/               # YAML schema
  zone/                 # compact store
  xfr/                  # AXFR/IXFR + SOA
  dnssec/               # verifier
  monitor/              # refresh state machine
  notify/ catalog/ chain/ webhooks/ state/ api/ app/
  zonegen/ testprimary/ # test helpers
frontend/               # TypeScript + Alpine
tests/e2e/              # build tag e2e
```

## Commands

```bash
go test ./...
go test -tags e2e ./tests/e2e -count=1
go run ./cmd/dnssec-auditor serve --config examples/config.example.yaml
npx tsc --noEmit
npm test
```

## Patterns

- Zone names always end with `.` — use `dnsname.Canonical`.
- DNS is the source of truth; the store is a cache of transferred contents.
- Findings have `severity` error|warning; only errors flip validity.
- `unsigned` is a distinct state, never `invalid`.
- Isolate miekg/dns behind `internal/zone` and `internal/xfr`.

## Gotchas

- Constructing `dns.NSEC3` in memory requires `HashLength` (20 for SHA-1) and `SaltLength`.
- Do not walk parents past the zone origin when generating empty non-terminals.
- BIND/Knot re-sign or reject broken dynamic updates; e2e defect injection uses `internal/testprimary`.
- miekg `RRSIG.Signature` is base64 text; mutating i
t must keep valid base64.
