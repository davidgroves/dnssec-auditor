# Testing

When adding a feature, add tests in the matching class (Go unit, Go e2e, frontend unit, Playwright if the UI changes). After backend changes run `go test ./...`. After any change run `./tests.sh`.

## Commands

```bash
./tests.sh                 # Go unit + frontend unit (default)
./tests.sh --all           # unit + e2e scenario suites
./tests.sh --e2e           # e2e only (build tag e2e)
./tests.sh --e2e-large     # large-zone / incremental performance
./tests.sh --integration   # go test -tags integration ./...

go test ./...
go test -tags e2e ./tests/e2e -count=1
go test -tags e2e ./tests/e2e -run 'TestDefects|TestDDNS|TestCatalog|TestOracle' -count=1

npm test                   # vitest
npm run typecheck
npm run test:e2e           # Playwright (frontend/__tests__/e2e)
```

`go test ./...` does **not** compile `tests/e2e` (those files use `//go:build e2e`).

## Layers

| Layer | Where | What it covers |
|-------|--------|----------------|
| Go unit | `internal/*_test.go` | Store, XFR client, verifier + mutators, config, catalog parse, notify, webhooks, state, `check` CLI, testprimary AXFR |
| Go e2e | `tests/e2e` (`-tags e2e`) | In-process auditor + `testprimary`: defect catalogue, live break/recover over IXFR, catalog discovery, optional BIND/`kzonecheck` oracle |
| Go e2e large | same package, nightly / `--e2e-large` | Large generated zones and incremental verify cost (`E2E_LARGE_RECORDS`) |
| Frontend unit | `frontend/__tests__` | Vitest (API client, etc.) |
| Playwright | `frontend/__tests__/e2e` | UI; not in `./tests.sh` or default CI |
| Integration tag | `-tags integration` | Reserved; no suites wired yet |
| Interop | `TestInteropBIND` / `TestInteropKnot` | Skipped unless `E2E_INTEROP=bind,knot`; container path is not wired |

Helpers:

- `internal/zonegen` — synthetic signed zones and named mutators (`FlipRRSIG`, `ExpireRRSIG`, `MixDenial`, …). `ExamplePack()` is the compose defect set.
- `internal/testprimary` — test authoritative used by e2e (see below).
- `tests/e2e/harness` — start the app in-process, wait for zone state, call the API.

Verifier unit tests (`internal/dnssec/verify_test.go`) generate a zone, apply one mutator, and assert the finding code. They use a frozen clock (`unix 1000`) and usually disable hygiene so only the injected defect is in play.

## CI

`.github/workflows/ci.yml`:

- `go vet ./...` and `go test ./...` on every push/PR
- e2e: `TestDefects`, `TestDDNS`, `TestCatalog`, `TestOracle`
- frontend typecheck + vitest
- large/incremental suites on `workflow_dispatch` and the nightly cron (`E2E_LARGE_RECORDS=200000`)

`TestInterop*` is not in CI. `TestOracle` skips if neither `kzonecheck` nor `dnssec-verify` is on `PATH`.

## Compose stack

`examples/` is a manual demo (BIND 9.20 + auditor + UI), not an automated suite. Static `db.*` files come from `go run ./cmd/zonegen -examples examples/bind/zones`. See [examples/README.md](examples/README.md).

BIND and Knot re-sign or reject broken dynamic updates, so the compose defect zones are **static files with no `dnssec-policy`**. Live “then it broke” e2e uses `testprimary` instead.

---

## `internal/testprimary`

A test-only authoritative server so e2e can serve AXFR/IXFR and inject broken signed changes that BIND/Knot would not leave broken.

`cmd/testprimary` generates a zone (or a tiny defect pack) and serves it:

```bash
go run ./cmd/testprimary --listen 127.0.0.1:5353 --zone example.com.
```

### What it serves

In-memory `zone.Store`s on UDP and TCP:

| Query | Behavior |
|--------|----------|
| SOA | Current SOA |
| AXFR | Whole store (chunked) |
| IXFR | One journaled changeset if the client serial matches; otherwise AXFR |
| UPDATE | Applies the update section literally (see DDNS below) |
| anything else | REFUSED |

Typical setup: `New()`, `Load(store)`, optional `SetTSIG` / `SetNotify`, then `Listen`. After a change it can send NOTIFY to `notifyTo`.

### How changes are applied

E2E uses `Apply(name, adds, removes)`, not a wire UPDATE. That:

1. Calls `Store.ApplyChanges`
2. Bumps the SOA serial if the change did not already change it (so IXFR has a new serial)
3. Appends a journal entry `{From, To, Adds, Removes}`
4. Sends NOTIFY if configured

IXFR only works for a **single** journaled hop that matches `from → to`. There is no multi-step journal merge. `PurgeJournal` drops the journal for a zone.

`TestDDNSBreakDetected` / `TestDDNSRecover` call `Apply` with `FlipPair` + `SignedSerialBump` so the auditor sees a broken RRSIG over IXFR, then a repair.

### Can you send DDNS updates?

**Yes, on the wire**, but only as a stub.

`handleUpdate` accepts RFC 2136 UPDATE (`OpcodeUpdate`): Authority/NS records with `CLASS ANY` or `CLASS NONE` become removes; everything else becomes adds. Then it calls `Apply` and always replies `NOERROR`.

It does **not**:

- Honor prerequisites (the Answer section is ignored)
- Implement real RFC 2136 matching (NXRRSET / YXRRSET, etc.)
- Re-sign or rewrite NSEC/NSEC3
- Fail the DNS response when `Apply` errors (the error is ignored)
- Require TSIG on UPDATE unless you `SetTSIG` **before** `Listen` (`TsigSecret` is copied at listen time)

You can point `nsupdate` or a miekg `dns.Client` at it to add/remove RRs and drive the auditor. It is not a BIND/Knot update server: broken signatures stay broken (that is the point), and a normal “add an A record” update leaves RRSIGs stale unless you also send the matching signature and serial changes.

For injecting defects, `Apply` in-process is the supported API. Wire UPDATE is the same literal apply path over the network.
