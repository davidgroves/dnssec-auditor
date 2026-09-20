# DNSSEC Auditor example environment

Docker Compose stack with BIND 9.20, the auditor, and the Alpine UI.

```bash
cd examples
docker compose up -d --build
```

UI: http://localhost:8080
Grafana: http://localhost:3000 (anonymous; DNSSEC Auditor dashboard is home)

Regenerate the static defect pack (after changing mutators):

```bash
go run ./cmd/zonegen -examples examples/bind/zones
```

`rrsig-expiring.example.` is signed ~36 hours ahead of generation time. After that window it becomes `RRSIG_EXPIRED`; regenerate the pack to restore the warning.

## Services

| Service | Port | Role |
|---------|------|------|
| frontend | 8080 | nginx UI, proxies `/v1` `/health` `/metrics` `/docs` `/openapi*` |
| grafana | 3000 | Grafana LGTM all-in-one (Prometheus scrapes `/metrics`) |
| dnssec-auditor | 5354 | NOTIFY listener (UDP/TCP) |
| bind | 15353 | BIND 9.20 primary |

## Zones

BIND `dnssec-policy` zones are re-signed on startup. Static pack zones have **no** policy so the injected defects survive.

| Zone | Expected state | How it is produced |
|------|----------------|--------------------|
| `example.com.` | valid | BIND `dnssec-policy` NSEC3 opt-out |
| `nsec.example.` | valid | BIND `dnssec-policy` NSEC |
| `unsigned.example.` | unsigned | no DNSSEC |
| `broken.example.` | invalid `RRSIG_INVALID` | static flipped RRSIG |
| `member.example.` | valid | catalog-discovered, BIND-signed |
| `catalog.example.` | unsigned | RFC 9432 catalog |
| `rrsig-missing.example.` | invalid `RRSIG_MISSING` | drop one covering RRSIG |
| `rrsig-expired.example.` | invalid `RRSIG_EXPIRED` | SOA RRSIG expiration in the past |
| `rrsig-future.example.` | invalid `RRSIG_NOT_YET_VALID` | SOA RRSIG inception still in the future |
| `rrsig-unknown.example.` | invalid `RRSIG_UNKNOWN_KEY` | signed by a key not in DNSKEY |
| `rrsig-labels.example.` | invalid `RRSIG_LABELS_MISMATCH` | impossible RRSIG Labels |
| `rrsig-ttl.example.` | invalid `RRSIG_INVALID` | OrigTTL mutated (signature fails) |
| `rrsig-expiring.example.` | warning `RRSIG_EXPIRING_SOON` | SOA RRSIG expires in ~36h |
| `dnskey-zskonly.example.` | invalid `DNSKEY_NOT_SIGNED_BY_KSK` | DNSKEY signed only by ZSK |
| `dnskey-unused.example.` | warning `DNSKEY_UNUSED` | extra ZSK that signs nothing |
| `alg-rsasha1.example.` | warning `DEPRECATED_ALGORITHM` | RSASHA1 |
| `alg-rsasha1nsec3.example.` | warning `DEPRECATED_ALGORITHM` | RSASHA1-NSEC3-SHA1 |
| `alg-rsasha256.example.` | valid | RSASHA256 |
| `alg-ed25519.example.` | valid | ED25519 |
| `nsec3-missing.example.` | invalid `NSEC3_CHAIN_BROKEN` | one NSEC3 removed |
| `nsec3-chain.example.` | invalid `NSEC3_CHAIN_BROKEN` | next-hash does not match successor |
| `nsec3-bitmap.example.` | invalid `NSEC3_BITMAP_MISMATCH` | DS omitted from NSEC3 bitmap |
| `nsec3-param.example.` | invalid `NSEC3PARAM_MISMATCH` | NSEC3PARAM iterations ≠ chain |
| `nsec3-iters.example.` | warning `NSEC3_ITERATIONS_NONZERO` | iterations=5 (RFC 9276 wants 0) |
| `nsec3-salt.example.` | warning `NSEC3_SALT_PRESENT` | salt `aabb` (RFC 9276 wants empty) |
| `nsec3-strict.example.` | valid | NSEC3 without opt-out |
| `nsec-missing.example.` | invalid `NSEC_MISSING` | NSEC removed at a delegation |
| `nsec-chain.example.` | invalid `NSEC_CHAIN_BROKEN` | NSEC next-name is wrong |
| `mixed-nsec-nsec3.example.` | invalid `NSEC3_MISSING` | NSEC zone plus extra NSEC3PARAM |
| `mixed-nsec3-plus-nsec.example.` | invalid `RRSIG_MISSING` | NSEC3 zone plus extra unsigned NSEC |
| `zonemd-bad.example.` | invalid `ZONEMD_MISMATCH` | zeroed SIMPLE SHA-384 digest |
| `zonemd-good.example.` | valid | small NSEC zone with matching ZONEMD |
| `wildcard.example.` | valid | wildcard A + DNAME empty-nonterminal |

Config-declared zones win over catalog members of the same name. `member.example.` is learned only from the catalog.

BIND signs the policy-managed zones on first start. The first transfer can briefly show `unsigned` or `transfer_failed`; a refresh a few seconds later should settle.

## Useful URLs

- Auditor UI: http://localhost:8080
- OpenAPI docs: http://localhost:8080/docs
- OpenAPI JSON: http://localhost:8080/openapi.json
- Grafana: http://localhost:3000 (login disabled; admin/admin if you turn it back on)
- API: http://localhost:8080/v1/zones
- Memory: http://localhost:8080/v1/memory
- Health: http://localhost:8080/health
- Metrics: http://localhost:8080/metrics
- OTLP (optional): `localhost:4317` gRPC, `localhost:4318` HTTP

The Grafana service is [`grafana/otel-lgtm`](https://github.com/grafana/docker-otel-lgtm): Grafana, Prometheus, Loki, Tempo, and an OpenTelemetry Collector in one container. Prometheus scrapes `dnssec-auditor:8080/metrics` using `examples/grafana/prometheus.yaml` and loads `examples/grafana/dnssec-auditor.json` plus `examples/alerts.yaml`.

There is no API authentication. Error responses use `application/problem+json`. Do not expose this stack on a public network.

## Query BIND directly

```bash
dig @localhost -p 15353 example.com SOA
dig @localhost -p 15353 example.com DNSKEY +dnssec
dig @localhost -p 15353 rrsig-expired.example SOA +dnssec
dig @localhost -p 15353 example.com AXFR -y hmac-sha256:xfr-key:K8vC2mP9nQ4rT6wX1yB3fG5hJ7kL0mN2pR4sU6vW8xY=
```

## Logs and reset

```bash
docker compose logs -f
docker compose logs -f dnssec-auditor
docker compose down -v    # drop BIND journals/keys and start clean
```
