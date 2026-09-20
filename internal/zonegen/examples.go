package zonegen

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
)

// ExampleExpect is the expected auditor outcome for a compose demo zone.
type ExampleExpect string

const (
	ExpectValid    ExampleExpect = "valid"
	ExpectInvalid  ExampleExpect = "invalid"
	ExpectWarning  ExampleExpect = "warning"
	ExpectUnsigned ExampleExpect = "unsigned"
)

// ExampleSpec describes one static zone in the compose defect pack.
type ExampleSpec struct {
	Origin  string
	Summary string
	Expect  ExampleExpect
	Want    string
	Options Options
	Mutate  Mutator
}

// FileName is the BIND zone-file basename (db.<origin without trailing dot>).
func (s ExampleSpec) FileName() string {
	return "db." + strings.TrimSuffix(s.Origin, ".")
}

// BINDName is the zone name as BIND wants it (no trailing dot).
func (s ExampleSpec) BINDName() string {
	return strings.TrimSuffix(s.Origin, ".")
}

func baseOpts(origin string, denial Denial) Options {
	return Options{
		Origin:      origin,
		Delegations: 4,
		SecurePct:   50,
		Denial:      denial,
		Seed:        11,
	}
}

func secureOpts(origin string, denial Denial) Options {
	o := baseOpts(origin, denial)
	o.SecurePct = 100
	return o
}

// ExamplePack is the set of static pre-signed zones shipped under examples/bind/zones.
// BIND must not apply a dnssec-policy to these files or it will re-sign them.
func ExamplePack() []ExampleSpec {
	return []ExampleSpec{
		{
			Origin:  "rrsig-missing.example.",
			Summary: "one RRset has no covering RRSIG",
			Expect:  ExpectInvalid,
			Want:    "RRSIG_MISSING",
			Options: baseOpts("rrsig-missing.example.", DenialNSEC3OptOut),
			Mutate:  DropRRSIG,
		},
		{
			Origin:  "rrsig-expired.example.",
			Summary: "SOA RRSIG expiration is in the past",
			Expect:  ExpectInvalid,
			Want:    "RRSIG_EXPIRED",
			Options: baseOpts("rrsig-expired.example.", DenialNSEC3OptOut),
			Mutate:  ExpireRRSIG,
		},
		{
			Origin:  "rrsig-future.example.",
			Summary: "SOA RRSIG inception is still in the future",
			Expect:  ExpectInvalid,
			Want:    "RRSIG_NOT_YET_VALID",
			Options: baseOpts("rrsig-future.example.", DenialNSEC3OptOut),
			Mutate:  FutureRRSIG,
		},
		{
			Origin:  "rrsig-unknown.example.",
			Summary: "SOA is signed by a key not in the DNSKEY set",
			Expect:  ExpectInvalid,
			Want:    "RRSIG_UNKNOWN_KEY",
			Options: baseOpts("rrsig-unknown.example.", DenialNSEC3OptOut),
			Mutate:  UnknownKeyRRSIG,
		},
		{
			Origin:  "rrsig-labels.example.",
			Summary: "SOA RRSIG Labels field does not match the owner",
			Expect:  ExpectInvalid,
			Want:    "RRSIG_LABELS_MISMATCH",
			Options: baseOpts("rrsig-labels.example.", DenialNSEC3OptOut),
			Mutate:  LabelsMismatch,
		},
		{
			Origin:  "rrsig-ttl.example.",
			Summary: "SOA RRSIG OrigTTL does not match the RRset TTL (signature fails)",
			Expect:  ExpectInvalid,
			Want:    "RRSIG_INVALID",
			Options: baseOpts("rrsig-ttl.example.", DenialNSEC3OptOut),
			Mutate:  TTLMismatch,
		},
		{
			Origin:  "rrsig-expiring.example.",
			Summary: "SOA RRSIG expires within the 72h warning window",
			Expect:  ExpectWarning,
			Want:    "RRSIG_EXPIRING_SOON",
			Options: baseOpts("rrsig-expiring.example.", DenialNSEC3OptOut),
			Mutate:  ExpiringSoonLive,
		},
		{
			Origin:  "dnskey-zskonly.example.",
			Summary: "DNSKEY RRset is signed only by the ZSK",
			Expect:  ExpectInvalid,
			Want:    "DNSKEY_NOT_SIGNED_BY_KSK",
			Options: baseOpts("dnskey-zskonly.example.", DenialNSEC3OptOut),
			Mutate:  DNSKEYSignedByZSKOnly,
		},
		{
			Origin:  "dnskey-unused.example.",
			Summary: "extra ZSK in DNSKEY that signs nothing",
			Expect:  ExpectWarning,
			Want:    "DNSKEY_UNUSED",
			Options: func() Options {
				o := baseOpts("dnskey-unused.example.", DenialNSEC3OptOut)
				o.ExtraUnused = true
				return o
			}(),
		},
		{
			Origin:  "alg-rsasha1.example.",
			Summary: "signed with RSASHA1 (deprecated)",
			Expect:  ExpectWarning,
			Want:    "DEPRECATED_ALGORITHM",
			Options: func() Options {
				o := baseOpts("alg-rsasha1.example.", DenialNSEC)
				o.Algorithm = dns.RSASHA1
				return o
			}(),
		},
		{
			Origin:  "alg-rsasha1nsec3.example.",
			Summary: "signed with RSASHA1-NSEC3-SHA1 (deprecated)",
			Expect:  ExpectWarning,
			Want:    "DEPRECATED_ALGORITHM",
			Options: func() Options {
				o := baseOpts("alg-rsasha1nsec3.example.", DenialNSEC3)
				o.Algorithm = dns.RSASHA1NSEC3SHA1
				o.SecurePct = 100
				return o
			}(),
		},
		{
			Origin:  "alg-rsasha256.example.",
			Summary: "valid zone signed with RSASHA256",
			Expect:  ExpectValid,
			Options: func() Options {
				o := baseOpts("alg-rsasha256.example.", DenialNSEC)
				o.Algorithm = dns.RSASHA256
				return o
			}(),
		},
		{
			Origin:  "alg-ed25519.example.",
			Summary: "valid zone signed with ED25519",
			Expect:  ExpectValid,
			Options: func() Options {
				o := baseOpts("alg-ed25519.example.", DenialNSEC)
				o.Algorithm = dns.ED25519
				return o
			}(),
		},
		{
			Origin:  "nsec3-missing.example.",
			Summary: "one NSEC3 record removed (chain/coverage breaks)",
			Expect:  ExpectInvalid,
			Want:    "NSEC3_CHAIN_BROKEN",
			Options: secureOpts("nsec3-missing.example.", DenialNSEC3OptOut),
			Mutate:  DropNSEC3,
		},
		{
			Origin:  "nsec3-chain.example.",
			Summary: "NSEC3 next-hash does not point at the successor",
			Expect:  ExpectInvalid,
			Want:    "NSEC3_CHAIN_BROKEN",
			Options: baseOpts("nsec3-chain.example.", DenialNSEC3OptOut),
			Mutate:  BreakNSEC3Chain,
		},
		{
			Origin:  "nsec3-bitmap.example.",
			Summary: "NSEC3 type bitmap omits DS at a secure delegation",
			Expect:  ExpectInvalid,
			Want:    "NSEC3_BITMAP_MISMATCH",
			Options: secureOpts("nsec3-bitmap.example.", DenialNSEC3OptOut),
			Mutate:  NSEC3BitmapDropDS,
		},
		{
			Origin:  "nsec3-param.example.",
			Summary: "NSEC3PARAM iterations do not match the NSEC3 chain",
			Expect:  ExpectInvalid,
			Want:    "NSEC3PARAM_MISMATCH",
			Options: baseOpts("nsec3-param.example.", DenialNSEC3OptOut),
			Mutate:  NSEC3PARAMMismatch,
		},
		{
			Origin:  "nsec3-iters.example.",
			Summary: "valid signatures, NSEC3 iterations=5 (RFC 9276 wants 0)",
			Expect:  ExpectWarning,
			Want:    "NSEC3_ITERATIONS_NONZERO",
			Options: func() Options {
				o := secureOpts("nsec3-iters.example.", DenialNSEC3)
				o.NSEC3Iters = 5
				return o
			}(),
		},
		{
			Origin:  "nsec3-salt.example.",
			Summary: "valid signatures, NSEC3 salt present (RFC 9276 wants empty)",
			Expect:  ExpectWarning,
			Want:    "NSEC3_SALT_PRESENT",
			Options: func() Options {
				o := secureOpts("nsec3-salt.example.", DenialNSEC3)
				o.NSEC3Salt = "aabb"
				return o
			}(),
		},
		{
			Origin:  "nsec3-strict.example.",
			Summary: "valid NSEC3 zone without opt-out",
			Expect:  ExpectValid,
			Options: secureOpts("nsec3-strict.example.", DenialNSEC3),
		},
		{
			Origin:  "nsec-missing.example.",
			Summary: "one NSEC record removed",
			Expect:  ExpectInvalid,
			Want:    "NSEC_MISSING",
			Options: baseOpts("nsec-missing.example.", DenialNSEC),
			Mutate:  DropNSEC,
		},
		{
			Origin:  "nsec-chain.example.",
			Summary: "NSEC next-name does not point at the successor",
			Expect:  ExpectInvalid,
			Want:    "NSEC_CHAIN_BROKEN",
			Options: baseOpts("nsec-chain.example.", DenialNSEC),
			Mutate:  BreakNSECChain,
		},
		{
			Origin:  "mixed-nsec-nsec3.example.",
			Summary: "NSEC-signed zone with an extra NSEC3PARAM",
			Expect:  ExpectInvalid,
			Want:    "NSEC3_MISSING",
			Options: baseOpts("mixed-nsec-nsec3.example.", DenialNSEC),
			Mutate:  MixDenial,
		},
		{
			Origin:  "mixed-nsec3-plus-nsec.example.",
			Summary: "NSEC3-signed zone with an extra unsigned NSEC",
			Expect:  ExpectInvalid,
			Want:    "RRSIG_MISSING",
			Options: baseOpts("mixed-nsec3-plus-nsec.example.", DenialNSEC3OptOut),
			Mutate:  MixNSEC,
		},
		{
			Origin:  "zonemd-bad.example.",
			Summary: "ZONEMD digest does not match the zone",
			Expect:  ExpectInvalid,
			Want:    "ZONEMD_MISMATCH",
			Options: baseOpts("zonemd-bad.example.", DenialNSEC3OptOut),
			Mutate:  FakeZONEMD,
		},
		{
			Origin:  "zonemd-good.example.",
			Summary: "small signed zone with a matching SIMPLE SHA-384 ZONEMD",
			Expect:  ExpectValid,
			Options: Options{
				Origin:      "zonemd-good.example.",
				Delegations: 0,
				Denial:      DenialNSEC,
				Seed:        42,
				ZONEMD:      true,
			},
		},
		{
			Origin:  "wildcard.example.",
			Summary: "valid zone with a wildcard and a DNAME empty-nonterminal",
			Expect:  ExpectValid,
			Options: func() Options {
				o := baseOpts("wildcard.example.", DenialNSEC)
				o.AddWildcard = true
				o.AddDNAME = true
				return o
			}(),
		},
	}
}

// GenerateExample builds one pack zone (signed, then mutated).
func GenerateExample(spec ExampleSpec) (*Generated, error) {
	g, err := Generate(spec.Options)
	if err != nil {
		return nil, fmt.Errorf("%s: generate: %w", spec.Origin, err)
	}
	if spec.Mutate != nil {
		if err := spec.Mutate(g); err != nil {
			return nil, fmt.Errorf("%s: mutate: %w", spec.Origin, err)
		}
	}
	return g, nil
}

// WriteExamplePack writes db.* files and examples/bind/static-zones.conf.
// zonesDir should be examples/bind/zones.
func WriteExamplePack(zonesDir string) error {
	if err := os.MkdirAll(zonesDir, 0o755); err != nil {
		return err
	}
	var conf strings.Builder
	conf.WriteString("// Generated by go run ./cmd/zonegen -examples <dir>\n")
	conf.WriteString("// Static pre-signed zones. Do not attach a dnssec-policy.\n\n")
	for _, spec := range ExamplePack() {
		g, err := GenerateExample(spec)
		if err != nil {
			return err
		}
		path := filepath.Join(zonesDir, spec.FileName())
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		if err := g.Store.WriteZoneFile(f); err != nil {
			f.Close()
			return fmt.Errorf("write %s: %w", path, err)
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Fprintf(&conf, "zone %q {\n", spec.BINDName())
		conf.WriteString("    type primary;\n")
		fmt.Fprintf(&conf, "    file \"/var/lib/bind/%s\";\n", spec.FileName())
		conf.WriteString("    allow-transfer { key \"xfr-key\"; any; };\n")
		conf.WriteString("};\n\n")
	}
	confPath := filepath.Join(filepath.Dir(zonesDir), "static-zones.conf")
	return os.WriteFile(confPath, []byte(conf.String()), 0o644)
}
