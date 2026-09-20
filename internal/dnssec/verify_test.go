package dnssec_test

import (
	"testing"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/dnssec"
	"github.com/davidgroves/dnssec-auditor/internal/zonegen"
	"github.com/miekg/dns"
)

func newVerifier() *dnssec.Verifier {
	cfg := config.Defaults().Verification
	cfg.Hygiene.Enabled = false // generated zones may still trip unused-key etc.
	cfg.ClockSkew = 0
	v := dnssec.New(cfg)
	v.WithNow(func() time.Time { return time.Unix(1000, 0) })
	return v
}

func TestValidNSEC3OptOut(t *testing.T) {
	g, err := zonegen.Generate(zonegen.Options{
		Origin:      "ok.test.",
		Delegations: 6,
		SecurePct:   50,
		Denial:      zonegen.DenialNSEC3OptOut,
		Seed:        7,
	})
	if err != nil {
		t.Fatal(err)
	}
	res := newVerifier().Full(g.Store)
	if !res.Valid {
		t.Fatalf("expected valid, findings=%v", codes(res))
	}
	if res.Unsigned {
		t.Fatal("should be signed")
	}
}

func TestValidNSEC(t *testing.T) {
	g, err := zonegen.Generate(zonegen.Options{
		Origin:      "nsec.test.",
		Delegations: 4,
		SecurePct:   50,
		Denial:      zonegen.DenialNSEC,
		Seed:        3,
	})
	if err != nil {
		t.Fatal(err)
	}
	res := newVerifier().Full(g.Store)
	if !res.Valid {
		t.Fatalf("expected valid NSEC, findings=%v", codes(res))
	}
}

func TestMutations(t *testing.T) {
	cases := []struct {
		name   string
		denial zonegen.Denial
		mut    zonegen.Mutator
		want   string
		secPct int
	}{
		{"rrsig_invalid", zonegen.DenialNSEC3OptOut, zonegen.FlipRRSIG, dnssec.RRSIGInvalid, 100},
		{"rrsig_missing", zonegen.DenialNSEC3OptOut, zonegen.DropRRSIG, dnssec.RRSIGMissing, 100},
		{"rrsig_expired", zonegen.DenialNSEC3OptOut, zonegen.ExpireRRSIG, dnssec.RRSIGExpired, 50},
		{"rrsig_future", zonegen.DenialNSEC3OptOut, zonegen.FutureRRSIG, dnssec.RRSIGNotYetValid, 50},
		{"unknown_key", zonegen.DenialNSEC3OptOut, zonegen.UnknownKeyRRSIG, dnssec.RRSIGUnknownKey, 50},
		{"dnskey_zsk_only", zonegen.DenialNSEC3OptOut, zonegen.DNSKEYSignedByZSKOnly, dnssec.DNSKEYNotSignedByKSK, 50},
		{"nsec3_chain", zonegen.DenialNSEC3OptOut, zonegen.BreakNSEC3Chain, dnssec.NSEC3ChainBroken, 50},
		{"nsec3_missing", zonegen.DenialNSEC3OptOut, zonegen.DropNSEC3, dnssec.NSEC3ChainBroken, 100},
		{"nsec3_bitmap", zonegen.DenialNSEC3OptOut, zonegen.NSEC3BitmapDropDS, dnssec.NSEC3BitmapMismatch, 100},
		{"nsec3param", zonegen.DenialNSEC3OptOut, zonegen.NSEC3PARAMMismatch, dnssec.NSEC3PARAMMismatch, 50},
		{"nsec_missing", zonegen.DenialNSEC, zonegen.DropNSEC, dnssec.NSECChainBroken, 50},
		{"nsec_chain", zonegen.DenialNSEC, zonegen.BreakNSECChain, dnssec.NSECChainBroken, 50},
		{"labels", zonegen.DenialNSEC3OptOut, zonegen.LabelsMismatch, dnssec.RRSIGLabelsMismatch, 50},
		{"zonemd", zonegen.DenialNSEC3OptOut, zonegen.FakeZONEMD, dnssec.ZONEMDMismatch, 50},
		{"mixed_denial", zonegen.DenialNSEC, zonegen.MixDenial, dnssec.NSEC3Missing, 50},
		{"mixed_nsec", zonegen.DenialNSEC3OptOut, zonegen.MixNSEC, dnssec.RRSIGMissing, 50},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := zonegen.Generate(zonegen.Options{
				Origin:      tc.name + ".test.",
				Delegations: 6,
				SecurePct:   tc.secPct,
				Denial:      tc.denial,
				Seed:        11,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.mut(g); err != nil {
				t.Fatal(err)
			}
			res := newVerifier().Full(g.Store)
			if res.Valid {
				t.Fatalf("expected invalid, no findings")
			}
			found := false
			for _, c := range res.Findings.Codes(dnssec.Error) {
				if c == tc.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("want %s, got %v", tc.want, codes(res))
			}
		})
	}
}

func TestUnsignedIsNotInvalid(t *testing.T) {
	g, err := zonegen.Generate(zonegen.Options{
		Origin:      "unsigned.test.",
		Delegations: 2,
		Denial:      zonegen.DenialNone,
		Seed:        1,
	})
	if err != nil {
		t.Fatal(err)
	}
	res := newVerifier().Full(g.Store)
	if !res.Unsigned || !res.Valid {
		t.Fatalf("unsigned=%v valid=%v findings=%v", res.Unsigned, res.Valid, codes(res))
	}
}

func TestIncrementalMatchesFullAfterFlip(t *testing.T) {
	g, err := zonegen.Small("inc.test.")
	if err != nil {
		t.Fatal(err)
	}
	v := newVerifier()
	base := v.Full(g.Store)
	if !base.Valid {
		t.Fatalf("base invalid: %v", codes(base))
	}
	oldSig, newSig, err := zonegen.FlipPair(g)
	if err != nil {
		t.Fatal(err)
	}
	touched, err := g.Store.ApplyChanges([]dns.RR{newSig}, []dns.RR{oldSig})
	if err != nil {
		t.Fatal(err)
	}
	inc := v.Incremental(g.Store, base.Findings.Clone(), touched)
	full := v.Full(g.Store)
	if inc.Valid || full.Valid {
		t.Fatalf("expected invalid incremental=%v full=%v", inc.Valid, full.Valid)
	}
	if !hasCode(inc, dnssec.RRSIGInvalid) {
		t.Fatalf("incremental missing RRSIG_INVALID: %v", codes(inc))
	}
	if !hasCode(full, dnssec.RRSIGInvalid) {
		t.Fatalf("full missing RRSIG_INVALID: %v", codes(full))
	}
	if inc.Mode != "incremental" {
		t.Fatalf("mode %q", inc.Mode)
	}
}

func TestHygieneWarnings(t *testing.T) {
	g, err := zonegen.Generate(zonegen.Options{
		Origin:      "hygiene.test.",
		Delegations: 2,
		SecurePct:   50,
		Denial:      zonegen.DenialNSEC3OptOut,
		NSEC3Iters:  5,
		ExtraUnused: true,
		Seed:        4,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults().Verification
	cfg.ClockSkew = 0
	cfg.Hygiene.Enabled = true
	cfg.Hygiene.NSEC3MaxIterations = 0
	cfg.Hygiene.WarnNSEC3Salt = true
	v := dnssec.New(cfg)
	v.WithNow(func() time.Time { return time.Unix(1000, 0) })
	res := v.Full(g.Store)
	if !res.Valid {
		t.Fatalf("hygiene should not invalidate: %v", codes(res))
	}
	for _, want := range []string{dnssec.NSEC3IterationsNonzero, dnssec.DNSKEYUnused} {
		if !hasCode(res, want) {
			t.Errorf("missing %s in %v", want, codes(res))
		}
	}
}

func TestZONEMDRequired(t *testing.T) {
	g, err := zonegen.Small("needmd.test.")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults().Verification
	cfg.Hygiene.Enabled = false
	cfg.ClockSkew = 0
	cfg.ZONEMD = "on"
	v := dnssec.New(cfg)
	v.WithNow(func() time.Time { return time.Unix(1000, 0) })
	res := v.Full(g.Store)
	if res.Valid || !hasCode(res, dnssec.ZONEMDMissing) {
		t.Fatalf("want ZONEMD_MISSING, valid=%v findings=%v", res.Valid, codes(res))
	}
}

func TestZONEMDValidDigest(t *testing.T) {
	g, err := zonegen.Generate(zonegen.Options{
		Origin:      "zmdok.test.",
		Delegations: 4,
		SecurePct:   50,
		Denial:      zonegen.DenialNSEC3OptOut,
		Seed:        11,
		ZONEMD:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	res := newVerifier().Full(g.Store)
	if !res.Valid || !res.ZONEMDChecked || !res.ZONEMDOK {
		t.Fatalf("want valid ZONEMD, valid=%v checked=%v ok=%v findings=%v",
			res.Valid, res.ZONEMDChecked, res.ZONEMDOK, codes(res))
	}
}

func TestIncrementalSkipsZONEMD(t *testing.T) {
	g, err := zonegen.Generate(zonegen.Options{
		Origin:      "zmdinc.test.",
		Delegations: 4,
		SecurePct:   50,
		Denial:      zonegen.DenialNSEC3OptOut,
		Seed:        13,
		ZONEMD:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	v := newVerifier()
	full := v.Full(g.Store)
	if !full.ZONEMDChecked || !full.ZONEMDOK {
		t.Fatalf("full want ZONEMD ok, checked=%v ok=%v findings=%v", full.ZONEMDChecked, full.ZONEMDOK, codes(full))
	}
	// Touch a non-apex name so Incremental does not escalate.
	n := g.Store.Lookup("ns1." + g.Store.Origin())
	if n == nil {
		t.Fatal("missing ns1")
	}
	a, err := n.UnpackType(dns.TypeA)
	if err != nil || len(a) == 0 {
		t.Fatal(err)
	}
	old := a[0].(*dns.A)
	neu := dns.Copy(old).(*dns.A)
	neu.A = []byte{192, 0, 2, 200}
	touched, err := g.Store.ApplyChanges([]dns.RR{neu}, []dns.RR{old})
	if err != nil {
		t.Fatal(err)
	}
	inc := v.Incremental(g.Store, full.Findings, touched)
	if inc.Mode != "incremental" {
		t.Fatalf("mode %q", inc.Mode)
	}
	if inc.ZONEMDChecked {
		t.Fatal("incremental must not recompute ZONEMD")
	}
}

func hasCode(r *dnssec.Result, code string) bool {
	for _, c := range r.Findings.Codes("") {
		if c == code {
			return true
		}
	}
	return false
}

func codes(r *dnssec.Result) []string {
	return r.Findings.Codes("")
}

func TestExamplePack(t *testing.T) {
	cfg := config.Defaults().Verification
	cfg.Hygiene.Enabled = true
	v := dnssec.New(cfg)
	for _, spec := range zonegen.ExamplePack() {
		t.Run(spec.Origin, func(t *testing.T) {
			g, err := zonegen.GenerateExample(spec)
			if err != nil {
				t.Fatal(err)
			}
			res := v.Full(g.Store)
			switch spec.Expect {
			case zonegen.ExpectValid:
				if !res.Valid || res.Unsigned {
					t.Fatalf("want valid signed, valid=%v unsigned=%v findings=%v", res.Valid, res.Unsigned, codes(res))
				}
			case zonegen.ExpectWarning:
				if !res.Valid {
					t.Fatalf("want valid with warning %s, valid=false findings=%v", spec.Want, codes(res))
				}
				if spec.Want != "" && !hasCode(res, spec.Want) {
					t.Fatalf("want warning %s, findings=%v", spec.Want, codes(res))
				}
			case zonegen.ExpectInvalid:
				if res.Valid {
					t.Fatalf("want invalid %s, findings=%v", spec.Want, codes(res))
				}
				if spec.Want != "" && !hasCode(res, spec.Want) {
					t.Fatalf("want %s, findings=%v", spec.Want, codes(res))
				}
			case zonegen.ExpectUnsigned:
				if !res.Unsigned || !res.Valid {
					t.Fatalf("want unsigned, unsigned=%v valid=%v findings=%v", res.Unsigned, res.Valid, codes(res))
				}
			}
		})
	}
}

func TestRSASHA1Deprecated(t *testing.T) {
	g, err := zonegen.Generate(zonegen.Options{
		Origin:      "rsa1.test.",
		Delegations: 2,
		SecurePct:   50,
		Denial:      zonegen.DenialNSEC,
		Algorithm:   dns.RSASHA1,
		Seed:        4,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults().Verification
	cfg.Hygiene.Enabled = true
	res := dnssec.New(cfg).Full(g.Store)
	if !res.Valid {
		t.Fatalf("RSASHA1 should still verify, findings=%v", codes(res))
	}
	if !hasCode(res, dnssec.DeprecatedAlgorithm) {
		t.Fatalf("want DEPRECATED_ALGORITHM, findings=%v", codes(res))
	}
}

func TestEd25519Zone(t *testing.T) {
	g, err := zonegen.Generate(zonegen.Options{
		Origin:      "ed.test.",
		Delegations: 2,
		SecurePct:   50,
		Denial:      zonegen.DenialNSEC3OptOut,
		Algorithm:   dns.ED25519,
		Seed:        2,
	})
	if err != nil {
		t.Fatal(err)
	}
	res := newVerifier().Full(g.Store)
	if !res.Valid {
		t.Fatalf("ed25519 invalid: %v", codes(res))
	}
}
