//go:build e2e

package e2e

import (
	"testing"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/testprimary"
	"github.com/davidgroves/dnssec-auditor/internal/zonegen"
	"github.com/davidgroves/dnssec-auditor/tests/e2e/harness"
)

func TestDefectsInProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	primary := testprimary.New()
	if err := primary.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(primary.Close)

	g, err := zonegen.Small("good.test.")
	if err != nil {
		t.Fatal(err)
	}
	primary.Load(g.Store)

	bad, err := zonegen.Small("bad.test.")
	if err != nil {
		t.Fatal(err)
	}
	if err := zonegen.FlipRRSIG(bad); err != nil {
		t.Fatal(err)
	}
	primary.Load(bad.Store)

	cfg := config.Defaults()
	cfg.API.Listen = harness.FreeListen()
	cfg.Notify.Enabled = false
	cfg.Refresh.MinInterval = config.Duration(time.Hour)
	cfg.Refresh.MaxInterval = config.Duration(time.Hour)
	cfg.Verification.Hygiene.Enabled = false
	cfg.Servers = []config.Server{{Name: "p1", Address: "127.0.0.1", Port: primary.Port}}
	cfg.Zones = []config.Zone{
		{Name: "good.test.", Servers: []string{"p1"}},
		{Name: "bad.test.", Servers: []string{"p1"}},
	}
	_, cli := harness.StartInProcess(t, cfg)
	harness.WaitState(t, cli, "good.test.", "valid", 30*time.Second)
	harness.WaitState(t, cli, "bad.test.", "invalid", 30*time.Second)
	findings, err := cli.Findings("bad.test.")
	if err != nil {
		t.Fatal(err)
	}
	if !harness.HasCode(findings, "RRSIG_INVALID") {
		t.Fatalf("expected RRSIG_INVALID, got %#v", findings)
	}
}

func TestDefectsCatalogue(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	type tc struct {
		name   string
		origin string
		opt    zonegen.Options
		mut    zonegen.Mutator
		want   string
		state  string
	}
	cases := []tc{
		{name: "valid_nsec3", origin: "ok3.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC3OptOut, Seed: 1}, state: "valid"},
		{name: "valid_nsec", origin: "okn.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC, Seed: 2}, state: "valid"},
		{name: "unsigned", origin: "u.test.", opt: zonegen.Options{Delegations: 2, Denial: zonegen.DenialNone, Seed: 3}, state: "unsigned"},
		{name: "rrsig_invalid", origin: "fi.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 100, Denial: zonegen.DenialNSEC3OptOut, Seed: 4}, mut: zonegen.FlipRRSIG, want: "RRSIG_INVALID", state: "invalid"},
		{name: "rrsig_missing", origin: "miss.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 100, Denial: zonegen.DenialNSEC3OptOut, Seed: 5}, mut: zonegen.DropRRSIG, want: "RRSIG_MISSING", state: "invalid"},
		{name: "rrsig_expired", origin: "exp.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC3OptOut, Seed: 6}, mut: zonegen.ExpireRRSIG, want: "RRSIG_EXPIRED", state: "invalid"},
		{name: "rrsig_future", origin: "fut.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC3OptOut, Seed: 7}, mut: zonegen.FutureRRSIG, want: "RRSIG_NOT_YET_VALID", state: "invalid"},
		{name: "unknown_key", origin: "unk.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC3OptOut, Seed: 8}, mut: zonegen.UnknownKeyRRSIG, want: "RRSIG_UNKNOWN_KEY", state: "invalid"},
		{name: "labels", origin: "lab.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC3OptOut, Seed: 9}, mut: zonegen.LabelsMismatch, want: "RRSIG_LABELS_MISMATCH", state: "invalid"},
		{name: "dnskey_zsk", origin: "zsk.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC3OptOut, Seed: 10}, mut: zonegen.DNSKEYSignedByZSKOnly, want: "DNSKEY_NOT_SIGNED_BY_KSK", state: "invalid"},
		{name: "nsec3_chain", origin: "n3c.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC3OptOut, Seed: 11}, mut: zonegen.BreakNSEC3Chain, want: "NSEC3_CHAIN_BROKEN", state: "invalid"},
		{name: "nsec3_missing", origin: "n3m.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 100, Denial: zonegen.DenialNSEC3OptOut, Seed: 12}, mut: zonegen.DropNSEC3, want: "NSEC3_CHAIN_BROKEN", state: "invalid"},
		{name: "nsec3_bitmap", origin: "n3b.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 100, Denial: zonegen.DenialNSEC3OptOut, Seed: 13}, mut: zonegen.NSEC3BitmapDropDS, want: "NSEC3_BITMAP_MISMATCH", state: "invalid"},
		{name: "nsec3param", origin: "n3p.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC3OptOut, Seed: 14}, mut: zonegen.NSEC3PARAMMismatch, want: "NSEC3PARAM_MISMATCH", state: "invalid"},
		{name: "nsec_missing", origin: "nm.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC, Seed: 15}, mut: zonegen.DropNSEC, want: "NSEC_CHAIN_BROKEN", state: "invalid"},
		{name: "nsec_chain", origin: "nc.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC, Seed: 16}, mut: zonegen.BreakNSECChain, want: "NSEC_CHAIN_BROKEN", state: "invalid"},
		{name: "zonemd", origin: "zmd.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC3OptOut, Seed: 17}, mut: zonegen.FakeZONEMD, want: "ZONEMD_MISMATCH", state: "invalid"},
		{name: "zonemd_ok", origin: "zmdok.test.", opt: zonegen.Options{Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC3OptOut, Seed: 18, ZONEMD: true}, want: "", state: "valid"},
	}

	primary := testprimary.New()
	if err := primary.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(primary.Close)

	cfg := config.Defaults()
	cfg.API.Listen = harness.FreeListen()
	cfg.Notify.Enabled = false
	cfg.Refresh.MinInterval = config.Duration(time.Hour)
	cfg.Refresh.MaxInterval = config.Duration(time.Hour)
	cfg.Verification.Hygiene.Enabled = false
	cfg.Verification.ClockSkew = 0
	cfg.Servers = []config.Server{{Name: "p1", Address: "127.0.0.1", Port: primary.Port}}

	for i := range cases {
		c := cases[i]
		opt := c.opt
		opt.Origin = c.origin
		g, err := zonegen.Generate(opt)
		if err != nil {
			t.Fatalf("%s generate: %v", c.name, err)
		}
		if c.mut != nil {
			if err := c.mut(g); err != nil {
				t.Fatalf("%s mutate: %v", c.name, err)
			}
		}
		primary.Load(g.Store)
		cfg.Zones = append(cfg.Zones, config.Zone{Name: c.origin, Servers: []string{"p1"}})
	}

	_, cli := harness.StartInProcess(t, cfg)
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			z := harness.WaitState(t, cli, c.origin, c.state, 45*time.Second)
			if c.name == "zonemd_ok" {
				ok, _ := z["zonemd_ok"].(bool)
				if !ok {
					t.Fatalf("want zonemd_ok=true got %#v", z["zonemd_ok"])
				}
				if z["zonemd_checked_at"] == nil || z["zonemd_checked_at"] == "" {
					t.Fatalf("want zonemd_checked_at, got %#v", z["zonemd_checked_at"])
				}
				if stale, _ := z["zonemd_stale"].(bool); stale {
					t.Fatal("want zonemd_stale=false after full verify")
				}
			}
			if c.want == "" {
				return
			}
			findings, err := cli.Findings(c.origin)
			if err != nil {
				t.Fatal(err)
			}
			if !harness.HasCode(findings, c.want) {
				t.Fatalf("state=%v want %s got %v", z["state"], c.want, harness.FindingCodes(findings))
			}
		})
	}
}

func TestDefectsHygieneWarnings(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	primary := testprimary.New()
	if err := primary.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(primary.Close)
	g, err := zonegen.Generate(zonegen.Options{
		Origin:      "hyg.test.",
		Delegations: 2,
		SecurePct:   50,
		Denial:      zonegen.DenialNSEC3OptOut,
		NSEC3Iters:  5,
		ExtraUnused: true,
		Seed:        21,
	})
	if err != nil {
		t.Fatal(err)
	}
	primary.Load(g.Store)
	cfg := config.Defaults()
	cfg.API.Listen = harness.FreeListen()
	cfg.Notify.Enabled = false
	cfg.Refresh.MinInterval = config.Duration(time.Hour)
	cfg.Verification.Hygiene.Enabled = true
	cfg.Verification.ClockSkew = 0
	cfg.Servers = []config.Server{{Name: "p1", Address: "127.0.0.1", Port: primary.Port}}
	cfg.Zones = []config.Zone{{Name: "hyg.test.", Servers: []string{"p1"}}}
	_, cli := harness.StartInProcess(t, cfg)
	harness.WaitState(t, cli, "hyg.test.", "valid", 30*time.Second)
	findings, err := cli.Findings("hyg.test.")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"NSEC3_ITERATIONS_NONZERO", "DNSKEY_UNUSED"} {
		if !harness.HasCode(findings, want) {
			t.Errorf("missing %s in %v", want, harness.FindingCodes(findings))
		}
	}
}
