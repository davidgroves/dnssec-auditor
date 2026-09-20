//go:build e2e

package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/testprimary"
	"github.com/davidgroves/dnssec-auditor/internal/zonegen"
	"github.com/davidgroves/dnssec-auditor/tests/e2e/harness"
)

func TestDDNSBreakDetected(t *testing.T) {
	primary := testprimary.New()
	if err := primary.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(primary.Close)

	g, err := zonegen.Small("live.test.")
	if err != nil {
		t.Fatal(err)
	}
	primary.Load(g.Store)

	cfg := config.Defaults()
	cfg.API.Listen = harness.FreeListen()
	cfg.Notify.Enabled = true
	cfg.Notify.BindAddress = "127.0.0.1"
	cfg.Notify.UDPPort = 0
	cfg.Notify.TCPPort = 0
	cfg.Refresh.MinInterval = config.Duration(time.Hour)
	cfg.Refresh.PreferIXFR = true
	cfg.Verification.Hygiene.Enabled = false
	cfg.Verification.ClockSkew = 0
	cfg.Servers = []config.Server{{Name: "p1", Address: "127.0.0.1", Port: primary.Port}}
	cfg.Zones = []config.Zone{{Name: "live.test.", Servers: []string{"p1"}}}

	a, cli := harness.StartInProcess(t, cfg)
	port := harness.WaitNotifyPort(t, a)
	primary.SetNotify(fmt.Sprintf("127.0.0.1:%d", port))

	before := harness.WaitState(t, cli, "live.test.", "valid", 20*time.Second)
	t0, _ := before["last_valid_at"].(string)

	oldSig, newSig, err := zonegen.FlipPair(g)
	if err != nil {
		t.Fatal(err)
	}
	adds, removes, err := zonegen.SignedSerialBump(g)
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Apply("live.test.", append(adds, newSig), append(removes, oldSig)); err != nil {
		t.Fatal(err)
	}
	_ = cli.Refresh("live.test.", false)

	after := harness.WaitState(t, cli, "live.test.", "invalid", 20*time.Second)
	findings, err := cli.Findings("live.test.")
	if err != nil {
		t.Fatal(err)
	}
	if !harness.HasCode(findings, "RRSIG_INVALID") {
		t.Fatalf("expected RRSIG_INVALID, got %v", harness.FindingCodes(findings))
	}
	if t0 != "" {
		if got, _ := after["last_valid_at"].(string); got != "" && got != t0 {
			t.Fatalf("last_valid_at changed from %s to %s while invalid", t0, got)
		}
	}
}

func TestDDNSRecover(t *testing.T) {
	primary := testprimary.New()
	if err := primary.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(primary.Close)
	g, err := zonegen.Small("rec.test.")
	if err != nil {
		t.Fatal(err)
	}
	primary.Load(g.Store)
	cfg := config.Defaults()
	cfg.API.Listen = harness.FreeListen()
	cfg.Notify.Enabled = false
	cfg.Refresh.MinInterval = config.Duration(time.Hour)
	cfg.Verification.Hygiene.Enabled = false
	cfg.Verification.ClockSkew = 0
	cfg.Servers = []config.Server{{Name: "p1", Address: "127.0.0.1", Port: primary.Port}}
	cfg.Zones = []config.Zone{{Name: "rec.test.", Servers: []string{"p1"}}}
	_, cli := harness.StartInProcess(t, cfg)
	harness.WaitState(t, cli, "rec.test.", "valid", 20*time.Second)

	oldSig, newSig, err := zonegen.FlipPair(g)
	if err != nil {
		t.Fatal(err)
	}
	adds, removes, err := zonegen.SignedSerialBump(g)
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Apply("rec.test.", append(adds, newSig), append(removes, oldSig)); err != nil {
		t.Fatal(err)
	}
	_ = cli.Refresh("rec.test.", false)
	harness.WaitState(t, cli, "rec.test.", "invalid", 20*time.Second)

	adds2, removes2, err := zonegen.SignedSerialBump(g)
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Apply("rec.test.", append(adds2, oldSig), append(removes2, newSig)); err != nil {
		t.Fatal(err)
	}
	_ = cli.Refresh("rec.test.", false)
	harness.WaitState(t, cli, "rec.test.", "valid", 20*time.Second)
}
