//go:build e2e

package e2e

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/testprimary"
	"github.com/davidgroves/dnssec-auditor/internal/zonegen"
	"github.com/davidgroves/dnssec-auditor/tests/e2e/harness"
)

func TestLargeZone(t *testing.T) {
	raw := os.Getenv("E2E_LARGE_RECORDS")
	if raw == "" {
		t.Skip("set E2E_LARGE_RECORDS to run the large-zone suite")
	}
	n, _ := strconv.Atoi(raw)
	if n <= 0 {
		n = 1_000_000
	}
	start := time.Now()
	g, err := zonegen.Large(n, 1)
	if err != nil {
		t.Fatal(err)
	}
	primary := testprimary.New()
	if err := primary.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(primary.Close)
	primary.Load(g.Store)

	cfg := config.Defaults()
	cfg.API.Listen = harness.FreeListen()
	cfg.Notify.Enabled = false
	cfg.Refresh.MinInterval = config.Duration(time.Hour)
	cfg.Verification.Hygiene.Enabled = false
	cfg.Servers = []config.Server{{Name: "p1", Address: "127.0.0.1", Port: primary.Port}}
	cfg.Zones = []config.Zone{{Name: "large.test.", Servers: []string{"p1"}}}
	_, cli := harness.StartInProcess(t, cfg)
	z := harness.WaitState(t, cli, "large.test.", "valid", 10*time.Minute)
	recs, _ := z["records"].(float64)
	if int(recs) == 0 {
		t.Fatal("expected transferred records")
	}
	_ = harness.WriteResult("large-"+strconv.Itoa(n), harness.BudgetResult{
		Suite:    "large_zone",
		N:        n,
		Duration: time.Since(start),
		RSSBytes: harness.RSS(),
		OK:       true,
		Extra:    map[string]any{"records": recs, "rrsigs": z["rrsigs"], "nsec3": z["nsec3"]},
	})
}

func TestIncrementalPerf(t *testing.T) {
	if os.Getenv("E2E_LARGE_RECORDS") == "" {
		t.Skip("set E2E_LARGE_RECORDS to run incremental performance")
	}
	n, _ := strconv.Atoi(os.Getenv("E2E_LARGE_RECORDS"))
	if n <= 0 {
		n = 50_000
	}
	if n > 200_000 {
		n = 200_000 // keep the incremental suite bounded in this revision
	}
	g, err := zonegen.Large(n, 2)
	if err != nil {
		t.Fatal(err)
	}
	primary := testprimary.New()
	if err := primary.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(primary.Close)
	primary.Load(g.Store)
	cfg := config.Defaults()
	cfg.API.Listen = harness.FreeListen()
	cfg.Notify.Enabled = false
	cfg.Refresh.MinInterval = config.Duration(time.Hour)
	cfg.Refresh.PreferIXFR = true
	cfg.Verification.Hygiene.Enabled = false
	cfg.Verification.ClockSkew = 0
	cfg.Servers = []config.Server{{Name: "p1", Address: "127.0.0.1", Port: primary.Port}}
	cfg.Zones = []config.Zone{{Name: "large.test.", Servers: []string{"p1"}}}
	_, cli := harness.StartInProcess(t, cfg)
	harness.WaitState(t, cli, "large.test.", "valid", 10*time.Minute)

	oldSig, newSig, err := zonegen.FlipPair(g)
	if err != nil {
		t.Fatal(err)
	}
	adds, removes, err := zonegen.SignedSerialBump(g)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := primary.Apply("large.test.", append(adds, newSig), append(removes, oldSig)); err != nil {
		t.Fatal(err)
	}
	_ = cli.Refresh("large.test.", false)
	harness.WaitState(t, cli, "large.test.", "invalid", 2*time.Minute)
	_ = harness.WriteResult("incremental-"+strconv.Itoa(n), harness.BudgetResult{
		Suite:    "incremental_perf",
		N:        n,
		Duration: time.Since(start),
		RSSBytes: harness.RSS(),
		OK:       true,
	})
}
