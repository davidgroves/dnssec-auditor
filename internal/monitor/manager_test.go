package monitor

import (
	"context"
	"testing"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/event"
	"github.com/davidgroves/dnssec-auditor/internal/logging"
	"github.com/davidgroves/dnssec-auditor/internal/metrics"
	"github.com/davidgroves/dnssec-auditor/internal/testprimary"
	"github.com/davidgroves/dnssec-auditor/internal/zonegen"
)

func TestSOAUnchangedDoesNotLeaveTransferring(t *testing.T) {
	g, err := zonegen.Small("stuck.test.")
	if err != nil {
		t.Fatal(err)
	}
	primary := testprimary.New()
	primary.Load(g.Store)
	if err := primary.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(primary.Close)

	cfg := config.Defaults()
	cfg.Servers = []config.Server{{Name: "p", Address: "127.0.0.1", Port: primary.Port}}
	cfg.Zones = []config.Zone{{Name: "stuck.test.", Servers: []string{"p"}}}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	mgr := New(&cfg, event.New(8), metrics.New(), logging.Setup(cfg.Logging, nil))
	z := mgr.Get("stuck.test.")
	if z == nil {
		t.Fatal("missing zone")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mgr.Refresh(ctx, z, false)
	first := z.Snapshot()
	if first.State == string(StateTransferring) || first.State == string(StateVerifying) || first.State == string(StateUnknown) {
		t.Fatalf("after first refresh: %s", first.State)
	}

	z.mu.Lock()
	z.State = StateTransferring
	z.mu.Unlock()

	mgr.Refresh(ctx, z, false)
	got := z.Snapshot()
	if got.State == string(StateTransferring) || got.State == string(StateVerifying) {
		t.Fatalf("SOA unchanged left state %s", got.State)
	}
	if got.State != first.State {
		t.Fatalf("restored %s want %s", got.State, first.State)
	}
}
