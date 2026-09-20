package state

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/dnssec"
	"github.com/davidgroves/dnssec-auditor/internal/event"
	"github.com/davidgroves/dnssec-auditor/internal/logging"
	"github.com/davidgroves/dnssec-auditor/internal/metrics"
	"github.com/davidgroves/dnssec-auditor/internal/monitor"
	"github.com/davidgroves/dnssec-auditor/internal/zonegen"
)

func TestStateFileRoundTrip(t *testing.T) {
	cfg := config.Defaults()
	cfg.Servers = []config.Server{{Name: "p1", Address: "127.0.0.1", Port: 53}}
	cfg.Zones = []config.Zone{{Name: "rt.test.", Servers: []string{"p1"}}}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	mgr := monitor.New(&cfg, event.New(8), metrics.New(), logging.Setup(cfg.Logging, nil))
	z := mgr.Get("rt.test.")
	if z == nil {
		t.Fatal("missing zone")
	}
	when := time.Unix(1_700_000_000, 0)
	z.Restore(when, []dnssec.Finding{dnssec.NewFinding(dnssec.RRSIGInvalid, dnssec.Error, "rt.test.", 6, "x")})

	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, mgr, metrics.New()); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	snap, ok := loaded.Zones["rt.test."]
	if !ok {
		t.Fatalf("zones=%v", loaded.Zones)
	}
	if snap.LastValidAt.Unix() != when.Unix() {
		t.Fatalf("last_valid_at %v", snap.LastValidAt)
	}
	if len(snap.Findings) != 1 || snap.Findings[0].Code != dnssec.RRSIGInvalid {
		t.Fatalf("findings %+v", snap.Findings)
	}
}

func TestZoneSnapshotRoundTrip(t *testing.T) {
	g, err := zonegen.Small("snap.test.")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Servers = []config.Server{{Name: "p1", Address: "127.0.0.1", Port: 53}}
	cfg.Zones = []config.Zone{{Name: "snap.test.", Servers: []string{"p1"}}}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	mgr := monitor.New(&cfg, event.New(8), metrics.New(), logging.Setup(cfg.Logging, nil))
	z := mgr.Get("snap.test.")
	z.AttachStore(g.Store)

	sc := config.SnapshotConfig{Enabled: true, Dir: t.TempDir()}
	if err := WriteSnapshot(sc, z); err != nil {
		t.Fatal(err)
	}
	st, saved, err := ReadSnapshot(sc, "snap.test.")
	if err != nil {
		t.Fatal(err)
	}
	if st.Origin() != "snap.test." || st.Serial() != g.Store.Serial() {
		t.Fatalf("origin=%s serial=%d", st.Origin(), st.Serial())
	}
	if saved.IsZero() {
		t.Fatal("saved_at zero")
	}
	if st.RecordCount() != g.Store.RecordCount() {
		t.Fatalf("records %d != %d", st.RecordCount(), g.Store.RecordCount())
	}
}
