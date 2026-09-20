package testprimary

import (
	"context"
	"testing"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/xfr"
	"github.com/davidgroves/dnssec-auditor/internal/zonegen"
)

func TestAXFRRoundTrip(t *testing.T) {
	g, err := zonegen.Small("axfr.test.")
	if err != nil {
		t.Fatal(err)
	}
	s := New()
	s.Load(g.Store)
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	cfg := config.Defaults()
	c := xfr.New(&cfg)
	srv := config.Server{Name: "p", Address: "127.0.0.1", Port: s.Port}
	res, err := c.AXFR(context.Background(), "axfr.test.", srv, "", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.Store == nil || res.Store.Serial() == 0 {
		t.Fatalf("empty store serial=%d records=%d", res.Serial, res.Records)
	}
	if res.Store.RecordCount() < 10 {
		t.Fatalf("too few records: %d", res.Store.RecordCount())
	}
}
