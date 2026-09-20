package webhooks

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/event"
	"github.com/davidgroves/dnssec-auditor/internal/logging"
	"github.com/davidgroves/dnssec-auditor/internal/metrics"
)

func TestDeliverFiltersAndRetries(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		n := hits.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	cfg := config.WebhookConfig{
		Enabled:      true,
		Timeout:      config.Duration(time.Second),
		MaxRetries:   2,
		RetryBackoff: config.Duration(time.Millisecond),
		QueueSize:    8,
		Targets: []config.WebhookTarget{
			{URL: srv.URL, Events: []string{string(event.ZoneInvalid)}, Zones: []string{"w.test."}},
		},
	}
	s := New(cfg, metrics.New(), logging.Setup(config.LoggingConfig{Level: "error"}, io.Discard))
	s.deliver(event.Event{Type: event.ZoneValid, Zone: "w.test."})
	if hits.Load() != 0 {
		t.Fatal("event filter failed")
	}
	s.deliver(event.Event{Type: event.ZoneInvalid, Zone: "other.test."})
	if hits.Load() != 0 {
		t.Fatal("zone filter failed")
	}
	s.deliver(event.Event{Type: event.ZoneInvalid, Zone: "w.test."})
	if hits.Load() < 2 {
		t.Fatalf("expected retry, hits=%d", hits.Load())
	}
}
