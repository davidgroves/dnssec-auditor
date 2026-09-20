package webhooks

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/event"
	"github.com/davidgroves/dnssec-auditor/internal/metrics"
)

type Sender struct {
	cfg     config.WebhookConfig
	metrics *metrics.Metrics
	log     *slog.Logger
	client  *http.Client
	ch      chan event.Event
}

func New(cfg config.WebhookConfig, m *metrics.Metrics, log *slog.Logger) *Sender {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1000
	}
	timeout := cfg.Timeout.Duration()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Sender{
		cfg:     cfg,
		metrics: m,
		log:     log,
		client:  &http.Client{Timeout: timeout},
		ch:      make(chan event.Event, cfg.QueueSize),
	}
}

func (s *Sender) Subscribe(bus *event.Bus) {
	if !s.cfg.Enabled {
		return
	}
	bus.Subscribe(func(e event.Event) {
		select {
		case s.ch <- e:
		default:
			s.log.Warn("webhook queue full, dropping", "type", e.Type, "zone", e.Zone)
		}
	})
}

func (s *Sender) Run(ctx context.Context) {
	if !s.cfg.Enabled {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-s.ch:
			s.deliver(e)
		}
	}
}

func (s *Sender) deliver(e event.Event) {
	body, err := json.Marshal(e)
	if err != nil {
		return
	}
	for _, t := range s.cfg.Targets {
		if !matchEvent(t, e) {
			continue
		}
		ok := false
		for i := 0; i <= s.cfg.MaxRetries; i++ {
			req, err := http.NewRequest(http.MethodPost, t.URL, bytes.NewReader(body))
			if err != nil {
				break
			}
			req.Header.Set("Content-Type", "application/json")
			for k, v := range t.Headers {
				req.Header.Set(k, v)
			}
			resp, err := s.client.Do(req)
			if err == nil && resp.StatusCode < 300 {
				resp.Body.Close()
				ok = true
				break
			}
			if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(s.cfg.RetryBackoff.Duration())
		}
		result := "ok"
		if !ok {
			result = "error"
		}
		s.metrics.WebhookDeliveries.WithLabelValues(t.URL, result).Inc()
	}
}

func matchEvent(t config.WebhookTarget, e event.Event) bool {
	if len(t.Events) > 0 {
		ok := false
		for _, ev := range t.Events {
			if ev == string(e.Type) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(t.Zones) > 0 {
		ok := false
		for _, z := range t.Zones {
			if z == e.Zone {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
