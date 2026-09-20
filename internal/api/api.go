package api

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/event"
	"github.com/davidgroves/dnssec-auditor/internal/metrics"
	"github.com/davidgroves/dnssec-auditor/internal/monitor"
	"github.com/davidgroves/dnssec-auditor/internal/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	cfg     *config.Config
	mgr     *monitor.Manager
	metrics *metrics.Metrics
	bus     *event.Bus
	started time.Time

	sseMu sync.Mutex
	sse   map[chan event.Event]struct{}
}

func New(cfg *config.Config, mgr *monitor.Manager, m *metrics.Metrics, bus *event.Bus) *Server {
	s := &Server{
		cfg:     cfg,
		mgr:     mgr,
		metrics: m,
		bus:     bus,
		started: time.Now(),
		sse:     map[chan event.Event]struct{}{},
	}
	bus.Subscribe(func(e event.Event) {
		s.sseMu.Lock()
		defer s.sseMu.Unlock()
		for ch := range s.sse {
			select {
			case ch <- e:
			default:
			}
		}
	})
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	cfg := huma.DefaultConfig("DNSSEC Auditor", version.Version)
	cfg.Info.Description = "JSON API for DNSSEC Auditor zone state, findings, catalogs, and events. " +
		"There is no API authentication; put the listener behind a reverse proxy if needed. " +
		"Error responses use application/problem+json (RFC 7807)."
	// Keep success JSON identical to the pre-Huma API (no $schema field / Link header).
	cfg.CreateHooks = nil

	api := humago.New(mux, cfg)
	s.registerRoutes(api)

	// Prometheus text exposition stays outside OpenAPI.
	mux.Handle("/metrics", promhttp.HandlerFor(s.metrics.Registry, promhttp.HandlerOpts{}))

	return withLogging(s.cfg.Logging, mux)
}

func withLogging(cfg config.LoggingConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusWriter{ResponseWriter: w, code: 200}
		next.ServeHTTP(rw, r)
		d := time.Since(start)
		always := rw.code >= 400 || r.Method != http.MethodGet || d > time.Duration(cfg.SlowThresholdMS)*time.Millisecond
		if always || sample(cfg.SampleRate) {
			_ = strconv.Itoa(rw.code)
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) {
	w.code = c
	w.ResponseWriter.WriteHeader(c)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func sample(rate float64) bool {
	if rate >= 1 {
		return true
	}
	if rate <= 0 {
		return false
	}
	return time.Now().UnixNano()%1000 < int64(rate*1000)
}
