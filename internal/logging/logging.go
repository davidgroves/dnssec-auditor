package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
)

type ctxKey struct{}

// Setup installs the process-wide slog default logger from config.
func Setup(cfg config.LoggingConfig, w io.Writer) *slog.Logger {
	if w == nil {
		w = os.Stdout
	}
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	var h slog.Handler
	opts := &slog.HandlerOptions{Level: level}
	if strings.EqualFold(cfg.Format, "text") {
		h = slog.NewTextHandler(w, opts)
	} else {
		h = slog.NewJSONHandler(w, opts)
	}
	logger := slog.New(h)
	slog.SetDefault(logger)
	return logger
}

// WideEvent is one structured event for a refresh cycle (or similar).
type WideEvent struct {
	Event          string         `json:"event"`
	Zone           string         `json:"zone,omitempty"`
	Source         string         `json:"source,omitempty"`
	Server         string         `json:"server,omitempty"`
	SerialFrom     uint32         `json:"serial_from,omitempty"`
	SerialTo       uint32         `json:"serial_to,omitempty"`
	Method         string         `json:"method,omitempty"`
	RecordsAdded   int            `json:"records_added,omitempty"`
	RecordsRemoved int            `json:"records_removed,omitempty"`
	VerifyMode     string         `json:"verify_mode,omitempty"`
	RRSIGsVerified int            `json:"rrsigs_verified,omitempty"`
	NSEC3Checked   int            `json:"nsec3_checked,omitempty"`
	ZONEMDChecked  bool           `json:"zonemd_checked,omitempty"`
	DurationMS     int64          `json:"duration_ms"`
	Result         string         `json:"result"`
	FindingsOpened int            `json:"findings_opened,omitempty"`
	FindingsClosed int            `json:"findings_closed,omitempty"`
	Warnings       int            `json:"warnings,omitempty"`
	Extra          map[string]any `json:"extra,omitempty"`
	started        time.Time
}

// StartWide begins a wide event timer.
func StartWide(event string) *WideEvent {
	return &WideEvent{Event: event, started: time.Now()}
}

// Emit logs the event with elapsed duration.
func (e *WideEvent) Emit(logger *slog.Logger) {
	if e.DurationMS == 0 && !e.started.IsZero() {
		e.DurationMS = time.Since(e.started).Milliseconds()
	}
	if logger == nil {
		logger = slog.Default()
	}
	attrs := []any{
		"event", e.Event,
		"duration_ms", e.DurationMS,
		"result", e.Result,
	}
	if e.Zone != "" {
		attrs = append(attrs, "zone", e.Zone)
	}
	if e.Source != "" {
		attrs = append(attrs, "source", e.Source)
	}
	if e.Server != "" {
		attrs = append(attrs, "server", e.Server)
	}
	if e.SerialFrom != 0 || e.SerialTo != 0 {
		attrs = append(attrs, "serial_from", e.SerialFrom, "serial_to", e.SerialTo)
	}
	if e.Method != "" {
		attrs = append(attrs, "method", e.Method)
	}
	if e.VerifyMode != "" {
		attrs = append(attrs, "verify_mode", e.VerifyMode)
	}
	if e.RRSIGsVerified != 0 {
		attrs = append(attrs, "rrsigs_verified", e.RRSIGsVerified)
	}
	if e.NSEC3Checked != 0 {
		attrs = append(attrs, "nsec3_checked", e.NSEC3Checked)
	}
	if e.ZONEMDChecked {
		attrs = append(attrs, "zonemd_checked", true)
	}
	if e.RecordsAdded != 0 {
		attrs = append(attrs, "records_added", e.RecordsAdded)
	}
	if e.RecordsRemoved != 0 {
		attrs = append(attrs, "records_removed", e.RecordsRemoved)
	}
	if e.FindingsOpened != 0 {
		attrs = append(attrs, "findings_opened", e.FindingsOpened)
	}
	if e.FindingsClosed != 0 {
		attrs = append(attrs, "findings_closed", e.FindingsClosed)
	}
	if e.Warnings != 0 {
		attrs = append(attrs, "warnings", e.Warnings)
	}
	for k, v := range e.Extra {
		attrs = append(attrs, k, v)
	}
	logger.Info("wide_event", attrs...)
}

// WithLogger stores a logger on the context.
func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, logger)
}

// FromContext returns the context logger or the default.
func FromContext(ctx context.Context) *slog.Logger {
	if ctx == nil {
		return slog.Default()
	}
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}
