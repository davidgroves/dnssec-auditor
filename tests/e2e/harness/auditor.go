package harness

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/app"
	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/logging"
	"gopkg.in/yaml.v3"
)

// StartInProcess writes cfg to a temp file, starts the auditor, and waits until /ready.
func StartInProcess(t *testing.T, cfg config.Config) (*app.App, *Client) {
	t.Helper()
	if cfg.API.Listen == "" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		cfg.API.Listen = ln.Addr().String()
		ln.Close()
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	b, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a := app.New(loaded, logging.Setup(loaded.Logging, os.Stdout))
	go func() { _ = a.Run(ctx) }()
	cli := NewClient("http://" + loaded.API.Listen)
	Eventually(t, 10*time.Second, func() bool { return cli.Ready() == nil })
	return a, cli
}

func FreeListen() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func WaitNotifyPort(t *testing.T, a *app.App) int {
	t.Helper()
	var port int
	Eventually(t, 5*time.Second, func() bool {
		if a.Notify == nil {
			return false
		}
		port = a.Notify.UDPPort()
		return port > 0
	})
	return port
}

func Must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func FindingCodes(findings []map[string]any) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, f := range findings {
		c, _ := f["code"].(string)
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

func HasCode(findings []map[string]any, code string) bool {
	for _, f := range findings {
		if f["code"] == code {
			return true
		}
	}
	return false
}

func WaitState(t *testing.T, cli *Client, zone, state string, timeout time.Duration) map[string]any {
	t.Helper()
	var z map[string]any
	Eventually(t, timeout, func() bool {
		var err error
		z, err = cli.Zone(zone)
		return err == nil && z["state"] == state
	})
	return z
}

func MetricLine(t *testing.T, cli *Client, substr string) string {
	t.Helper()
	body, err := cli.Metrics()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range splitLines(body) {
		if contains(line, substr) && len(line) > 0 && line[0] != '#' {
			return line
		}
	}
	return ""
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func FormatAddr(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}
