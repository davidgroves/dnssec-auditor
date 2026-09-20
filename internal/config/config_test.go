package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaultsAndValidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	yaml := `
tsig_keys:
  - name: xfr-key
    secret: dGVzdA==
    algorithm: hmac-sha256
servers:
  - name: primary1
    address: 127.0.0.1
    port: 53
    tsig_key: xfr-key
zones:
  - name: example.com
    servers: [primary1]
refresh:
  min_interval: 30s
  max_interval: 1h
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Zones[0].Name != "example.com." {
		t.Fatalf("origin not canonical: %q", cfg.Zones[0].Name)
	}
	if cfg.Refresh.MinInterval.Duration() != 30*time.Second {
		t.Fatalf("min interval: %s", cfg.Refresh.MinInterval.Duration())
	}
	if _, ok := cfg.ServerByName("primary1"); !ok {
		t.Fatal("missing server")
	}
}

func TestExampleConfigsLoad(t *testing.T) {
	for _, path := range []string{
		filepath.Join("..", "..", "examples", "config.example.yaml"),
		filepath.Join("..", "..", "examples", "config.yaml"),
	} {
		if _, err := Load(path); err != nil {
			t.Fatalf("load %s: %v", path, err)
		}
	}
}

func TestUnknownServerRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(`
zones:
  - name: x.
    servers: [nope]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error")
	}
}
