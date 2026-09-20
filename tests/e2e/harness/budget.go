package harness

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type BudgetResult struct {
	Suite    string         `json:"suite"`
	N        int            `json:"n"`
	Duration time.Duration  `json:"duration_ns"`
	RSSBytes uint64         `json:"rss_bytes"`
	At       time.Time      `json:"at"`
	OK       bool           `json:"ok"`
	Detail   string         `json:"detail,omitempty"`
	Extra    map[string]any `json:"extra,omitempty"`
}

func RSS() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Sys
}

func WriteResult(name string, r BudgetResult) error {
	dir := os.Getenv("E2E_RESULTS_DIR")
	if dir == "" {
		dir = "tests/e2e/results"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	r.At = time.Now()
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, name+".json")
	return os.WriteFile(path, b, 0o644)
}
