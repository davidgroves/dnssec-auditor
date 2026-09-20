package harness

import (
	"testing"
	"time"
)

func Eventually(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		last = "condition still false"
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout after %s: %s", timeout, last)
}
