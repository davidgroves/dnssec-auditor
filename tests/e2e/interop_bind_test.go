//go:build e2e

package e2e

import (
	"os"
	"strings"
	"testing"
)

func TestInteropBIND(t *testing.T) {
	if !interopEnabled("bind") {
		t.Skip("set E2E_INTEROP=bind,knot to run BIND interop")
	}
	t.Fatal("BIND interop container path is not wired in this revision")
}

func TestInteropKnot(t *testing.T) {
	if !interopEnabled("knot") {
		t.Skip("set E2E_INTEROP=bind,knot to run Knot interop")
	}
	t.Fatal("Knot interop container path is not wired in this revision")
}

func interopEnabled(name string) bool {
	raw := os.Getenv("E2E_INTEROP")
	if raw == "" {
		return false
	}
	for _, p := range strings.Split(raw, ",") {
		if strings.TrimSpace(p) == name || strings.TrimSpace(p) == "all" {
			return true
		}
	}
	return false
}
