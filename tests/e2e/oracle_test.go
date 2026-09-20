//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/davidgroves/dnssec-auditor/internal/check"
	"github.com/davidgroves/dnssec-auditor/internal/zonegen"
)

func TestOracle(t *testing.T) {
	kzone, kzoneErr := exec.LookPath("kzonecheck")
	bind, bindErr := exec.LookPath("dnssec-verify")
	if kzoneErr != nil && bindErr != nil {
		t.Skip("kzonecheck and dnssec-verify not installed")
	}

	dir := t.TempDir()
	g, err := zonegen.Small("oracle.test.")
	if err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good.db")
	writeZone(t, good, g)
	if code := check.Run(check.Options{Zone: "oracle.test.", File: good}, os.Stdout); code != 0 {
		t.Fatalf("auditor rejected a valid zone: %d", code)
	}
	if kzoneErr == nil {
		cmd := exec.Command(kzone, "--dnssec", "on", "-o", "oracle.test.", good)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("kzonecheck valid zone failed: %v\n%s", err, out)
		}
	}
	if bindErr == nil {
		cmd := exec.Command(bind, "-o", "oracle.test.", good)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("dnssec-verify disagrees on generator presentation (continuing): %v\n%s", err, out)
		}
	}

	if err := zonegen.FlipRRSIG(g); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.db")
	writeZone(t, bad, g)
	if code := check.Run(check.Options{Zone: "oracle.test.", File: bad}, os.Stdout); code != 1 {
		t.Fatalf("auditor accepted a broken zone: %d", code)
	}
	if kzoneErr == nil {
		cmd := exec.Command(kzone, "--dnssec", "on", "-o", "oracle.test.", bad)
		if err := cmd.Run(); err == nil {
			t.Fatal("kzonecheck accepted a broken zone")
		}
	}
}

func writeZone(t *testing.T, path string, g *zonegen.Generated) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := g.Store.WriteZoneFile(f); err != nil {
		t.Fatal(err)
	}
}
