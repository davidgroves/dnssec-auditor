package check

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/davidgroves/dnssec-auditor/internal/zonegen"
)

func TestCheckFileValidAndBroken(t *testing.T) {
	g, err := zonegen.Small("cli.test.")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "good.db")
	f, err := os.Create(good)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Store.WriteZoneFile(f); err != nil {
		t.Fatal(err)
	}
	f.Close()

	var buf bytes.Buffer
	if code := Run(Options{Zone: "cli.test.", File: good}, &buf); code != 0 {
		t.Fatalf("valid zone exit %d output=%s", code, buf.String())
	}

	if err := zonegen.FlipRRSIG(g); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.db")
	f, err = os.Create(bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Store.WriteZoneFile(f); err != nil {
		t.Fatal(err)
	}
	f.Close()
	buf.Reset()
	if code := Run(Options{Zone: "cli.test.", File: bad}, &buf); code != 1 {
		t.Fatalf("broken zone exit %d output=%s", code, buf.String())
	}
}
