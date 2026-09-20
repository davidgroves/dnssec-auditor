package monitor

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/dnssec"
	"github.com/davidgroves/dnssec-auditor/internal/zonegen"
)

func TestApplyZONEMDResultFullAndIncremental(t *testing.T) {
	g, err := zonegen.Generate(zonegen.Options{
		Origin:      "mdmon.test.",
		Delegations: 2,
		SecurePct:   50,
		Denial:      zonegen.DenialNSEC3OptOut,
		Seed:        9,
		ZONEMD:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	z := NewZone("mdmon.test.", "config", nil, "")
	z.Store = g.Store

	full := &dnssec.Result{Mode: "full", ZONEMDChecked: true, ZONEMDOK: true}
	applyZONEMDResult(z, g.Store, full)
	if z.ZONEMDOK == nil || !*z.ZONEMDOK || z.ZONEMDStale || z.ZONEMDCheckedAt.IsZero() {
		t.Fatalf("after full: ok=%v stale=%v at=%v", z.ZONEMDOK, z.ZONEMDStale, z.ZONEMDCheckedAt)
	}
	checked := z.ZONEMDCheckedAt

	inc := &dnssec.Result{Mode: "incremental", ZONEMDChecked: false}
	applyZONEMDResult(z, g.Store, inc)
	if z.ZONEMDOK == nil || !*z.ZONEMDOK {
		t.Fatal("incremental must preserve zonemd_ok")
	}
	if !z.ZONEMDStale {
		t.Fatal("incremental must mark zonemd_stale")
	}
	if !z.ZONEMDCheckedAt.Equal(checked) {
		t.Fatal("incremental must preserve checked_at")
	}
}

func TestLastFullVerifiedOnlyOnFull(t *testing.T) {
	z := NewZone("fullts.test.", "config", nil, "")
	if snap := z.Snapshot(); snap.LastFullVerified != nil {
		t.Fatal("expected omitted LastFullVerified")
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	z.LastVerified = now
	z.VerifyMode = "full"
	z.LastFullVerified = now
	snap := z.Snapshot()
	if snap.LastFullVerified == nil || !snap.LastFullVerified.Equal(now) {
		t.Fatalf("after full: got %#v want %v", snap.LastFullVerified, now)
	}

	z.LastVerified = time.Now()
	z.VerifyMode = "incremental"
	snap = z.Snapshot()
	if snap.LastFullVerified == nil || !snap.LastFullVerified.Equal(now) {
		t.Fatal("incremental must preserve last_full_verified_at")
	}

	raw, err := json.Marshal(NewZone("empty.test.", "config", nil, "").Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["last_full_verified_at"]; ok {
		t.Fatalf("should omit unset last_full_verified_at, got %#v", m["last_full_verified_at"])
	}
}

func TestZoneViewOmitsUncheckedZONEMD(t *testing.T) {
	z := NewZone("nozmd.test.", "config", nil, "")
	raw, err := json.Marshal(z.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["zonemd_ok"]; ok {
		t.Fatalf("zonemd_ok should be omitted, got %#v", m["zonemd_ok"])
	}
	if _, ok := m["zonemd_checked_at"]; ok {
		t.Fatalf("zonemd_checked_at should be omitted, got %#v", m["zonemd_checked_at"])
	}

	now := time.Now().UTC().Truncate(time.Second)
	ok := false
	z.ZONEMDOK = &ok
	z.ZONEMDCheckedAt = now
	raw, err = json.Marshal(z.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["zonemd_ok"] != false {
		t.Fatalf("want zonemd_ok=false, got %#v", m["zonemd_ok"])
	}
	if m["zonemd_checked_at"] == nil || m["zonemd_checked_at"] == "" {
		t.Fatalf("want zonemd_checked_at set, got %#v", m["zonemd_checked_at"])
	}
}

func TestZONEMDMaxAgeDue(t *testing.T) {
	cfg := config.Defaults()
	cfg.Verification.ZONEMDMaxAge = config.Duration(time.Hour)
	m := &Manager{cfg: &cfg}
	g, err := zonegen.Generate(zonegen.Options{
		Origin:      "mdage.test.",
		Delegations: 1,
		SecurePct:   0,
		Denial:      zonegen.DenialNSEC3OptOut,
		Seed:        3,
		ZONEMD:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	z := NewZone("mdage.test.", "config", nil, "")
	z.Store = g.Store
	if !m.zonemdMaxAgeDue(z, g.Store) {
		t.Fatal("never checked should be due when ZONEMD present")
	}
	z.ZONEMDCheckedAt = time.Now()
	if m.zonemdMaxAgeDue(z, g.Store) {
		t.Fatal("fresh check should not be due")
	}
	z.ZONEMDCheckedAt = time.Now().Add(-2 * time.Hour)
	if !m.zonemdMaxAgeDue(z, g.Store) {
		t.Fatal("expired max_age should be due")
	}
}
