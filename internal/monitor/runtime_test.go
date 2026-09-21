package monitor

import (
	"encoding/json"
	"testing"
)

func TestTryLockRefreshExposesFullInSnapshot(t *testing.T) {
	z := NewZone("ex.test.", "config", nil, "")
	snap := z.Snapshot()
	if snap.Refreshing || snap.RefreshFull {
		t.Fatalf("idle snapshot should not be refreshing: %+v", snap)
	}

	if !z.TryLockRefresh(true) {
		t.Fatal("first full lock should succeed")
	}
	snap = z.Snapshot()
	if !snap.Refreshing || !snap.RefreshFull {
		t.Fatalf("in-flight full verify: refreshing=%v refresh_full=%v", snap.Refreshing, snap.RefreshFull)
	}

	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["refreshing"] != true || m["refresh_full"] != true {
		t.Fatalf("json flags: %#v", m)
	}

	if z.TryLockRefresh(false) {
		t.Fatal("second lock should fail while a full verify is in progress")
	}
	snap = z.Snapshot()
	if !snap.RefreshFull {
		t.Fatal("failed lock must not clear an in-flight full verify")
	}

	z.UnlockRefresh()
	snap = z.Snapshot()
	if snap.Refreshing || snap.RefreshFull {
		t.Fatalf("unlocked snapshot still refreshing: %+v", snap)
	}
}

func TestTryLockRefreshIncrementalDoesNotMarkFull(t *testing.T) {
	z := NewZone("inc.test.", "config", nil, "")
	if !z.TryLockRefresh(false) {
		t.Fatal("lock")
	}
	snap := z.Snapshot()
	if !snap.Refreshing || snap.RefreshFull {
		t.Fatalf("incremental refresh: refreshing=%v refresh_full=%v", snap.Refreshing, snap.RefreshFull)
	}
	z.UnlockRefresh()
}
