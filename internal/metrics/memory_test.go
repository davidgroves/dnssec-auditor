package metrics

import "testing"

func TestSnapshotMemory(t *testing.T) {
	snap := SnapshotMemory(42)
	if snap.HeapAllocBytes == 0 {
		t.Fatal("heap_alloc_bytes is 0")
	}
	if snap.SysBytes == 0 {
		t.Fatal("sys_bytes is 0")
	}
	if snap.Goroutines < 1 {
		t.Fatal("goroutines")
	}
	if snap.ZoneStoreBytes != 42 {
		t.Fatalf("zone_store_bytes=%d", snap.ZoneStoreBytes)
	}
	if snap.RSSBytes == 0 {
		t.Fatal("rss_bytes is 0; /proc/self/statm should be readable on Linux")
	}
	if snap.VirtualBytes < snap.RSSBytes {
		t.Fatalf("virtual %d < rss %d", snap.VirtualBytes, snap.RSSBytes)
	}
}

func TestProcessCollectorRegistered(t *testing.T) {
	fams, err := New().Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var sawRSS, sawHeap bool
	for _, f := range fams {
		switch f.GetName() {
		case "process_resident_memory_bytes":
			sawRSS = true
		case "go_memstats_heap_alloc_bytes":
			sawHeap = true
		}
	}
	if !sawRSS {
		t.Fatal("missing process_resident_memory_bytes")
	}
	if !sawHeap {
		t.Fatal("missing go_memstats_heap_alloc_bytes")
	}
}
