package metrics

import (
	"fmt"
	"os"
	"runtime"
)

// MemorySnapshot is the process memory picture returned by GET /v1/memory.
type MemorySnapshot struct {
	RSSBytes        uint64 `json:"rss_bytes"`
	VirtualBytes    uint64 `json:"virtual_bytes"`
	HeapAllocBytes  uint64 `json:"heap_alloc_bytes"`
	HeapSysBytes    uint64 `json:"heap_sys_bytes"`
	HeapInuseBytes  uint64 `json:"heap_inuse_bytes"`
	StackInuseBytes uint64 `json:"stack_inuse_bytes"`
	SysBytes        uint64 `json:"sys_bytes"`
	NextGCBytes     uint64 `json:"next_gc_bytes"`
	NumGC           uint32 `json:"num_gc"`
	Goroutines      int    `json:"goroutines"`
	ZoneStoreBytes  uint64 `json:"zone_store_bytes"`
}

// SnapshotMemory reads OS RSS/virtual size and Go heap stats.
func SnapshotMemory(zoneStoreBytes uint64) MemorySnapshot {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	rss, virt := processMemory()
	return MemorySnapshot{
		RSSBytes:        rss,
		VirtualBytes:    virt,
		HeapAllocBytes:  ms.HeapAlloc,
		HeapSysBytes:    ms.HeapSys,
		HeapInuseBytes:  ms.HeapInuse,
		StackInuseBytes: ms.StackInuse,
		SysBytes:        ms.Sys,
		NextGCBytes:     ms.NextGC,
		NumGC:           ms.NumGC,
		Goroutines:      runtime.NumGoroutine(),
		ZoneStoreBytes:  zoneStoreBytes,
	}
}

func processMemory() (rss, virt uint64) {
	f, err := os.Open("/proc/self/statm")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	var pages, resident uint64
	if _, err := fmt.Fscan(f, &pages, &resident); err != nil {
		return 0, 0
	}
	page := uint64(os.Getpagesize())
	return resident * page, pages * page
}
