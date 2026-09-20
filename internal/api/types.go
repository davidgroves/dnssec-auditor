package api

import (
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/dnssec"
	"github.com/davidgroves/dnssec-auditor/internal/metrics"
	"github.com/davidgroves/dnssec-auditor/internal/monitor"
)

// Shared path parameter for zone-scoped routes.
type zonePathInput struct {
	Zone string `path:"zone" doc:"Zone name (one path segment; trailing dot optional)."`
}

type healthOutput struct {
	Body struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
}

type readyOutput struct {
	Body struct {
		Status string `json:"status"`
		Zones  int    `json:"zones"`
	}
}

type uiConfigOutput struct {
	Body config.ThemeConfig
}

type statusOutput struct {
	Body struct {
		Version   string         `json:"version"`
		Commit    string         `json:"commit"`
		UptimeS   int            `json:"uptime_s"`
		Counts    map[string]int `json:"counts"`
		StartedAt time.Time      `json:"started_at"`
	}
}

type memoryOutput struct {
	Body metrics.MemorySnapshot
}

type zonesInput struct {
	State  string `query:"state" doc:"Filter by zone state (e.g. valid, invalid, unsigned)."`
	Source string `query:"source" doc:"Filter by source (e.g. config, catalog:name)."`
}

type zonesOutput struct {
	Body struct {
		Zones []monitor.ZoneView `json:"zones"`
		Total int                `json:"total"`
	}
}

type zoneOutput struct {
	Body monitor.ZoneView
}

type zoneSOAOutput struct {
	Body *monitor.SOAInfo
}

type keyView struct {
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
	Algorithm uint8  `json:"algorithm"`
	KeyTag    uint16 `json:"keytag"`
	KSK       bool   `json:"ksk"`
	DS        string `json:"ds_sha256,omitempty"`
}

type zoneDNSKEYsOutput struct {
	Body struct {
		DNSKEYs        []keyView `json:"dnskeys"`
		ChainOfTrustOK *bool     `json:"chain_of_trust_ok"`
	}
}

type zoneServersOutput struct {
	Body []monitor.ServerStatus
}

type findingsInput struct {
	Zone     string `path:"zone" doc:"Zone name (one path segment; trailing dot optional)."`
	Severity string `query:"severity" enum:"error,warning" doc:"Filter by finding severity."`
}

type findingsOutput struct {
	Body struct {
		Findings []dnssec.Finding `json:"findings"`
	}
}

type zoneHistoryOutput struct {
	Body []monitor.HistoryEntry
}

type refreshInput struct {
	Zone string `path:"zone" doc:"Zone name (one path segment; trailing dot optional)."`
	Full bool   `query:"full" doc:"When true, force a full AXFR instead of IXFR."`
}

type refreshOutput struct {
	Body struct {
		Status string `json:"status"`
		Full   bool   `json:"full"`
	}
}

type catalogView struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

type catalogsOutput struct {
	Body struct {
		Catalogs []catalogView `json:"catalogs"`
	}
}
