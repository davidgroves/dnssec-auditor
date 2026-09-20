package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/davidgroves/dnssec-auditor/internal/metrics"
	"github.com/davidgroves/dnssec-auditor/internal/monitor"
	"github.com/davidgroves/dnssec-auditor/internal/version"
)

func (s *Server) registerRoutes(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "get-health",
		Method:      http.MethodGet,
		Path:        "/health",
		Summary:     "Liveness probe",
		Tags:        []string{"Status"},
	}, s.getHealth)

	huma.Register(api, huma.Operation{
		OperationID: "get-ready",
		Method:      http.MethodGet,
		Path:        "/ready",
		Summary:     "Readiness probe",
		Tags:        []string{"Status"},
	}, s.getReady)

	huma.Register(api, huma.Operation{
		OperationID: "get-ui-config",
		Method:      http.MethodGet,
		Path:        "/ui/config",
		Summary:     "UI theme configuration",
		Tags:        []string{"Status"},
	}, s.getUIConfig)

	huma.Register(api, huma.Operation{
		OperationID: "get-status",
		Method:      http.MethodGet,
		Path:        "/v1/status",
		Summary:     "Process status and zone counts",
		Tags:        []string{"Status"},
	}, s.getStatus)

	huma.Register(api, huma.Operation{
		OperationID: "get-memory",
		Method:      http.MethodGet,
		Path:        "/v1/memory",
		Summary:     "Process and zone-store memory snapshot",
		Tags:        []string{"Status"},
	}, s.getMemory)

	huma.Register(api, huma.Operation{
		OperationID: "list-zones",
		Method:      http.MethodGet,
		Path:        "/v1/zones",
		Summary:     "List monitored zones",
		Description: "Returns zone summaries without findings or history.",
		Tags:        []string{"Zones"},
	}, s.listZones)

	huma.Register(api, huma.Operation{
		OperationID: "get-zone",
		Method:      http.MethodGet,
		Path:        "/v1/zones/{zone}",
		Summary:     "Get a zone snapshot",
		Tags:        []string{"Zones"},
		Errors:      []int{http.StatusNotFound},
	}, s.getZone)

	huma.Register(api, huma.Operation{
		OperationID: "get-zone-soa",
		Method:      http.MethodGet,
		Path:        "/v1/zones/{zone}/soa",
		Summary:     "Get zone SOA fields",
		Tags:        []string{"Zones"},
		Errors:      []int{http.StatusNotFound},
	}, s.getZoneSOA)

	huma.Register(api, huma.Operation{
		OperationID: "get-zone-dnskeys",
		Method:      http.MethodGet,
		Path:        "/v1/zones/{zone}/dnskeys",
		Summary:     "List zone DNSKEYs",
		Tags:        []string{"Zones"},
		Errors:      []int{http.StatusNotFound, http.StatusInternalServerError},
	}, s.getZoneDNSKEYs)

	huma.Register(api, huma.Operation{
		OperationID: "get-zone-servers",
		Method:      http.MethodGet,
		Path:        "/v1/zones/{zone}/servers",
		Summary:     "List per-primary server status",
		Tags:        []string{"Zones"},
		Errors:      []int{http.StatusNotFound},
	}, s.getZoneServers)

	huma.Register(api, huma.Operation{
		OperationID: "get-zone-findings",
		Method:      http.MethodGet,
		Path:        "/v1/zones/{zone}/findings",
		Summary:     "List DNSSEC findings for a zone",
		Tags:        []string{"Zones"},
		Errors:      []int{http.StatusNotFound},
	}, s.getZoneFindings)

	huma.Register(api, huma.Operation{
		OperationID: "get-zone-history",
		Method:      http.MethodGet,
		Path:        "/v1/zones/{zone}/history",
		Summary:     "List recent zone state history",
		Tags:        []string{"Zones"},
		Errors:      []int{http.StatusNotFound},
	}, s.getZoneHistory)

	huma.Register(api, huma.Operation{
		OperationID: "dump-zone",
		Method:      http.MethodGet,
		Path:        "/v1/zones/{zone}/dump",
		Summary:     "Dump zone file with finding comments",
		Description: "Returns the transferred zone as a sorted master file (text/plain). " +
			"Error findings are inserted as '; CODE owner TYPE — message' comments before the owner's records.",
		Tags:   []string{"Zones"},
		Errors: []int{http.StatusNotFound, http.StatusConflict},
		Responses: map[string]*huma.Response{
			strconv.Itoa(http.StatusOK): {
				Description: "Zone dump (attachment)",
				Content: map[string]*huma.MediaType{
					"text/plain": {
						Schema: &huma.Schema{Type: "string"},
					},
				},
			},
		},
	}, s.dumpZone)

	huma.Register(api, huma.Operation{
		OperationID: "export-zone",
		Method:      http.MethodGet,
		Path:        "/v1/zones/{zone}/export",
		Summary:     "Export zone file contents",
		Description: "Alias of /dump: sorted master file with error finding comments.",
		Tags:        []string{"Zones"},
		Errors:      []int{http.StatusNotFound, http.StatusConflict},
		Responses: map[string]*huma.Response{
			strconv.Itoa(http.StatusOK): {
				Description: "Zone dump (attachment)",
				Content: map[string]*huma.MediaType{
					"text/plain": {
						Schema: &huma.Schema{Type: "string"},
					},
				},
			},
		},
	}, s.exportZone)

	huma.Register(api, huma.Operation{
		OperationID:   "refresh-zone",
		Method:        http.MethodPost,
		Path:          "/v1/zones/{zone}/refresh",
		Summary:       "Request a zone refresh",
		DefaultStatus: http.StatusAccepted,
		Tags:          []string{"Zones"},
		Errors:        []int{http.StatusNotFound},
	}, s.refreshZone)

	huma.Register(api, huma.Operation{
		OperationID: "list-catalogs",
		Method:      http.MethodGet,
		Path:        "/v1/catalogs",
		Summary:     "List catalog zones and members",
		Tags:        []string{"Catalogs"},
	}, s.listCatalogs)

	huma.Register(api, huma.Operation{
		OperationID: "stream-events",
		Method:      http.MethodGet,
		Path:        "/v1/events",
		Summary:     "Server-sent events stream",
		Description: "Long-lived text/event-stream of auditor events (data: JSON lines only).",
		Tags:        []string{"Events"},
		Responses: map[string]*huma.Response{
			strconv.Itoa(http.StatusOK): {
				Description: "SSE stream; each message is `data: <event JSON>`",
				Content: map[string]*huma.MediaType{
					"text/event-stream": {
						Schema: &huma.Schema{Type: "string"},
					},
				},
			},
		},
	}, s.streamEvents)
}

func (s *Server) getHealth(ctx context.Context, _ *struct{}) (*healthOutput, error) {
	out := &healthOutput{}
	out.Body.Status = "ok"
	out.Body.Version = version.Version
	return out, nil
}

func (s *Server) getReady(ctx context.Context, _ *struct{}) (*readyOutput, error) {
	out := &readyOutput{}
	out.Body.Status = "ready"
	out.Body.Zones = len(s.mgr.List())
	return out, nil
}

func (s *Server) getUIConfig(ctx context.Context, _ *struct{}) (*uiConfigOutput, error) {
	return &uiConfigOutput{Body: s.cfg.Theme}, nil
}

func (s *Server) getStatus(ctx context.Context, _ *struct{}) (*statusOutput, error) {
	out := &statusOutput{}
	out.Body.Version = version.Version
	out.Body.Commit = version.Commit
	out.Body.UptimeS = int(time.Since(s.started).Seconds())
	out.Body.Counts = s.mgr.Counts()
	out.Body.StartedAt = s.started
	return out, nil
}

func (s *Server) getMemory(ctx context.Context, _ *struct{}) (*memoryOutput, error) {
	return &memoryOutput{Body: metrics.SnapshotMemory(s.mgr.StoreBytes())}, nil
}

func (s *Server) listZones(ctx context.Context, input *zonesInput) (*zonesOutput, error) {
	views := s.mgr.Views()
	out := &zonesOutput{}
	out.Body.Zones = make([]monitor.ZoneView, 0, len(views))
	for _, v := range views {
		if input.State != "" && v.State != input.State {
			continue
		}
		if input.Source != "" && v.Source != input.Source {
			continue
		}
		v.Findings = nil
		v.History = nil
		out.Body.Zones = append(out.Body.Zones, v)
	}
	out.Body.Total = len(out.Body.Zones)
	return out, nil
}

func (s *Server) zoneOrNotFound(name string) (*monitor.ZoneRuntime, error) {
	z := s.mgr.Get(name)
	if z == nil {
		return nil, huma.Error404NotFound("not found")
	}
	return z, nil
}

func (s *Server) getZone(ctx context.Context, input *zonePathInput) (*zoneOutput, error) {
	z, err := s.zoneOrNotFound(input.Zone)
	if err != nil {
		return nil, err
	}
	return &zoneOutput{Body: z.Snapshot()}, nil
}

func (s *Server) getZoneSOA(ctx context.Context, input *zonePathInput) (*zoneSOAOutput, error) {
	z, err := s.zoneOrNotFound(input.Zone)
	if err != nil {
		return nil, err
	}
	return &zoneSOAOutput{Body: z.Snapshot().SOA}, nil
}

func (s *Server) getZoneDNSKEYs(ctx context.Context, input *zonePathInput) (*zoneDNSKEYsOutput, error) {
	z, err := s.zoneOrNotFound(input.Zone)
	if err != nil {
		return nil, err
	}
	st, chain := z.StoreAndChain()
	out := &zoneDNSKEYsOutput{}
	out.Body.ChainOfTrustOK = chain
	if st == nil {
		out.Body.DNSKEYs = []keyView{}
		return out, nil
	}
	keys, err := st.DNSKEYs()
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}
	out.Body.DNSKEYs = make([]keyView, 0, len(keys))
	for _, k := range keys {
		kv := keyView{
			Flags:     k.Flags,
			Protocol:  k.Protocol,
			Algorithm: k.Algorithm,
			KeyTag:    k.KeyTag(),
			KSK:       k.Flags&257 == 257 || k.Flags&1 == 1,
		}
		if ds := k.ToDS(2); ds != nil {
			kv.DS = ds.Digest
		}
		out.Body.DNSKEYs = append(out.Body.DNSKEYs, kv)
	}
	return out, nil
}

func (s *Server) getZoneServers(ctx context.Context, input *zonePathInput) (*zoneServersOutput, error) {
	z, err := s.zoneOrNotFound(input.Zone)
	if err != nil {
		return nil, err
	}
	return &zoneServersOutput{Body: z.Snapshot().Servers}, nil
}

func (s *Server) getZoneFindings(ctx context.Context, input *findingsInput) (*findingsOutput, error) {
	z, err := s.zoneOrNotFound(input.Zone)
	if err != nil {
		return nil, err
	}
	list := z.Snapshot().Findings
	if input.Severity != "" {
		filtered := list[:0]
		for _, f := range list {
			if string(f.Severity) == input.Severity {
				filtered = append(filtered, f)
			}
		}
		list = filtered
	}
	out := &findingsOutput{}
	out.Body.Findings = list
	return out, nil
}

func (s *Server) getZoneHistory(ctx context.Context, input *zonePathInput) (*zoneHistoryOutput, error) {
	z, err := s.zoneOrNotFound(input.Zone)
	if err != nil {
		return nil, err
	}
	return &zoneHistoryOutput{Body: z.Snapshot().History}, nil
}

func (s *Server) refreshZone(ctx context.Context, input *refreshInput) (*refreshOutput, error) {
	if err := s.mgr.RequestRefresh(input.Zone, input.Full); err != nil {
		return nil, huma.Error404NotFound(err.Error())
	}
	out := &refreshOutput{}
	out.Body.Status = "refreshing"
	out.Body.Full = input.Full
	return out, nil
}

func (s *Server) listCatalogs(ctx context.Context, _ *struct{}) (*catalogsOutput, error) {
	out := &catalogsOutput{}
	out.Body.Catalogs = make([]catalogView, 0, len(s.cfg.Catalogs))
	for _, c := range s.cfg.Catalogs {
		members := []string{}
		for _, v := range s.mgr.Views() {
			if strings.HasPrefix(v.Source, "catalog:"+c.Name) || v.Source == "catalog:"+c.Name {
				members = append(members, v.Name)
			}
		}
		out.Body.Catalogs = append(out.Body.Catalogs, catalogView{Name: c.Name, Members: members})
	}
	return out, nil
}
