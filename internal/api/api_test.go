package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/dnssec"
	"github.com/davidgroves/dnssec-auditor/internal/event"
	"github.com/davidgroves/dnssec-auditor/internal/logging"
	"github.com/davidgroves/dnssec-auditor/internal/metrics"
	"github.com/davidgroves/dnssec-auditor/internal/monitor"
	"github.com/davidgroves/dnssec-auditor/internal/zone"
	"github.com/miekg/dns"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	cfg := config.Defaults()
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	m := metrics.New()
	bus := event.New(8)
	mgr := monitor.New(&cfg, bus, m, logging.Setup(cfg.Logging, nil))
	return New(&cfg, mgr, m, bus)
}

func TestMemoryEndpoint(t *testing.T) {
	srv := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/memory", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
	}
	var snap metrics.MemorySnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.HeapAllocBytes == 0 {
		t.Fatal("heap_alloc_bytes")
	}
	if snap.RSSBytes == 0 {
		t.Fatal("rss_bytes")
	}
	if snap.Goroutines < 1 {
		t.Fatal("goroutines")
	}
	if strings.Contains(rec.Body.String(), `"$schema"`) {
		t.Fatal("unexpected $schema in success body")
	}
}

func TestMetricsIncludesProcessMemory(t *testing.T) {
	srv := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, name := range []string{
		"process_resident_memory_bytes",
		"go_memstats_heap_alloc_bytes",
		"dnssec_auditor_zone_store_bytes",
	} {
		if !strings.Contains(body, name) {
			t.Fatalf("missing %s", name)
		}
	}
}

func TestOpenAPIDocument(t *testing.T) {
	srv := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
	}
	var doc struct {
		OpenAPI string                    `json:"openapi"`
		Paths   map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.1") {
		t.Fatalf("openapi version %q", doc.OpenAPI)
	}
	required := []string{
		"/health",
		"/ready",
		"/ui/config",
		"/v1/status",
		"/v1/memory",
		"/v1/zones",
		"/v1/zones/{zone}",
		"/v1/zones/{zone}/soa",
		"/v1/zones/{zone}/dnskeys",
		"/v1/zones/{zone}/servers",
		"/v1/zones/{zone}/findings",
		"/v1/zones/{zone}/history",
		"/v1/zones/{zone}/dump",
		"/v1/zones/{zone}/export",
		"/v1/zones/{zone}/refresh",
		"/v1/catalogs",
		"/v1/events",
	}
	for _, p := range required {
		if _, ok := doc.Paths[p]; !ok {
			t.Fatalf("missing path %s", p)
		}
	}
	if _, ok := doc.Paths["/metrics"]; ok {
		t.Fatal("/metrics should not be in OpenAPI")
	}
	dump := doc.Paths["/v1/zones/{zone}/dump"]["get"].(map[string]any)
	responses := dump["responses"].(map[string]any)
	okResp := responses["200"].(map[string]any)
	content := okResp["content"].(map[string]any)
	if _, ok := content["text/plain"]; !ok {
		t.Fatalf("dump missing text/plain content: %#v", content)
	}
	export := doc.Paths["/v1/zones/{zone}/export"]["get"].(map[string]any)
	exportResponses := export["responses"].(map[string]any)
	exportOK := exportResponses["200"].(map[string]any)
	exportContent := exportOK["content"].(map[string]any)
	if _, ok := exportContent["text/plain"]; !ok {
		t.Fatalf("export missing text/plain content: %#v", exportContent)
	}
	events := doc.Paths["/v1/events"]["get"].(map[string]any)
	evResponses := events["responses"].(map[string]any)
	evOK := evResponses["200"].(map[string]any)
	evContent := evOK["content"].(map[string]any)
	if _, ok := evContent["text/event-stream"]; !ok {
		t.Fatalf("events missing text/event-stream: %#v", evContent)
	}
}

func TestDocsUI(t *testing.T) {
	srv := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "openapi") && !strings.Contains(body, "OpenAPI") && !strings.Contains(body, "elements") {
		t.Fatalf("docs HTML unexpected: %s", body[:min(200, len(body))])
	}
}

func TestZoneNotFoundProblemJSON(t *testing.T) {
	srv := testServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/zones/missing.example.", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "problem+json") && !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type %q", ct)
	}
	var problem map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem["status"] != float64(404) && problem["status"] != 404 {
		t.Fatalf("status field %#v", problem["status"])
	}
	detail, _ := problem["detail"].(string)
	if !strings.Contains(detail, "not found") {
		t.Fatalf("detail %q", detail)
	}
}

func TestDumpZone(t *testing.T) {
	cfg := config.Defaults()
	cfg.Zones = []config.Zone{{Name: "example.com.", Servers: []string{"p1"}}}
	cfg.Servers = []config.Server{{Name: "p1", Address: "127.0.0.1", Port: 53}}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	m := metrics.New()
	bus := event.New(8)
	mgr := monitor.New(&cfg, bus, m, logging.Setup(cfg.Logging, nil))
	z := mgr.Get("example.com.")
	if z == nil {
		t.Fatal("zone missing")
	}
	st := zone.NewStore("example.com.")
	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "ns.example.com.", Mbox: "h.example.com.", Serial: 1, Refresh: 60, Retry: 60, Expire: 60, Minttl: 60,
	}
	if err := st.AddRR(soa); err != nil {
		t.Fatal(err)
	}
	z.AttachStore(st)
	z.ApplyFindings([]dnssec.Finding{
		dnssec.NewFinding(dnssec.NSEC3Missing, dnssec.Error, "ns1.example.com.", dns.TypeNSEC3, "missing NSEC3"),
	}, nil, false)

	srv := New(&cfg, mgr, m, bus)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/zones/example.com./dump", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("content-type %q", rec.Header().Get("Content-Type"))
	}
	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, `filename="example.com.txt"`) {
		t.Fatalf("content-disposition %q", cd)
	}
	body := rec.Body.String()
	want := "; NSEC3_MISSING ns1.example.com. NSEC3 — missing NSEC3"
	if !strings.Contains(body, want) {
		t.Fatalf("missing comment in dump:\n%s", body)
	}
	if !strings.Contains(body, "example.com.") {
		t.Fatalf("missing SOA in dump:\n%s", body)
	}
}

func TestZonesListAndRefreshJSON(t *testing.T) {
	cfg := config.Defaults()
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	cfg.Zones = []config.Zone{{Name: "example.com.", Servers: []string{"p1"}}}
	cfg.Servers = []config.Server{{Name: "p1", Address: "127.0.0.1", Port: 53}}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	m := metrics.New()
	bus := event.New(8)
	mgr := monitor.New(&cfg, bus, m, logging.Setup(cfg.Logging, nil))
	srv := New(&cfg, mgr, m, bus)
	h := srv.Handler()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/zones", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status %d body=%s", rec.Code, rec.Body.String())
	}
	var list struct {
		Zones []monitor.ZoneView `json:"zones"`
		Total int                `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 || len(list.Zones) != 1 {
		t.Fatalf("list %#v", list)
	}
	if list.Zones[0].Name != "example.com." {
		t.Fatalf("zone name %q", list.Zones[0].Name)
	}
	if list.Zones[0].Findings != nil {
		t.Fatal("list should strip findings")
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/zones/example.com./refresh?full=true", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("refresh status %d body=%s", rec.Code, rec.Body.String())
	}
	var accepted struct {
		Status string `json:"status"`
		Full   bool   `json:"full"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Status != "refreshing" || !accepted.Full {
		t.Fatalf("accepted %#v", accepted)
	}

	z := mgr.Get("example.com.")
	if z == nil {
		t.Fatal("missing zone")
	}
	if !z.TryLockRefresh(true) {
		t.Fatal("lock")
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/zones/example.com.", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status %d body=%s", rec.Code, rec.Body.String())
	}
	var view monitor.ZoneView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.Refreshing || !view.RefreshFull {
		t.Fatalf("in-flight full verify flags: %+v", view)
	}
	z.UnlockRefresh()
}

func TestUIConfigSnakeCase(t *testing.T) {
	cfg := config.Defaults()
	cfg.Theme.AppName = "Test Auditor"
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	m := metrics.New()
	bus := event.New(8)
	mgr := monitor.New(&cfg, bus, m, logging.Setup(cfg.Logging, nil))
	srv := New(&cfg, mgr, m, bus)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ui/config", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
	}
	var theme map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &theme); err != nil {
		t.Fatal(err)
	}
	if theme["app_name"] != "Test Auditor" {
		t.Fatalf("theme %#v", theme)
	}
	if _, ok := theme["AppName"]; ok {
		t.Fatal("expected snake_case keys only")
	}
}
