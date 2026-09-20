package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const ns = "dnssec_auditor"

// Metrics holds all collectors. One instance is shared by the process.
type Metrics struct {
	Registry *prometheus.Registry

	ZoneValid           *prometheus.GaugeVec
	ZoneState           *prometheus.GaugeVec
	ZoneSerial          *prometheus.GaugeVec
	ZoneLastValid       *prometheus.GaugeVec
	ZoneLastVerified    *prometheus.GaugeVec
	ZoneLastTransfer    *prometheus.GaugeVec
	ZoneNextRefresh     *prometheus.GaugeVec
	ZoneRecords         *prometheus.GaugeVec
	ZoneRRSIGs          *prometheus.GaugeVec
	ZoneNSEC3           *prometheus.GaugeVec
	ZoneDNSKEYs         *prometheus.GaugeVec
	ZoneEarliestExpiry  *prometheus.GaugeVec
	ZoneFindings        *prometheus.GaugeVec
	ZoneChainOK         *prometheus.GaugeVec
	ZoneZONEMDOK        *prometheus.GaugeVec
	ZoneZONEMDCheckedAt *prometheus.GaugeVec
	ZoneZONEMDStale     *prometheus.GaugeVec
	ZoneServerSerial    *prometheus.GaugeVec
	ZoneServerReachable *prometheus.GaugeVec
	ZoneServerRTT       *prometheus.HistogramVec
	ZoneStoreBytes      prometheus.Gauge

	TransfersTotal       *prometheus.CounterVec
	TransferDuration     *prometheus.HistogramVec
	TransferRecords      *prometheus.CounterVec
	VerificationsTotal   *prometheus.CounterVec
	VerificationDuration *prometheus.HistogramVec
	RRSIGVerifications   *prometheus.CounterVec
	NotifiesReceived     *prometheus.CounterVec
	CatalogMembers       *prometheus.GaugeVec
	WebhookDeliveries    *prometheus.CounterVec
	StateSaves           *prometheus.CounterVec
}

func New() *Metrics {
	r := prometheus.NewRegistry()
	r.MustRegister(collectors.NewGoCollector())
	// process_resident_memory_bytes, process_virtual_memory_bytes, process_cpu_seconds_total, …
	r.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	f := promauto.With(r)
	m := &Metrics{Registry: r}

	m.ZoneValid = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_valid", Help: "1 if the zone has no error findings."}, []string{"zone"})
	m.ZoneState = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_state", Help: "1 for the current zone state label."}, []string{"zone", "state"})
	m.ZoneSerial = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_serial", Help: "Current SOA serial."}, []string{"zone"})
	m.ZoneLastValid = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_last_valid_timestamp_seconds", Help: "Unix time the zone was last valid."}, []string{"zone"})
	m.ZoneLastVerified = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_last_verified_timestamp_seconds", Help: "Unix time of the last verification."}, []string{"zone"})
	m.ZoneLastTransfer = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_last_transfer_timestamp_seconds", Help: "Unix time of the last successful transfer."}, []string{"zone"})
	m.ZoneNextRefresh = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_next_refresh_timestamp_seconds", Help: "Unix time of the next scheduled refresh."}, []string{"zone"})
	m.ZoneRecords = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_records", Help: "Number of resource records in the store."}, []string{"zone"})
	m.ZoneRRSIGs = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_rrsigs", Help: "Number of RRSIG records."}, []string{"zone"})
	m.ZoneNSEC3 = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_nsec3_records", Help: "Number of NSEC3 records."}, []string{"zone"})
	m.ZoneDNSKEYs = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_dnskeys", Help: "Number of DNSKEY records."}, []string{"zone", "flags", "algorithm"})
	m.ZoneEarliestExpiry = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_rrsig_earliest_expiry_timestamp_seconds", Help: "Earliest RRSIG expiration."}, []string{"zone"})
	m.ZoneFindings = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_findings", Help: "Open findings by code and severity."}, []string{"zone", "code", "severity"})
	m.ZoneChainOK = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_chain_of_trust_ok", Help: "1 if parent DS matches a signing KSK."}, []string{"zone"})
	m.ZoneZONEMDOK = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_zonemd_ok", Help: "1 if last ZONEMD check matched, 0 if mismatched, -1 if never checked."}, []string{"zone"})
	m.ZoneZONEMDCheckedAt = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_zonemd_checked_timestamp_seconds", Help: "Unix time of the last ZONEMD digest check."}, []string{"zone"})
	m.ZoneZONEMDStale = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_zonemd_stale", Help: "1 if the zone changed since the last ZONEMD check."}, []string{"zone"})
	m.ZoneServerSerial = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_server_serial", Help: "SOA serial reported by a configured server."}, []string{"zone", "server"})
	m.ZoneServerReachable = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "zone_server_reachable", Help: "1 if the last SOA probe succeeded."}, []string{"zone", "server"})
	m.ZoneServerRTT = f.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Name: "zone_server_probe_rtt_seconds", Help: "SOA probe RTT.", Buckets: prometheus.DefBuckets}, []string{"zone", "server"})
	m.ZoneStoreBytes = f.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "zone_store_bytes", Help: "Estimated bytes used by all in-memory zone stores."})

	m.TransfersTotal = f.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "transfers_total", Help: "Zone transfers."}, []string{"zone", "method", "result"})
	m.TransferDuration = f.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Name: "transfer_duration_seconds", Help: "Zone transfer duration.", Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300}}, []string{"zone", "method"})
	m.TransferRecords = f.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "transfer_records_total", Help: "Records received during transfers."}, []string{"zone", "method"})
	m.VerificationsTotal = f.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "verifications_total", Help: "Verification passes."}, []string{"zone", "mode", "result"})
	m.VerificationDuration = f.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Name: "verification_duration_seconds", Help: "Verification duration.", Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120}}, []string{"zone", "mode"})
	m.RRSIGVerifications = f.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "rrsig_verifications_total", Help: "Individual RRSIG cryptographic checks."}, []string{"algorithm", "result"})
	m.NotifiesReceived = f.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "notifies_received_total", Help: "NOTIFY messages received."}, []string{"transport", "result"})
	m.CatalogMembers = f.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "catalog_members", Help: "Member zones learned from a catalog."}, []string{"catalog"})
	m.WebhookDeliveries = f.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "webhook_deliveries_total", Help: "Webhook delivery attempts."}, []string{"target", "result"})
	m.StateSaves = f.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: "state_saves_total", Help: "State file write attempts."}, []string{"result"})
	return m
}
