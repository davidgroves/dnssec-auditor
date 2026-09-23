package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/dnsname"
	"github.com/davidgroves/dnssec-auditor/internal/dnssec"
	"github.com/davidgroves/dnssec-auditor/internal/event"
	"github.com/davidgroves/dnssec-auditor/internal/logging"
	"github.com/davidgroves/dnssec-auditor/internal/metrics"
	"github.com/davidgroves/dnssec-auditor/internal/xfr"
	"github.com/davidgroves/dnssec-auditor/internal/zone"
	"github.com/miekg/dns"
)

type Manager struct {
	cfg      *config.Config
	client   *xfr.Client
	verifier *dnssec.Verifier
	bus      *event.Bus
	metrics  *metrics.Metrics
	log      *slog.Logger

	mu    sync.RWMutex
	zones map[string]*ZoneRuntime

	sem chan struct{}
}

func New(cfg *config.Config, bus *event.Bus, m *metrics.Metrics, log *slog.Logger) *Manager {
	n := cfg.Refresh.ConcurrentTransfers
	if n < 1 {
		n = 1
	}
	mgr := &Manager{
		cfg:      cfg,
		client:   xfr.New(cfg),
		verifier: dnssec.New(cfg.Verification),
		bus:      bus,
		metrics:  m,
		log:      log,
		zones:    map[string]*ZoneRuntime{},
		sem:      make(chan struct{}, n),
	}
	for _, z := range cfg.Zones {
		mgr.AddZone(z.Name, "config", cfg.ResolveServers(z.Servers), z.TSIGKey)
	}
	for _, c := range cfg.Catalogs {
		mgr.AddZone(c.Name, "catalog", cfg.ResolveServers(c.Servers), c.TSIGKey)
	}
	return mgr
}

func (m *Manager) AddZone(name, source string, servers []config.Server, tsig string) {
	name = dnsname.Canonical(name)
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.zones[name]; ok {
		if existing.Source == "config" {
			return
		}
	}
	m.zones[name] = NewZone(name, source, servers, tsig)
}

func (m *Manager) RemoveZone(name string) {
	name = dnsname.Canonical(name)
	m.mu.Lock()
	delete(m.zones, name)
	m.mu.Unlock()
}

func (m *Manager) Get(name string) *ZoneRuntime {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.zones[dnsname.Canonical(name)]
}

func (m *Manager) List() []*ZoneRuntime {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*ZoneRuntime, 0, len(m.zones))
	for _, z := range m.zones {
		out = append(out, z)
	}
	return out
}

func (m *Manager) Views() []ZoneView {
	zs := m.List()
	out := make([]ZoneView, 0, len(zs))
	for _, z := range zs {
		out = append(out, z.Snapshot())
	}
	return out
}

func (m *Manager) Counts() map[string]int {
	c := map[string]int{}
	for _, z := range m.List() {
		z.mu.RLock()
		c[string(z.State)]++
		z.mu.RUnlock()
	}
	return c
}

// StoreBytes is the estimated size of every in-memory zone store.
func (m *Manager) StoreBytes() uint64 {
	var n uint64
	for _, z := range m.List() {
		st, _ := z.StoreAndChain()
		if st != nil {
			n += uint64(st.EstimateBytes())
		}
	}
	return n
}

func (m *Manager) Run(ctx context.Context) {
	// initial refresh of all zones
	for _, z := range m.List() {
		go m.Refresh(ctx, z, false)
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	expTick := time.NewTicker(m.cfg.Verification.ExpiryCheckInterval.Duration())
	if m.cfg.Verification.ExpiryCheckInterval.Duration() <= 0 {
		expTick.Stop()
	}
	defer expTick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			now := time.Now()
			for _, z := range m.List() {
				z.mu.Lock()
				if !z.Refreshing && (z.State == StateTransferring || z.State == StateVerifying) {
					if term := z.lastTerminalState(); term != z.State {
						z.State = term
					}
				}
				due := !z.NextRefresh.IsZero() && !now.Before(z.NextRefresh)
				expired := !z.ExpireAt.IsZero() && now.After(z.ExpireAt) && z.State != StateStale
				if expired {
					z.setState(StateStale, 0, "", "", "SOA EXPIRE elapsed")
				}
				z.mu.Unlock()
				if expired {
					m.bus.Publish(event.Event{Type: event.ZoneStale, Zone: z.Name, State: string(StateStale)})
				}
				if due {
					go m.Refresh(ctx, z, false)
				}
			}
		case <-expTick.C:
			for _, z := range m.List() {
				m.sweep(z)
			}
		}
	}
}

func (m *Manager) RequestRefresh(name string, forceFull bool) error {
	z := m.Get(name)
	if z == nil {
		return fmt.Errorf("unknown zone %s", name)
	}
	if forceFull {
		z.mu.Lock()
		z.RefreshFull = true
		z.mu.Unlock()
	}
	go m.Refresh(context.Background(), z, forceFull)
	return nil
}

func (m *Manager) Refresh(ctx context.Context, z *ZoneRuntime, forceFull bool) {
	if !z.TryLockRefresh(forceFull) {
		return
	}
	defer z.UnlockRefresh()
	m.sem <- struct{}{}
	defer func() { <-m.sem }()

	wide := logging.StartWide("refresh_cycle")
	wide.Zone = z.Name
	wide.Source = z.Source

	z.mu.Lock()
	servers := append([]config.Server(nil), z.Servers...)
	tsig := z.TSIGKey
	oldSerial := uint32(0)
	if z.Store != nil {
		oldSerial = z.Store.Serial()
	}
	z.mu.Unlock()
	wide.SerialFrom = oldSerial

	timeout := m.cfg.Refresh.SOATimeout.Duration()
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	stats := make([]ServerStatus, 0, len(servers))
	var best *xfr.SOAResult
	for _, s := range servers {
		r := m.client.ProbeSOA(ctx, z.Name, s, tsig, timeout)
		st := ServerStatus{Name: s.Name, Serial: r.Serial, Reachable: r.Reachable, RTT: r.RTT, At: time.Now()}
		if r.Err != nil {
			st.Error = r.Err.Error()
		}
		stats = append(stats, st)
		m.metrics.ZoneServerSerial.WithLabelValues(z.Name, s.Name).Set(float64(r.Serial))
		reach := 0.0
		if r.Reachable {
			reach = 1
		}
		m.metrics.ZoneServerReachable.WithLabelValues(z.Name, s.Name).Set(reach)
		m.metrics.ZoneServerRTT.WithLabelValues(z.Name, s.Name).Observe(r.RTT.Seconds())
		if r.Reachable && (best == nil || serialGreater(r.Serial, best.Serial)) {
			cp := r
			best = &cp
		}
		if !m.cfg.Refresh.ProbeAllServers && r.Reachable {
			break
		}
	}
	z.mu.Lock()
	z.ServersStat = stats
	z.mu.Unlock()
	m.detectSkew(z, stats)

	if best == nil {
		z.mu.Lock()
		z.setState(StateTransferFailed, oldSerial, "", "", "all servers unreachable")
		z.schedule(m.cfg.Refresh, 0, 60, true)
		z.mu.Unlock()
		wide.Result = "transfer_failed"
		wide.Extra = map[string]any{"error": "all servers unreachable"}
		wide.Emit(m.log)
		m.metrics.TransfersTotal.WithLabelValues(z.Name, "soa", "error").Inc()
		m.bus.Publish(event.Event{Type: event.TransferFailed, Zone: z.Name, Result: "error"})
		return
	}
	wide.Server = best.Server
	wide.SerialTo = best.Serial

	if oldSerial != 0 && best.Serial == oldSerial && !forceFull {
		z.mu.Lock()
		store := z.Store
		z.mu.Unlock()
		if store != nil && m.zonemdMaxAgeDue(z, store) {
			vres := m.verifier.Full(store)
			wide.VerifyMode = vres.Mode
			wide.ZONEMDChecked = vres.ZONEMDChecked
			wide.Method = "soa"
			z.mu.Lock()
			z.Findings = vres.Findings
			z.VerifyMode = vres.Mode
			z.LastVerified = time.Now()
			if vres.Mode == "full" {
				z.LastFullVerified = z.LastVerified
			}
			z.LastTransfer = time.Now()
			applyZONEMDResult(z, store, vres)
			newState := StateInvalid
			if vres.Unsigned {
				newState = StateUnsigned
			} else if vres.Valid {
				newState = StateValid
			}
			z.setState(newState, store.Serial(), vres.Mode, "soa", "zonemd_max_age")
			z.schedule(m.cfg.Refresh, best.Refresh, best.Retry, false)
			z.mu.Unlock()
			view := z.Snapshot()
			m.updateZoneMetrics(view, vres)
			result := "invalid"
			if vres.Valid {
				result = "valid"
			}
			if vres.Unsigned {
				result = "unsigned"
			}
			wide.Result = result
			wide.Emit(m.log)
			m.metrics.VerificationsTotal.WithLabelValues(z.Name, vres.Mode, result).Inc()
			m.metrics.VerificationDuration.WithLabelValues(z.Name, vres.Mode).Observe(vres.Duration.Seconds())
			m.bus.Publish(event.Event{Type: event.VerificationCompleted, Zone: z.Name, Mode: vres.Mode, Result: result, State: string(newState)})
			return
		}
		z.mu.Lock()
		z.LastTransfer = time.Now()
		if term := z.lastTerminalState(); term != z.State {
			z.State = term
		}
		z.schedule(m.cfg.Refresh, best.Refresh, best.Retry, false)
		z.mu.Unlock()
		wide.Result = "unchanged"
		wide.Method = "soa"
		wide.Emit(m.log)
		return
	}

	var srv config.Server
	for _, s := range servers {
		if s.Name == best.Server {
			srv = s
			break
		}
	}
	axfrTO := m.cfg.Refresh.AXFRTimeout.Duration()
	if axfrTO <= 0 {
		axfrTO = 10 * time.Minute
	}

	z.mu.Lock()
	z.State = StateTransferring
	z.mu.Unlock()

	var tres *xfr.Result
	var err error
	method := "axfr"
	if !forceFull && oldSerial != 0 && m.cfg.Refresh.PreferIXFR {
		tres, err = m.client.IXFR(ctx, z.Name, oldSerial, srv, tsig, axfrTO)
		if err != nil {
			m.log.Warn("ixfr failed, falling back to axfr", "zone", z.Name, "err", err)
			tres, err = m.client.AXFR(ctx, z.Name, srv, tsig, axfrTO)
		} else {
			method = tres.Method
		}
	} else {
		tres, err = m.client.AXFR(ctx, z.Name, srv, tsig, axfrTO)
	}
	if err != nil {
		z.mu.Lock()
		z.setState(StateTransferFailed, oldSerial, "", method, err.Error())
		z.schedule(m.cfg.Refresh, best.Refresh, best.Retry, true)
		z.mu.Unlock()
		wide.Result = "transfer_failed"
		wide.Method = method
		wide.Extra = map[string]any{"error": err.Error()}
		wide.Emit(m.log)
		m.metrics.TransfersTotal.WithLabelValues(z.Name, method, "error").Inc()
		m.bus.Publish(event.Event{Type: event.TransferFailed, Zone: z.Name, Method: method, Result: "error"})
		return
	}
	wide.Method = tres.Method
	wide.RecordsAdded = len(tres.Adds)
	wide.RecordsRemoved = len(tres.Removes)
	m.metrics.TransfersTotal.WithLabelValues(z.Name, tres.Method, "ok").Inc()
	m.metrics.TransferDuration.WithLabelValues(z.Name, tres.Method).Observe(tres.Duration.Seconds())
	m.metrics.TransferRecords.WithLabelValues(z.Name, tres.Method).Add(float64(tres.Records))
	m.bus.Publish(event.Event{Type: event.TransferCompleted, Zone: z.Name, Method: tres.Method, Result: "ok"})

	z.mu.Lock()
	z.State = StateVerifying
	z.LastTransfer = time.Now()
	z.LastMethod = tres.Method
	var touched *zone.Touched
	if tres.Store != nil {
		z.Store = tres.Store
	} else if z.Store != nil {
		touched, err = z.Store.ApplyChanges(tres.Adds, tres.Removes)
		if err != nil {
			z.setState(StateInvalid, oldSerial, "", "ixfr", "apply failed")
			z.Findings.Add(dnssec.NewFinding(dnssec.IXFRApplyFailed, dnssec.Error, z.Name, 0, err.Error()))
			z.mu.Unlock()
			wide.Result = "ixfr_apply_failed"
			wide.Emit(m.log)
			return
		}
	} else {
		z.mu.Unlock()
		wide.Result = "no_store"
		wide.Emit(m.log)
		return
	}
	if soa := z.Store.SOA(); soa != nil {
		z.ExpireAt = time.Now().Add(time.Duration(soa.Expire) * time.Second)
	}
	store := z.Store
	prev := z.Findings
	z.mu.Unlock()

	var vres *dnssec.Result
	forceZONEMD := m.zonemdMaxAgeDue(z, store)
	if forceFull || tres.Method == "axfr" || tres.Fallback || touched == nil || forceZONEMD {
		vres = m.verifier.Full(store)
	} else {
		vres = m.verifier.Incremental(store, prev, touched)
	}
	wide.VerifyMode = vres.Mode
	wide.RRSIGsVerified = vres.RRSIGsVerified
	wide.NSEC3Checked = vres.NSEC3Checked
	wide.ZONEMDChecked = vres.ZONEMDChecked
	wide.FindingsOpened = vres.Findings.CountBySeverity(dnssec.Error)
	wide.Warnings = vres.Findings.CountBySeverity(dnssec.Warning)

	z.mu.Lock()
	z.Findings = vres.Findings
	z.VerifyMode = vres.Mode
	z.LastVerified = time.Now()
	if vres.Mode == "full" {
		z.LastFullVerified = z.LastVerified
	}
	applyZONEMDResult(z, store, vres)
	newState := StateInvalid
	if vres.Unsigned {
		newState = StateUnsigned
	} else if vres.Valid {
		newState = StateValid
	}
	z.setState(newState, store.Serial(), vres.Mode, tres.Method, "")
	z.schedule(m.cfg.Refresh, best.Refresh, best.Retry, false)
	z.mu.Unlock()
	view := z.Snapshot()

	m.updateZoneMetrics(view, vres)
	result := "invalid"
	if vres.Valid {
		result = "valid"
	}
	if vres.Unsigned {
		result = "unsigned"
	}
	wide.Result = result
	wide.Emit(m.log)
	m.metrics.VerificationsTotal.WithLabelValues(z.Name, vres.Mode, result).Inc()
	m.metrics.VerificationDuration.WithLabelValues(z.Name, vres.Mode).Observe(vres.Duration.Seconds())
	m.bus.Publish(event.Event{Type: event.VerificationCompleted, Zone: z.Name, Mode: vres.Mode, Result: result, State: string(newState)})
	m.bus.Publish(event.Event{Type: event.ZoneStateChanged, Zone: z.Name, State: string(newState)})
	if newState == StateValid || newState == StateUnsigned {
		m.bus.Publish(event.Event{Type: event.ZoneValid, Zone: z.Name, State: string(newState)})
	} else {
		m.bus.Publish(event.Event{Type: event.ZoneInvalid, Zone: z.Name, State: string(newState)})
	}
}

func (m *Manager) sweep(z *ZoneRuntime) {
	z.mu.Lock()
	if z.Store == nil || z.Findings == nil {
		z.mu.Unlock()
		return
	}
	opened := m.verifier.SweepExpiry(z.Store, z.Findings)
	if opened > 0 && z.Findings.HasErrors() && z.State == StateValid {
		z.setState(StateInvalid, z.Store.Serial(), "expiry", "", "RRSIG expired")
		m.bus.Publish(event.Event{Type: event.ZoneInvalid, Zone: z.Name, State: string(StateInvalid)})
		m.bus.Publish(event.Event{Type: event.ZoneStateChanged, Zone: z.Name, State: string(StateInvalid)})
	}
	if z.Findings.CountBySeverity(dnssec.Warning) > 0 {
		m.bus.Publish(event.Event{Type: event.ZoneExpiringSoon, Zone: z.Name})
	}
	z.mu.Unlock()
}

func (m *Manager) detectSkew(z *ZoneRuntime, stats []ServerStatus) {
	var serials []uint32
	for _, s := range stats {
		if s.Reachable {
			serials = append(serials, s.Serial)
		}
	}
	if len(serials) < 2 {
		return
	}
	min, max := serials[0], serials[0]
	for _, s := range serials[1:] {
		if serialGreater(min, s) {
			min = s
		}
		if serialGreater(s, max) {
			max = s
		}
	}
	diff := int(max - min)
	if diff < 0 {
		diff = -diff
	}
	if diff <= m.cfg.Refresh.SerialSkewWarning {
		z.mu.Lock()
		z.SkewSince = time.Time{}
		z.mu.Unlock()
		return
	}
	z.mu.Lock()
	if z.SkewSince.IsZero() {
		z.SkewSince = time.Now()
	}
	since := z.SkewSince
	z.mu.Unlock()
	if time.Since(since) >= m.cfg.Refresh.SerialSkewGrace.Duration() {
		z.mu.Lock()
		z.Findings.Add(dnssec.NewFinding(dnssec.SerialSkew, dnssec.Warning, z.Name, 0, fmt.Sprintf("server serials differ by %d", diff)))
		z.mu.Unlock()
		m.bus.Publish(event.Event{Type: event.SerialSkew, Zone: z.Name, Detail: map[string]any{"diff": diff}})
	}
}

func (m *Manager) updateZoneMetrics(v ZoneView, r *dnssec.Result) {
	valid := 0.0
	if v.Valid {
		valid = 1
	}
	m.metrics.ZoneValid.WithLabelValues(v.Name).Set(valid)
	for _, s := range []string{"unknown", "transferring", "verifying", "valid", "invalid", "unsigned", "transfer_failed", "stale"} {
		val := 0.0
		if v.State == s {
			val = 1
		}
		m.metrics.ZoneState.WithLabelValues(v.Name, s).Set(val)
	}
	m.metrics.ZoneSerial.WithLabelValues(v.Name).Set(float64(v.Serial))
	m.metrics.ZoneRecords.WithLabelValues(v.Name).Set(float64(v.Records))
	m.metrics.ZoneRRSIGs.WithLabelValues(v.Name).Set(float64(v.RRSIGs))
	m.metrics.ZoneNSEC3.WithLabelValues(v.Name).Set(float64(v.NSEC3))
	if !v.LastValidAt.IsZero() {
		m.metrics.ZoneLastValid.WithLabelValues(v.Name).Set(float64(v.LastValidAt.Unix()))
	}
	if !v.LastVerified.IsZero() {
		m.metrics.ZoneLastVerified.WithLabelValues(v.Name).Set(float64(v.LastVerified.Unix()))
	}
	if !v.LastTransfer.IsZero() {
		m.metrics.ZoneLastTransfer.WithLabelValues(v.Name).Set(float64(v.LastTransfer.Unix()))
	}
	if !v.NextRefresh.IsZero() {
		m.metrics.ZoneNextRefresh.WithLabelValues(v.Name).Set(float64(v.NextRefresh.Unix()))
	}
	if r != nil && r.EarliestExpiry != 0 {
		m.metrics.ZoneEarliestExpiry.WithLabelValues(v.Name).Set(float64(r.EarliestExpiry))
	}
	if r != nil {
		if v.ZONEMDOK == nil {
			m.metrics.ZoneZONEMDOK.WithLabelValues(v.Name).Set(-1)
		} else if *v.ZONEMDOK {
			m.metrics.ZoneZONEMDOK.WithLabelValues(v.Name).Set(1)
		} else {
			m.metrics.ZoneZONEMDOK.WithLabelValues(v.Name).Set(0)
		}
	}
	if v.ZONEMDCheckedAt != nil {
		m.metrics.ZoneZONEMDCheckedAt.WithLabelValues(v.Name).Set(float64(v.ZONEMDCheckedAt.Unix()))
	}
	stale := 0.0
	if v.ZONEMDStale {
		stale = 1
	}
	m.metrics.ZoneZONEMDStale.WithLabelValues(v.Name).Set(stale)
	m.metrics.ZoneFindings.Reset()
	for _, f := range v.Findings {
		m.metrics.ZoneFindings.WithLabelValues(v.Name, f.Code, string(f.Severity)).Inc()
	}
	m.metrics.ZoneStoreBytes.Set(float64(m.StoreBytes()))
}

// zonemdMaxAgeDue reports whether a full verify should be forced so ZONEMD is rehashed.
func (m *Manager) zonemdMaxAgeDue(z *ZoneRuntime, st *zone.Store) bool {
	maxAge := m.cfg.Verification.ZONEMDMaxAge.Duration()
	if maxAge <= 0 {
		return false
	}
	if strings.EqualFold(m.cfg.Verification.ZONEMD, "off") {
		return false
	}
	if !storeHasZONEMD(st) && !strings.EqualFold(m.cfg.Verification.ZONEMD, "on") {
		return false
	}
	z.mu.RLock()
	defer z.mu.RUnlock()
	if z.ZONEMDCheckedAt.IsZero() {
		return storeHasZONEMD(st) || strings.EqualFold(m.cfg.Verification.ZONEMD, "on")
	}
	return time.Since(z.ZONEMDCheckedAt) > maxAge
}

func applyZONEMDResult(z *ZoneRuntime, st *zone.Store, vres *dnssec.Result) {
	if vres.ZONEMDChecked {
		ok := vres.ZONEMDOK
		z.ZONEMDOK = &ok
		z.ZONEMDCheckedAt = time.Now()
		z.ZONEMDStale = false
		return
	}
	// Incremental (or mode off / no ZONEMD): keep prior result, mark stale when the zone changed.
	if vres.Mode == "incremental" && (z.ZONEMDCheckedAt.IsZero() == false || storeHasZONEMD(st)) {
		z.ZONEMDStale = true
	}
}

func storeHasZONEMD(st *zone.Store) bool {
	if st == nil {
		return false
	}
	apex := st.Apex()
	return apex != nil && apex.Has(dns.TypeZONEMD)
}

func serialGreater(a, b uint32) bool {
	return int32(a-b) > 0
}

func (m *Manager) Client() *xfr.Client        { return m.client }
func (m *Manager) Verifier() *dnssec.Verifier { return m.verifier }
