package monitor

import (
	"math/rand"
	"sync"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/dnssec"
	"github.com/davidgroves/dnssec-auditor/internal/zone"
)

type State string

const (
	StateUnknown        State = "unknown"
	StateTransferring   State = "transferring"
	StateVerifying      State = "verifying"
	StateValid          State = "valid"
	StateInvalid        State = "invalid"
	StateUnsigned       State = "unsigned"
	StateTransferFailed State = "transfer_failed"
	StateStale          State = "stale"
)

type ServerStatus struct {
	Name      string        `json:"name"`
	Serial    uint32        `json:"serial"`
	Reachable bool          `json:"reachable"`
	RTT       time.Duration `json:"rtt_ns"`
	Error     string        `json:"error,omitempty"`
	At        time.Time     `json:"at"`
}

type HistoryEntry struct {
	At     time.Time `json:"at"`
	State  State     `json:"state"`
	Serial uint32    `json:"serial"`
	Mode   string    `json:"mode,omitempty"`
	Method string    `json:"method,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

type ZoneRuntime struct {
	mu sync.RWMutex

	Name    string
	Source  string // config | catalog:<name>
	Servers []config.Server
	TSIGKey string

	State            State
	Store            *zone.Store
	Findings         *dnssec.Set
	LastValidAt      time.Time
	LastVerified     time.Time
	LastFullVerified time.Time
	LastTransfer     time.Time
	NextRefresh      time.Time
	ExpireAt         time.Time
	VerifyMode       string
	LastMethod       string
	ServersStat      []ServerStatus
	History          []HistoryEntry
	Refreshing       bool
	RefreshFull      bool
	ChainOK          *bool
	ZONEMDOK         *bool
	ZONEMDCheckedAt  time.Time
	ZONEMDStale      bool
	SkewSince        time.Time
}

func NewZone(name, source string, servers []config.Server, tsig string) *ZoneRuntime {
	return &ZoneRuntime{
		Name:     name,
		Source:   source,
		Servers:  servers,
		TSIGKey:  tsig,
		State:    StateUnknown,
		Findings: dnssec.NewSet(),
	}
}

func (z *ZoneRuntime) Snapshot() ZoneView {
	z.mu.RLock()
	defer z.mu.RUnlock()
	v := ZoneView{
		Name:         z.Name,
		Source:       z.Source,
		State:        string(z.State),
		Valid:        z.State == StateValid || z.State == StateUnsigned,
		Unsigned:     z.State == StateUnsigned,
		LastValidAt:  z.LastValidAt,
		LastVerified: z.LastVerified,
		LastTransfer: z.LastTransfer,
		NextRefresh:  z.NextRefresh,
		VerifyMode:   z.VerifyMode,
		LastMethod:   z.LastMethod,
		Refreshing:   z.Refreshing,
		RefreshFull:  z.RefreshFull,
		Servers:      append([]ServerStatus(nil), z.ServersStat...),
		Findings:     z.Findings.List(),
		ErrorCount:   z.Findings.CountBySeverity(dnssec.Error),
		WarningCount: z.Findings.CountBySeverity(dnssec.Warning),
		History:      append([]HistoryEntry(nil), z.History...),
		ZONEMDStale:  z.ZONEMDStale,
	}
	if !z.LastFullVerified.IsZero() {
		t := z.LastFullVerified
		v.LastFullVerified = &t
	}
	if z.Store != nil {
		v.Serial = z.Store.Serial()
		v.Records = z.Store.RecordCount()
		v.RRSIGs = z.Store.RRSIGCount()
		v.NSEC3 = z.Store.NSEC3Count()
		if z.State == StateUnsigned {
			v.Signing = zone.SigningUnsigned
		} else {
			v.Signing = z.Store.SigningMode()
		}
		if soa := z.Store.SOA(); soa != nil {
			v.SOA = &SOAInfo{
				MName:   soa.Ns,
				RName:   soa.Mbox,
				Serial:  soa.Serial,
				Refresh: soa.Refresh,
				Retry:   soa.Retry,
				Expire:  soa.Expire,
				Minimum: soa.Minttl,
			}
		}
	} else {
		v.Signing = zone.SigningUnsigned
	}
	if z.ChainOK != nil {
		v.ChainOK = z.ChainOK
	}
	if z.ZONEMDOK != nil {
		v.ZONEMDOK = z.ZONEMDOK
	}
	if !z.ZONEMDCheckedAt.IsZero() {
		t := z.ZONEMDCheckedAt
		v.ZONEMDCheckedAt = &t
	}
	return v
}

type ZoneView struct {
	Name             string           `json:"name"`
	Source           string           `json:"source"`
	State            string           `json:"state"`
	Valid            bool             `json:"valid"`
	Unsigned         bool             `json:"unsigned"`
	Serial           uint32           `json:"serial"`
	Records          int              `json:"records"`
	RRSIGs           int              `json:"rrsigs"`
	NSEC3            int              `json:"nsec3"`
	Signing          string           `json:"signing"`
	LastValidAt      time.Time        `json:"last_valid_at"`
	LastVerified     time.Time        `json:"last_verified"`
	LastFullVerified *time.Time       `json:"last_full_verified_at,omitempty"`
	LastTransfer     time.Time        `json:"last_transfer"`
	NextRefresh      time.Time        `json:"next_refresh"`
	VerifyMode       string           `json:"verify_mode"`
	LastMethod       string           `json:"last_method"`
	Refreshing       bool             `json:"refreshing"`
	RefreshFull      bool             `json:"refresh_full"`
	ErrorCount       int              `json:"error_count"`
	WarningCount     int              `json:"warning_count"`
	Findings         []dnssec.Finding `json:"findings,omitempty"`
	Servers          []ServerStatus   `json:"servers,omitempty"`
	History          []HistoryEntry   `json:"history,omitempty"`
	SOA              *SOAInfo         `json:"soa,omitempty"`
	ChainOK          *bool            `json:"chain_of_trust_ok,omitempty"`
	ZONEMDOK         *bool            `json:"zonemd_ok,omitempty"`
	ZONEMDCheckedAt  *time.Time       `json:"zonemd_checked_at,omitempty"`
	ZONEMDStale      bool             `json:"zonemd_stale"`
}

type SOAInfo struct {
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

// SetState records a state transition (exported for chain-of-trust etc).
func (z *ZoneRuntime) SetState(s State, serial uint32, mode, method, detail string) {
	z.setState(s, serial, mode, method, detail)
}

func (z *ZoneRuntime) setState(s State, serial uint32, mode, method, detail string) {
	z.State = s
	if s == StateValid || s == StateUnsigned {
		z.LastValidAt = time.Now()
	}
	z.History = append(z.History, HistoryEntry{At: time.Now(), State: s, Serial: serial, Mode: mode, Method: method, Detail: detail})
	if len(z.History) > 64 {
		z.History = z.History[len(z.History)-64:]
	}
}

func (z *ZoneRuntime) schedule(cfg config.RefreshConfig, soaRefresh, soaRetry uint32, failed bool) {
	var base time.Duration
	if failed {
		base = time.Duration(soaRetry) * time.Second
		if base < cfg.RetryMin.Duration() {
			base = cfg.RetryMin.Duration()
		}
		if base > cfg.RetryMax.Duration() {
			base = cfg.RetryMax.Duration()
		}
	} else {
		if soaRefresh == 0 {
			base = cfg.MaxInterval.Duration()
		} else {
			base = time.Duration(soaRefresh) * time.Second
		}
		if base < cfg.MinInterval.Duration() {
			base = cfg.MinInterval.Duration()
		}
		if base > cfg.MaxInterval.Duration() {
			base = cfg.MaxInterval.Duration()
		}
	}
	j := cfg.Jitter
	if j < 0 {
		j = 0
	}
	if j > 1 {
		j = 1
	}
	mult := 1.0 - j + rand.Float64()*j
	z.NextRefresh = time.Now().Add(time.Duration(float64(base) * mult))
}

func (z *ZoneRuntime) TryLockRefresh(full bool) bool {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.Refreshing {
		return false
	}
	z.Refreshing = true
	z.RefreshFull = full
	return true
}

func (z *ZoneRuntime) UnlockRefresh() {
	z.mu.Lock()
	z.Refreshing = false
	z.RefreshFull = false
	z.mu.Unlock()
}

func isTerminalState(s State) bool {
	switch s {
	case StateValid, StateInvalid, StateUnsigned, StateTransferFailed, StateStale:
		return true
	default:
		return false
	}
}

// lastTerminalState is the last valid/invalid/unsigned (etc) state.
// Caller must hold z.mu.
func (z *ZoneRuntime) lastTerminalState() State {
	if isTerminalState(z.State) {
		return z.State
	}
	for i := len(z.History) - 1; i >= 0; i-- {
		if isTerminalState(z.History[i].State) {
			return z.History[i].State
		}
	}
	return StateUnknown
}

// Restore persists last_valid_at and findings from a previous process.
func (z *ZoneRuntime) Restore(lastValid time.Time, findings []dnssec.Finding) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if !lastValid.IsZero() {
		z.LastValidAt = lastValid
	}
	if z.Findings == nil {
		z.Findings = dnssec.NewSet()
	}
	for _, f := range findings {
		z.Findings.Add(f)
	}
}

// AttachStore replaces the in-memory store (used for snapshot resume).
func (z *ZoneRuntime) AttachStore(st *zone.Store) {
	z.mu.Lock()
	z.Store = st
	z.mu.Unlock()
}

// StoreAndFindings returns the current store and a copy of open findings.
func (z *ZoneRuntime) StoreAndFindings() (*zone.Store, []dnssec.Finding) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	var findings []dnssec.Finding
	if z.Findings != nil {
		findings = z.Findings.List()
	}
	return z.Store, findings
}

// StoreAndChain returns the current store pointer and chain-of-trust flag.
func (z *ZoneRuntime) StoreAndChain() (*zone.Store, *bool) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.Store, z.ChainOK
}

// ApplyFindings adds findings and optionally records chain-of-trust status.
func (z *ZoneRuntime) ApplyFindings(findings []dnssec.Finding, chainOK *bool, invalidate bool) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.Findings == nil {
		z.Findings = dnssec.NewSet()
	}
	for _, f := range findings {
		z.Findings.Add(f)
	}
	if chainOK != nil {
		z.ChainOK = chainOK
	}
	if invalidate && z.State == StateValid {
		serial := uint32(0)
		if z.Store != nil {
			serial = z.Store.Serial()
		}
		z.setState(StateInvalid, serial, "chain", "", "DS mismatch")
	}
}
