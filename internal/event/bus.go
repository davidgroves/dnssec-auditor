package event

import (
	"sync"
	"time"
)

// Type is a stable event name shared by the API SSE stream, webhooks, and logs.
type Type string

const (
	ZoneStateChanged      Type = "zone_state_changed"
	ZoneValid             Type = "zone_valid"
	ZoneInvalid           Type = "zone_invalid"
	ZoneStale             Type = "zone_stale"
	ZoneExpiringSoon      Type = "zone_expiring_soon"
	TransferCompleted     Type = "transfer_completed"
	TransferFailed        Type = "transfer_failed"
	VerificationCompleted Type = "verification_completed"
	NotifyReceived        Type = "notify_received"
	SerialSkew            Type = "serial_skew"
	ChainOfTrustFailed    Type = "chain_of_trust_failed"
	CatalogMemberAdded    Type = "catalog_member_added"
	CatalogMemberRemoved  Type = "catalog_member_removed"
)

// Event is a bus payload.
type Event struct {
	Type      Type           `json:"type"`
	Zone      string         `json:"zone,omitempty"`
	At        time.Time      `json:"at"`
	State     string         `json:"state,omitempty"`
	Method    string         `json:"method,omitempty"`
	Mode      string         `json:"mode,omitempty"`
	Result    string         `json:"result,omitempty"`
	Transport string         `json:"transport,omitempty"`
	Catalog   string         `json:"catalog,omitempty"`
	Detail    map[string]any `json:"detail,omitempty"`
}

// Handler receives events. Handlers must not block.
type Handler func(Event)

// Bus is a process-wide pub/sub.
type Bus struct {
	mu       sync.RWMutex
	handlers []Handler
	buffer   int
}

func New(buffer int) *Bus {
	if buffer <= 0 {
		buffer = 256
	}
	return &Bus{buffer: buffer}
}

func (b *Bus) Subscribe(h Handler) {
	b.mu.Lock()
	b.handlers = append(b.handlers, h)
	b.mu.Unlock()
}

func (b *Bus) Publish(e Event) {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	b.mu.RLock()
	hs := append([]Handler(nil), b.handlers...)
	b.mu.RUnlock()
	for _, h := range hs {
		h(e)
	}
}
