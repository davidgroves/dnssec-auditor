package dnssec

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/dnsname"
	"github.com/miekg/dns"
)

type Severity string

const (
	Error   Severity = "error"
	Warning Severity = "warning"
)

const (
	RRSIGMissing           = "RRSIG_MISSING"
	RRSIGInvalid           = "RRSIG_INVALID"
	RRSIGExpired           = "RRSIG_EXPIRED"
	RRSIGNotYetValid       = "RRSIG_NOT_YET_VALID"
	RRSIGUnknownKey        = "RRSIG_UNKNOWN_KEY"
	RRSIGLabelsMismatch    = "RRSIG_LABELS_MISMATCH"
	DNSKEYNotSignedByKSK   = "DNSKEY_NOT_SIGNED_BY_KSK"
	NSECMissing            = "NSEC_MISSING"
	NSEC3Missing           = "NSEC3_MISSING"
	NSECBitmapMismatch     = "NSEC_BITMAP_MISMATCH"
	NSEC3BitmapMismatch    = "NSEC3_BITMAP_MISMATCH"
	NSECChainBroken        = "NSEC_CHAIN_BROKEN"
	NSEC3ChainBroken       = "NSEC3_CHAIN_BROKEN"
	NSEC3OptOutViolation   = "NSEC3_OPTOUT_VIOLATION"
	NSEC3PARAMMismatch     = "NSEC3PARAM_MISMATCH"
	KeytagCollisionLimit   = "KEYTAG_COLLISION_LIMIT"
	ZONEMDMismatch         = "ZONEMD_MISMATCH"
	ZONEMDMissing          = "ZONEMD_MISSING"
	DSMismatch             = "DS_MISMATCH"
	DSMissing              = "DS_MISSING"
	SOASerialMismatch      = "SOA_SERIAL_MISMATCH"
	IXFRApplyFailed        = "IXFR_APPLY_FAILED"
	NSEC3IterationsNonzero = "NSEC3_ITERATIONS_NONZERO"
	NSEC3SaltPresent       = "NSEC3_SALT_PRESENT"
	DeprecatedAlgorithm    = "DEPRECATED_ALGORITHM"
	RRSIGTTLMismatch       = "RRSIG_TTL_MISMATCH"
	RRSIGExpiringSoon      = "RRSIG_EXPIRING_SOON"
	DNSKEYUnused           = "DNSKEY_UNUSED"
	NSEC3OptOutZeroDeleg   = "NSEC3_OPTOUT_ON_ZERO_DELEGATIONS"
	SerialSkew             = "SERIAL_SKEW"
	ServerUnreachable      = "SERVER_UNREACHABLE"
	InsecureDelegation     = "INSECURE_DELEGATION"
)

// Finding is one verification issue.
type Finding struct {
	Code       string    `json:"code"`
	Severity   Severity  `json:"severity"`
	Owner      string    `json:"owner"`
	RRType     uint16    `json:"rrtype"`
	RRTypeName string    `json:"rrtype_name"`
	Message    string    `json:"message"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

func (f Finding) Key() string {
	return fmt.Sprintf("%s|%s|%d", f.Code, f.Owner, f.RRType)
}

func NewFinding(code string, sev Severity, owner string, rrtype uint16, msg string) Finding {
	now := time.Now()
	return Finding{
		Code:       code,
		Severity:   sev,
		Owner:      owner,
		RRType:     rrtype,
		RRTypeName: typeName(rrtype),
		Message:    msg,
		FirstSeen:  now,
		LastSeen:   now,
	}
}

// FormatFindingComment returns a master-file comment for a finding, e.g.
// "; NSEC3_MISSING ns1.example. NSEC3 — missing NSEC3".
func FormatFindingComment(f Finding) string {
	rr := f.RRTypeName
	if rr == "" {
		rr = typeName(f.RRType)
	}
	return fmt.Sprintf("; %s %s %s — %s", f.Code, f.Owner, rr, f.Message)
}

// ErrorCommentsByOwner groups error findings into master-file comment lines
// keyed by canonical owner name. Lines for each owner are sorted stably.
func ErrorCommentsByOwner(findings []Finding) map[string][]string {
	type item struct {
		owner string
		line  string
		key   string
	}
	var items []item
	for _, f := range findings {
		if f.Severity != Error {
			continue
		}
		owner := dnsname.Canonical(f.Owner)
		items = append(items, item{
			owner: owner,
			line:  FormatFindingComment(f),
			key:   f.Key(),
		})
	}
	slices.SortFunc(items, func(a, b item) int {
		if a.owner != b.owner {
			return strings.Compare(a.owner, b.owner)
		}
		return strings.Compare(a.key, b.key)
	})
	out := map[string][]string{}
	for _, it := range items {
		out[it.owner] = append(out[it.owner], it.line)
	}
	return out
}

func typeName(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}

// Set is a keyed collection of findings with merge semantics.
type Set struct {
	byKey map[string]Finding
}

func NewSet() *Set { return &Set{byKey: map[string]Finding{}} }

func (s *Set) Add(f Finding) {
	if s.byKey == nil {
		s.byKey = map[string]Finding{}
	}
	if old, ok := s.byKey[f.Key()]; ok {
		f.FirstSeen = old.FirstSeen
		if f.LastSeen.IsZero() {
			f.LastSeen = time.Now()
		}
	}
	s.byKey[f.Key()] = f
}

func (s *Set) List() []Finding {
	out := make([]Finding, 0, len(s.byKey))
	for _, f := range s.byKey {
		out = append(out, f)
	}
	return out
}

func (s *Set) HasErrors() bool {
	for _, f := range s.byKey {
		if f.Severity == Error {
			return true
		}
	}
	return false
}

func (s *Set) CountBySeverity(sev Severity) int {
	n := 0
	for _, f := range s.byKey {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

func (s *Set) Codes(sev Severity) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, f := range s.byKey {
		if sev != "" && f.Severity != sev {
			continue
		}
		if _, ok := seen[f.Code]; ok {
			continue
		}
		seen[f.Code] = struct{}{}
		out = append(out, f.Code)
	}
	return out
}

func (s *Set) Clone() *Set {
	out := NewSet()
	for k, v := range s.byKey {
		out.byKey[k] = v
	}
	return out
}

func (s *Set) Get(key string) (Finding, bool) {
	f, ok := s.byKey[key]
	return f, ok
}

func (s *Set) Delete(key string) {
	delete(s.byKey, key)
}

func (s *Set) Len() int { return len(s.byKey) }

// MergeReplace keeps first_seen from previous for matching keys, drops keys
// not in next that belong to the provided owner set (empty = all).
func MergeReplace(prev, next *Set, owners map[string]struct{}) (opened, closed int) {
	if prev == nil {
		prev = NewSet()
	}
	if next == nil {
		next = NewSet()
	}
	restrict := len(owners) > 0
	for k, f := range prev.byKey {
		if restrict {
			if _, ok := owners[f.Owner]; !ok {
				next.Add(f) // keep findings for untouched owners
				continue
			}
		}
		if _, ok := next.byKey[k]; !ok {
			closed++
		}
	}
	for k, f := range next.byKey {
		if old, ok := prev.byKey[k]; ok {
			f.FirstSeen = old.FirstSeen
			next.byKey[k] = f
		} else {
			opened++
		}
	}
	*prev = *next
	return opened, closed
}
