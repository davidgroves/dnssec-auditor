package dnssec

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/dnsname"
	"github.com/davidgroves/dnssec-auditor/internal/zone"
	"github.com/miekg/dns"
)

// Result is the outcome of a verification pass.
type Result struct {
	Findings       *Set
	Mode           string
	Valid          bool
	Unsigned       bool
	RRSIGsVerified int
	NSEC3Checked   int
	ZONEMDChecked  bool
	ZONEMDOK       bool
	Duration       time.Duration
	EarliestExpiry uint32
}

// Verifier runs full and incremental DNSSEC checks.
type Verifier struct {
	cfg config.VerificationConfig
	now func() time.Time
}

func New(cfg config.VerificationConfig) *Verifier {
	return &Verifier{cfg: cfg, now: time.Now}
}

func (v *Verifier) WithNow(now func() time.Time) *Verifier {
	v.now = now
	return v
}

func (v *Verifier) workers() int {
	if v.cfg.Workers > 0 {
		return v.cfg.Workers
	}
	n := runtime.GOMAXPROCS(0)
	if n < 1 {
		n = 1
	}
	return n
}

func (v *Verifier) clock() time.Time { return v.now() }

// Full verifies the entire zone.
func (v *Verifier) Full(st *zone.Store) *Result {
	start := time.Now()
	res := &Result{Findings: NewSet(), Mode: "full"}
	apex := st.Apex()
	if apex == nil || !apex.Has(dns.TypeSOA) {
		res.Findings.Add(NewFinding(SOASerialMismatch, Error, st.Origin(), dns.TypeSOA, "zone has no SOA"))
		res.Duration = time.Since(start)
		return res
	}
	keys, err := st.DNSKEYs()
	if err != nil || len(keys) == 0 {
		res.Unsigned = true
		res.Valid = true
		res.Duration = time.Since(start)
		return res
	}
	cached, err := cacheKeys(keys)
	if err != nil {
		res.Findings.Add(NewFinding(RRSIGInvalid, Error, st.Origin(), dns.TypeDNSKEY, err.Error()))
		res.Duration = time.Since(start)
		return res
	}
	v.checkKeytagCollisions(st.Origin(), cached, res.Findings)
	v.checkDNSKEYSignedByKSK(st, cached, res)

	nodes := collectNodes(st)
	var verified atomic.Int64
	var nsec3checked atomic.Int64
	var mu sync.Mutex
	jobs := make(chan *zone.Node, len(nodes))
	for _, n := range nodes {
		jobs <- n
	}
	close(jobs)
	var wg sync.WaitGroup
	workers := v.workers()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := NewSet()
			var locNSEC3 int
			for n := range jobs {
				c := v.verifyNode(st, n, cached, local)
				verified.Add(int64(c))
				if st.NSEC3PARAM() != nil && !isNSEC3Owner(n.Name, st.Origin()) {
					locNSEC3++
				}
			}
			nsec3checked.Add(int64(locNSEC3))
			mu.Lock()
			for _, f := range local.List() {
				res.Findings.Add(f)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	res.RRSIGsVerified = int(verified.Load())
	res.NSEC3Checked = int(nsec3checked.Load())

	if p := st.NSEC3PARAM(); p != nil {
		v.verifyNSEC3Chain(st, p, res)
	} else {
		v.verifyNSECChain(st, res)
	}
	v.verifyZONEMD(st, res)
	if v.cfg.Hygiene.Enabled {
		v.hygiene(st, cached, res)
	}
	res.EarliestExpiry = st.EarliestExpiry()
	res.Valid = !res.Findings.HasErrors()
	res.Duration = time.Since(start)
	return res
}

func collectNodes(st *zone.Store) []*zone.Node {
	var nodes []*zone.Node
	st.ForEachNode(func(n *zone.Node) bool {
		nodes = append(nodes, n)
		return true
	})
	return nodes
}

func (v *Verifier) verifyNode(st *zone.Store, n *zone.Node, keys []CachedKey, findings *Set) int {
	checked := 0
	origin := st.Origin()
	// Glue at or under a delegation cut is not authoritative (except DS/NSEC/NSEC3/RRSIG at the cut).
	authoritative := v.isAuthoritative(st, n)
	if authoritative {
		for _, set := range n.Sets {
			if set.Type == dns.TypeRRSIG {
				continue
			}
			if set.Type == dns.TypeNSEC3 {
				continue
			}
			c := v.verifyRRSet(n, set, keys, findings)
			checked += c
		}
	}
	// Denial of existence
	if p := st.NSEC3PARAM(); p != nil {
		v.checkNSEC3Presence(st, n, p, findings)
	} else if !isNSEC3Owner(n.Name, origin) {
		v.checkNSECPresence(st, n, findings)
	}
	return checked
}

func (v *Verifier) isAuthoritative(st *zone.Store, n *zone.Node) bool {
	origin := st.Origin()
	if n.Name == origin {
		return true
	}
	// Walk parents: if a parent (not this name) is a delegation, we are glue
	// unless we *are* the delegation name (NS/DS/NSEC(3)/RRSIG are authoritative at the cut).
	parent := dnsname.Parent(n.Name)
	for parent != origin && parent != "." && parent != n.Name {
		if p := st.Lookup(parent); p != nil && p.IsDelegation {
			return false
		}
		next := dnsname.Parent(parent)
		if next == parent {
			break
		}
		parent = next
	}
	return true
}

func (v *Verifier) verifyRRSet(n *zone.Node, set zone.RRSet, keys []CachedKey, findings *Set) int {
	sigs := n.RRSIGsCovering(set.Type)
	if len(sigs) == 0 {
		// Delegations: NS at the cut is not signed (DS or NSEC3 opt-out covers it).
		if n.IsDelegation && set.Type == dns.TypeNS {
			return 0
		}
		if n.IsDelegation && set.Type != dns.TypeDS && set.Type != dns.TypeNSEC && set.Type != dns.TypeNSEC3 {
			return 0
		}
		findings.Add(NewFinding(RRSIGMissing, Error, n.Name, set.Type, fmt.Sprintf("no RRSIG covering %s", typeName(set.Type))))
		return 0
	}
	rrs, err := set.Unpack(n.Name)
	if err != nil {
		findings.Add(NewFinding(RRSIGInvalid, Error, n.Name, set.Type, err.Error()))
		return 0
	}
	now := uint32(v.clock().Unix())
	skew := uint32(v.cfg.ClockSkew.Duration().Seconds())
	ok := false
	checked := 0
	unknown := 0
	for _, sig := range sigs {
		wantLabels := dns.CountLabel(n.Name)
		if isWildcardOwner(n.Name) && wantLabels > 0 {
			wantLabels-- // RFC 4035: labels excludes the leftmost * label
		}
		if int(sig.Labels) != wantLabels {
			findings.Add(NewFinding(RRSIGLabelsMismatch, Error, n.Name, set.Type, fmt.Sprintf("RRSIG labels=%d name labels=%d", sig.Labels, dns.CountLabel(n.Name))))
		}
		if now+skew < sig.Inception {
			findings.Add(NewFinding(RRSIGNotYetValid, Error, n.Name, set.Type, fmt.Sprintf("inception %d", sig.Inception)))
			continue
		}
		if now > sig.Expiration+skew {
			findings.Add(NewFinding(RRSIGExpired, Error, n.Name, set.Type, fmt.Sprintf("expiration %d", sig.Expiration)))
			continue
		}
		if v.cfg.Hygiene.Enabled && v.cfg.Hygiene.WarnRRSIGTTLMismatch && sig.OrigTTL != set.TTL {
			findings.Add(NewFinding(RRSIGTTLMismatch, Warning, n.Name, set.Type, fmt.Sprintf("origTTL %d != TTL %d", sig.OrigTTL, set.TTL)))
		}
		warn := uint32(v.cfg.ExpiryWarning.Duration().Seconds())
		if warn > 0 && sig.Expiration > now && sig.Expiration-now <= warn {
			findings.Add(NewFinding(RRSIGExpiringSoon, Warning, n.Name, set.Type, fmt.Sprintf("expires in %ds", sig.Expiration-now)))
		}
		matched := false
		for i := range keys {
			k := &keys[i]
			if k.KeyTag != sig.KeyTag || k.Alg != sig.Algorithm || !k.IsZone {
				continue
			}
			checked++
			rrsig := zone.RRSIGFromCompact(n.Name, set.TTL, sig)
			if err := rrsig.Verify(k.RR, rrs); err != nil {
				continue
			}
			k.Used = true
			matched = true
			ok = true
			break
		}
		if !matched {
			unknown++
		}
	}
	if !ok {
		if unknown == len(sigs) && checked == 0 {
			findings.Add(NewFinding(RRSIGUnknownKey, Error, n.Name, set.Type, "no matching DNSKEY for RRSIG"))
		} else {
			findings.Add(NewFinding(RRSIGInvalid, Error, n.Name, set.Type, "no RRSIG verified"))
		}
	}
	return checked
}

func isWildcardOwner(name string) bool {
	return len(name) > 2 && name[0] == '*' && name[1] == '.'
}

func (v *Verifier) checkKeytagCollisions(origin string, keys []CachedKey, findings *Set) {
	byTag := map[uint16]int{}
	for _, k := range keys {
		byTag[k.KeyTag]++
	}
	for tag, n := range byTag {
		if n > 3 {
			findings.Add(NewFinding(KeytagCollisionLimit, Error, origin, dns.TypeDNSKEY, fmt.Sprintf("keytag %d has %d keys", tag, n)))
		}
	}
}

func (v *Verifier) checkDNSKEYSignedByKSK(st *zone.Store, keys []CachedKey, res *Result) {
	apex := st.Apex()
	if apex == nil {
		return
	}
	set := apex.Set(dns.TypeDNSKEY)
	if set == nil {
		return
	}
	rrs, err := set.Unpack(apex.Name)
	if err != nil {
		return
	}
	sigs := apex.RRSIGsCovering(dns.TypeDNSKEY)
	ok := false
	for _, sig := range sigs {
		for i := range keys {
			k := &keys[i]
			if !k.IsKSK || k.KeyTag != sig.KeyTag {
				continue
			}
			rrsig := zone.RRSIGFromCompact(apex.Name, set.TTL, sig)
			if err := rrsig.Verify(k.RR, rrs); err == nil {
				ok = true
				k.Used = true
			}
		}
	}
	if !ok {
		res.Findings.Add(NewFinding(DNSKEYNotSignedByKSK, Error, apex.Name, dns.TypeDNSKEY, "DNSKEY RRset is not signed by a KSK"))
	}
}

func isNSEC3Owner(name, origin string) bool {
	// NSEC3 owners are <base32hash>.<origin>
	if name == origin {
		return false
	}
	// hashed owner: single extra label that is base32hex
	if !dnsname.IsSubdomain(name, origin) {
		return false
	}
	// parent of name should be origin
	return dnsname.Parent(name) == origin && !hasTypicalName(name)
}

func hasTypicalName(name string) bool {
	// crude: NSEC3 labels are 32 chars of base32hex for SHA-1
	lab := name
	if i := len(name); i > 0 {
		if dot := indexByte(name, '.'); dot > 0 {
			lab = name[:dot]
		}
	}
	if len(lab) < 20 {
		return true
	}
	for _, c := range lab {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'v') || (c >= 'A' && c <= 'V')) {
			return true
		}
	}
	return false
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
