package dnssec

import (
	"fmt"
	"slices"

	"github.com/davidgroves/dnssec-auditor/internal/dnsname"
	"github.com/davidgroves/dnssec-auditor/internal/zone"
	"github.com/miekg/dns"
)

func (v *Verifier) checkNSECPresence(st *zone.Store, n *zone.Node, findings *Set) {
	if n.Has(dns.TypeNSEC3) {
		return
	}
	// Glue (below a cut) must not have NSEC.
	if !v.isAuthoritative(st, n) {
		return
	}
	// Empty-nonterminal / authoritative names / secure delegations / apex need NSEC.
	if n.IsDelegation && !n.HasDS {
		// insecure delegation still has NSEC (opt-out is NSEC3-only)
	}
	if !n.Has(dns.TypeNSEC) {
		findings.Add(NewFinding(NSECMissing, Error, n.Name, dns.TypeNSEC, "missing NSEC"))
		return
	}
	rrs, err := n.UnpackType(dns.TypeNSEC)
	if err != nil || len(rrs) == 0 {
		findings.Add(NewFinding(NSECMissing, Error, n.Name, dns.TypeNSEC, "unreadable NSEC"))
		return
	}
	nsec, ok := rrs[0].(*dns.NSEC)
	if !ok {
		return
	}
	want := zone.ExpectedBitmap(n, false)
	if !bitmapEqual(want, nsec.TypeBitMap) {
		findings.Add(NewFinding(NSECBitmapMismatch, Error, n.Name, dns.TypeNSEC, fmt.Sprintf("bitmap have=%v want=%v", nsec.TypeBitMap, want)))
	}
}

func (v *Verifier) verifyNSECChain(st *zone.Store, res *Result) {
	names := make([]string, 0)
	st.ForEachNode(func(n *zone.Node) bool {
		if n.Has(dns.TypeNSEC) {
			names = append(names, n.Name)
		}
		return true
	})
	slices.SortFunc(names, zone.CanonicalCmp)
	if len(names) == 0 {
		return
	}
	for i, name := range names {
		n := st.Lookup(name)
		rrs, err := n.UnpackType(dns.TypeNSEC)
		if err != nil || len(rrs) == 0 {
			continue
		}
		nsec, ok := rrs[0].(*dns.NSEC)
		if !ok {
			continue
		}
		next := names[(i+1)%len(names)]
		if dnsname.Canonical(nsec.NextDomain) != next {
			res.Findings.Add(NewFinding(NSECChainBroken, Error, name, dns.TypeNSEC, fmt.Sprintf("next=%s want=%s", nsec.NextDomain, next)))
		}
	}
}

func (v *Verifier) checkNSEC3Presence(st *zone.Store, n *zone.Node, p *dns.NSEC3PARAM, findings *Set) {
	if n.Name == st.Origin() && n.Has(dns.TypeNSEC3PARAM) {
		// apex is covered by the hash of the origin
	}
	if isNSEC3Owner(n.Name, st.Origin()) {
		return
	}
	if !v.needsNSEC3(st, n) {
		return
	}
	hash := zone.HashName(n.Name, p.Hash, p.Iterations, saltOf(p))
	rec := st.NSEC3ByHash(string(hash))
	if rec == nil {
		cover := st.CoveringNSEC3(string(hash))
		if n.IsDelegation && !n.HasDS {
			// opt-out: insecure delegation may be covered by an opt-out span
			if cover != nil && cover.Flags&1 == 1 {
				return
			}
			// still missing but not a hard requirement if the covering NSEC3 has opt-out
		}
		if n.IsDelegation && n.HasDS {
			findings.Add(NewFinding(NSEC3OptOutViolation, Error, n.Name, dns.TypeNSEC3, "secure delegation has no NSEC3"))
			return
		}
		findings.Add(NewFinding(NSEC3Missing, Error, n.Name, dns.TypeNSEC3, "missing NSEC3"))
		return
	}
	want := zone.ExpectedBitmap(n, true)
	if !bitmapEqual(want, rec.TypeBitMap) {
		findings.Add(NewFinding(NSEC3BitmapMismatch, Error, n.Name, dns.TypeNSEC3, fmt.Sprintf("bitmap have=%v want=%v", rec.TypeBitMap, want)))
	}
}

func (v *Verifier) needsNSEC3(st *zone.Store, n *zone.Node) bool {
	if n.Name == st.Origin() {
		return true
	}
	if !v.isAuthoritative(st, n) {
		return false
	}
	if n.IsDelegation && !n.HasDS {
		return false // opt-out candidate
	}
	return true
}

func (v *Verifier) verifyNSEC3Chain(st *zone.Store, p *dns.NSEC3PARAM, res *Result) {
	var hashes []string
	mismatch := false
	st.ForEachNSEC3(func(rec *zone.NSEC3Rec) bool {
		hashes = append(hashes, rec.Hash)
		if rec.Iterations != p.Iterations {
			mismatch = true
		}
		return true
	})
	if mismatch {
		res.Findings.Add(NewFinding(NSEC3PARAMMismatch, Error, st.Origin(), dns.TypeNSEC3PARAM, "NSEC3 iterations/salt do not match NSEC3PARAM"))
	}
	if len(hashes) == 0 {
		return
	}
	slices.Sort(hashes)
	for i, h := range hashes {
		rec := st.NSEC3ByHash(h)
		if rec == nil {
			continue
		}
		wantNext := hashes[(i+1)%len(hashes)]
		if rec.Next != wantNext {
			res.Findings.Add(NewFinding(NSEC3ChainBroken, Error, rec.Owner, dns.TypeNSEC3, "NSEC3 next hash does not match successor"))
		}
	}
}

func saltOf(p *dns.NSEC3PARAM) []byte {
	if p == nil || p.Salt == "" || p.Salt == "-" {
		return nil
	}
	b := make([]byte, len(p.Salt)/2)
	for i := 0; i < len(b); i++ {
		var v byte
		fmt.Sscanf(p.Salt[i*2:i*2+2], "%02x", &v)
		b[i] = v
	}
	return b
}

func bitmapEqual(a, b []uint16) bool {
	aa := append([]uint16(nil), a...)
	bb := append([]uint16(nil), b...)
	slices.Sort(aa)
	slices.Sort(bb)
	aa = slices.Compact(aa)
	bb = slices.Compact(bb)
	return slices.Equal(aa, bb)
}
