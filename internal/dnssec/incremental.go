package dnssec

import (
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/zone"
	"github.com/miekg/dns"
)

// Incremental re-verifies only the names and NSEC3 records in touched.
// DNSKEY or NSEC3PARAM changes escalate to Full.
func (v *Verifier) Incremental(st *zone.Store, prev *Set, touched *zone.Touched) *Result {
	if touched != nil && (touched.DNSKEY || touched.NSEC3PARAM) {
		res := v.Full(st)
		res.Mode = "full"
		return res
	}
	start := time.Now()
	res := &Result{Findings: NewSet(), Mode: "incremental"}
	keys, err := st.DNSKEYs()
	if err != nil || len(keys) == 0 {
		res.Unsigned = true
		res.Valid = true
		res.Duration = time.Since(start)
		if prev != nil {
			opened, closed := MergeReplace(prev, res.Findings, nil)
			res.Findings = prev
			_ = opened
			_ = closed
		}
		return res
	}
	cached, err := cacheKeys(keys)
	if err != nil {
		res.Findings.Add(NewFinding(RRSIGInvalid, Error, st.Origin(), dns.TypeDNSKEY, err.Error()))
		res.Duration = time.Since(start)
		return res
	}
	if touched == nil {
		res = v.Full(st)
		return res
	}
	for name := range touched.Names {
		n := st.Lookup(name)
		if n == nil {
			// name deleted: NSEC/NSEC3 neighbours are in touched.NSEC3 / nearby names
			continue
		}
		c := v.verifyNode(st, n, cached, res.Findings)
		res.RRSIGsVerified += c
	}
	if st.NSEC3PARAM() != nil {
		for h := range touched.NSEC3 {
			rec := st.NSEC3ByHash(h)
			if rec == nil {
				res.Findings.Add(NewFinding(NSEC3ChainBroken, Error, st.Origin(), dns.TypeNSEC3, "touched NSEC3 missing"))
				continue
			}
			res.NSEC3Checked++
			next := st.NextNSEC3(h)
			if next == nil || rec.Next != next.Hash {
				res.Findings.Add(NewFinding(NSEC3ChainBroken, Error, rec.Owner, dns.TypeNSEC3, "NSEC3 next pointer broken"))
			}
			pred := st.PredNSEC3(h)
			if pred != nil && pred.Next != rec.Hash {
				res.Findings.Add(NewFinding(NSEC3ChainBroken, Error, pred.Owner, dns.TypeNSEC3, "predecessor next pointer broken"))
			}
			// verify RRSIG on the NSEC3 owner
			if n := st.Lookup(rec.Owner); n != nil {
				if set := n.Set(dns.TypeNSEC3); set != nil {
					res.RRSIGsVerified += v.verifyRRSet(n, *set, cached, res.Findings)
				}
			}
		}
	}
	// ZONEMD digests the whole zone (O(records)). Skip on incremental passes;
	// the monitor rechecks on full verify or when zonemd_max_age is exceeded.
	if v.cfg.Hygiene.Enabled {
		v.hygiene(st, cached, res)
	}
	owners := map[string]struct{}{}
	for n := range touched.Names {
		owners[n] = struct{}{}
	}
	for h := range touched.NSEC3 {
		if rec := st.NSEC3ByHash(h); rec != nil {
			owners[rec.Owner] = struct{}{}
		}
	}
	if prev != nil {
		opened, closed := MergeReplace(prev, res.Findings, owners)
		res.Findings = prev
		_ = opened
		_ = closed
	}
	res.EarliestExpiry = st.EarliestExpiry()
	res.Valid = !res.Findings.HasErrors()
	res.Duration = time.Since(start)
	return res
}

// SweepExpiry adds RRSIG_EXPIRED / RRSIG_EXPIRING_SOON for signatures in the index.
func (v *Verifier) SweepExpiry(st *zone.Store, findings *Set) (opened int) {
	now := uint32(v.clock().Unix())
	skew := uint32(v.cfg.ClockSkew.Duration().Seconds())
	warn := uint32(v.cfg.ExpiryWarning.Duration().Seconds())
	before := findings.Len()
	st.ExpiringBefore(now+skew+warn, func(rec zone.ExpiryRec) bool {
		if rec.Expiration+skew < now {
			findings.Add(NewFinding(RRSIGExpired, Error, rec.Owner, rec.TypeCovered, "RRSIG expired"))
		} else if rec.Expiration > now && rec.Expiration-now <= warn {
			findings.Add(NewFinding(RRSIGExpiringSoon, Warning, rec.Owner, rec.TypeCovered, "RRSIG expiring soon"))
		}
		return true
	})
	return findings.Len() - before
}
