package dnssec

import (
	"fmt"
	"strings"

	"github.com/davidgroves/dnssec-auditor/internal/zone"
	"github.com/miekg/dns"
)

func (v *Verifier) hygiene(st *zone.Store, keys []CachedKey, res *Result) {
	h := v.cfg.Hygiene
	if p := st.NSEC3PARAM(); p != nil {
		if int(p.Iterations) > h.NSEC3MaxIterations {
			res.Findings.Add(NewFinding(NSEC3IterationsNonzero, Warning, st.Origin(), dns.TypeNSEC3PARAM, fmt.Sprintf("NSEC3 iterations=%d (RFC 9276 recommends 0)", p.Iterations)))
		}
		if h.WarnNSEC3Salt && p.Salt != "" && p.Salt != "-" {
			res.Findings.Add(NewFinding(NSEC3SaltPresent, Warning, st.Origin(), dns.TypeNSEC3PARAM, "NSEC3 salt present (RFC 9276 recommends empty)"))
		}
		optout := false
		deleg := 0
		st.ForEachNSEC3(func(rec *zone.NSEC3Rec) bool {
			if rec.Flags&1 == 1 {
				optout = true
			}
			return true
		})
		st.ForEachNode(func(n *zone.Node) bool {
			if n.IsDelegation {
				deleg++
			}
			return true
		})
		if optout && deleg == 0 {
			res.Findings.Add(NewFinding(NSEC3OptOutZeroDeleg, Warning, st.Origin(), dns.TypeNSEC3PARAM, "NSEC3 opt-out with no delegations"))
		}
	}
	deprecated := map[string]struct{}{}
	for _, a := range h.DeprecatedAlgorithms {
		deprecated[strings.ToUpper(a)] = struct{}{}
	}
	for _, k := range keys {
		name := algName(k.Alg)
		if _, ok := deprecated[strings.ToUpper(name)]; ok {
			res.Findings.Add(NewFinding(DeprecatedAlgorithm, Warning, st.Origin(), dns.TypeDNSKEY, fmt.Sprintf("DNSKEY algorithm %s keytag %d", name, k.KeyTag)))
		}
	}
	// Unused zone-signing keys (not KSKs that only sign DNSKEY).
	for _, k := range keys {
		if k.IsZone && !k.IsKSK && !k.Used {
			res.Findings.Add(NewFinding(DNSKEYUnused, Warning, st.Origin(), dns.TypeDNSKEY, fmt.Sprintf("zone key %d signs nothing", k.KeyTag)))
		}
	}
}
