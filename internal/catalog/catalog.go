package catalog

import (
	"strings"

	"github.com/davidgroves/dnssec-auditor/internal/dnsname"
	"github.com/davidgroves/dnssec-auditor/internal/zone"
	"github.com/miekg/dns"
)

// Member is one catalog-zone member.
type Member struct {
	ID    string
	Zone  string
	Group string
	COO   string
}

// Parse extracts RFC 9432 members from a catalog zone store.
func Parse(st *zone.Store) (version string, members []Member, err error) {
	origin := st.Origin()
	verOwner := "version." + origin
	if n := st.Lookup(verOwner); n != nil {
		rrs, _ := n.UnpackType(dns.TypeTXT)
		for _, rr := range rrs {
			if t, ok := rr.(*dns.TXT); ok && len(t.Txt) > 0 {
				version = t.Txt[0]
			}
		}
	}
	suffix := ".zones." + origin
	byID := map[string]*Member{}
	st.ForEachNode(func(n *zone.Node) bool {
		name := n.Name
		if !strings.HasSuffix(name, suffix) && name != "zones."+origin {
			return true
		}
		if name == "zones."+origin {
			return true
		}
		rel := strings.TrimSuffix(name, suffix)
		// rel is either <id> or <property>.<id>
		parts := dns.SplitDomainName(rel + ".")
		if len(parts) == 0 {
			return true
		}
		id := parts[len(parts)-1]
		m := byID[id]
		if m == nil {
			m = &Member{ID: id}
			byID[id] = m
		}
		if len(parts) == 1 {
			rrs, _ := n.UnpackType(dns.TypePTR)
			for _, rr := range rrs {
				if p, ok := rr.(*dns.PTR); ok {
					m.Zone = dnsname.Canonical(p.Ptr)
				}
			}
			return true
		}
		prop := strings.ToLower(parts[0])
		if prop == "group" {
			rrs, _ := n.UnpackType(dns.TypeTXT)
			for _, rr := range rrs {
				if t, ok := rr.(*dns.TXT); ok && len(t.Txt) > 0 {
					m.Group = t.Txt[0]
				}
			}
		}
		if prop == "coo" {
			rrs, _ := n.UnpackType(dns.TypePTR)
			for _, rr := range rrs {
				if p, ok := rr.(*dns.PTR); ok {
					m.COO = dnsname.Canonical(p.Ptr)
				}
			}
		}
		return true
	})
	for _, m := range byID {
		if m.Zone != "" {
			members = append(members, *m)
		}
	}
	return version, members, nil
}

// Diff returns members added and removed versus previous.
func Diff(prev, next []Member) (added, removed []Member) {
	pm := map[string]Member{}
	nm := map[string]Member{}
	for _, m := range prev {
		pm[m.Zone] = m
	}
	for _, m := range next {
		nm[m.Zone] = m
	}
	for z, m := range nm {
		if _, ok := pm[z]; !ok {
			added = append(added, m)
		}
	}
	for z, m := range pm {
		if _, ok := nm[z]; !ok {
			removed = append(removed, m)
		}
	}
	return added, removed
}
