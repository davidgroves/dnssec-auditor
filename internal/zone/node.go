package zone

import (
	"slices"

	"github.com/miekg/dns"
)

// Node is all RRsets at one owner name.
type Node struct {
	Name         string
	Sets         []RRSet
	NSEC3Hash    [20]byte
	HasNSEC3Hash bool
	IsDelegation bool
	HasDS        bool
}

func (n *Node) Set(rrtype uint16) *RRSet {
	for i := range n.Sets {
		if n.Sets[i].Type == rrtype {
			return &n.Sets[i]
		}
	}
	return nil
}

func (n *Node) Has(rrtype uint16) bool {
	return n.Set(rrtype) != nil
}

func (n *Node) Types() []uint16 {
	out := make([]uint16, len(n.Sets))
	for i, s := range n.Sets {
		out[i] = s.Type
	}
	return out
}

func (n *Node) RecordCount() int {
	c := 0
	for _, s := range n.Sets {
		c += len(s.Rdata)
	}
	return c
}

func (n *Node) addPacked(rrtype uint16, ttl uint32, rdata []byte) {
	for i := range n.Sets {
		if n.Sets[i].Type == rrtype {
			if n.Sets[i].TTL == 0 {
				n.Sets[i].TTL = ttl
			}
			for _, existing := range n.Sets[i].Rdata {
				if slices.Equal(existing, rdata) {
					return
				}
			}
			n.Sets[i].Rdata = append(n.Sets[i].Rdata, rdata)
			return
		}
	}
	n.Sets = append(n.Sets, RRSet{Type: rrtype, TTL: ttl, Rdata: [][]byte{rdata}})
}

func (n *Node) removePacked(rrtype uint16, rdata []byte) bool {
	for i := range n.Sets {
		if n.Sets[i].Type != rrtype {
			continue
		}
		kept := n.Sets[i].Rdata[:0]
		removed := false
		for _, existing := range n.Sets[i].Rdata {
			if !removed && slices.Equal(existing, rdata) {
				removed = true
				continue
			}
			kept = append(kept, existing)
		}
		if !removed {
			return false
		}
		if len(kept) == 0 {
			n.Sets = append(n.Sets[:i], n.Sets[i+1:]...)
		} else {
			n.Sets[i].Rdata = kept
		}
		return true
	}
	return false
}

func (n *Node) recomputeFlags(origin string) {
	n.IsDelegation = n.Name != origin && n.Has(dns.TypeNS)
	n.HasDS = n.Has(dns.TypeDS)
}

func (n *Node) Clone() *Node {
	out := &Node{
		Name:         n.Name,
		Sets:         make([]RRSet, len(n.Sets)),
		NSEC3Hash:    n.NSEC3Hash,
		HasNSEC3Hash: n.HasNSEC3Hash,
		IsDelegation: n.IsDelegation,
		HasDS:        n.HasDS,
	}
	for i, s := range n.Sets {
		out.Sets[i] = s.Clone()
	}
	return out
}

func (n *Node) UnpackType(rrtype uint16) ([]dns.RR, error) {
	s := n.Set(rrtype)
	if s == nil {
		return nil, nil
	}
	return s.Unpack(n.Name)
}

func (n *Node) AllRRs() ([]dns.RR, error) {
	var out []dns.RR
	for _, s := range n.Sets {
		rrs, err := s.Unpack(n.Name)
		if err != nil {
			return nil, err
		}
		out = append(out, rrs...)
	}
	return out, nil
}

func (n *Node) RRSIGsCovering(rrtype uint16) []CompactRRSIG {
	s := n.Set(dns.TypeRRSIG)
	if s == nil {
		return nil
	}
	rrs, err := s.Unpack(n.Name)
	if err != nil {
		return nil
	}
	var out []CompactRRSIG
	for _, rr := range rrs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		if sig.TypeCovered == rrtype {
			out = append(out, ParseRRSIG(sig))
		}
	}
	return out
}
