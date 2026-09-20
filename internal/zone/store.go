package zone

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/dnsname"
	"github.com/miekg/dns"
	"github.com/tidwall/btree"
)

// Store is a compact in-memory zone.
type Store struct {
	mu     sync.RWMutex
	origin string
	serial uint32
	nodes  map[string]*Node
	// nsec3 is keyed by the binary NSEC3 hash (owner label decoded).
	nsec3 *btree.Map[string, *NSEC3Rec]
	// expiry is keyed by "expiration:name:typeCovered:keytag" for sweep.
	expiry *btree.Map[string, ExpiryRec]
	rrs    int
}

// NSEC3Rec is one NSEC3 record in the ordered hash index.
type NSEC3Rec struct {
	Hash       string // binary hash (20 bytes for SHA-1)
	Owner      string // hashed owner name (base32hex.zone.)
	Next       string // binary next hash
	Iterations uint16
	Salt       []byte
	Flags      uint8
	TypeBitMap []uint16
}

// ExpiryRec points at one RRSIG for the expiry sweep.
type ExpiryRec struct {
	Expiration  uint32
	Owner       string
	TypeCovered uint16
	KeyTag      uint16
}

// Touched is the set of names and NSEC3 hashes affected by a changeset.
type Touched struct {
	Names      map[string]struct{}
	NSEC3      map[string]struct{}
	DNSKEY     bool
	NSEC3PARAM bool
	SOA        bool
	Added      int
	Removed    int
}

func NewStore(origin string) *Store {
	return &Store{
		origin: dnsname.Canonical(origin),
		nodes:  make(map[string]*Node),
		nsec3:  btree.NewMap[string, *NSEC3Rec](16),
		expiry: btree.NewMap[string, ExpiryRec](16),
	}
}

func (s *Store) Origin() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.origin
}

func (s *Store) Serial() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serial
}

func (s *Store) RecordCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rrs
}

func (s *Store) NodeCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.nodes)
}

func (s *Store) EstimateBytes() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for name, node := range s.nodes {
		n += len(name) + 64
		for _, set := range node.Sets {
			n += 16
			for _, rd := range set.Rdata {
				n += len(rd) + 16
			}
		}
	}
	return n
}

func (s *Store) Apex() *Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[s.origin]
}

func (s *Store) Lookup(name string) *Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[dnsname.Canonical(name)]
}

func (s *Store) ForEachNode(fn func(*Node) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, n := range s.nodes {
		if !fn(n) {
			return
		}
	}
}

func (s *Store) SortedNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.nodes))
	for name := range s.nodes {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int {
		return CanonicalCmp(a, b)
	})
	return names
}

// AddRR inserts a parsed RR. The store must be exclusively held by the caller
// or this is used during construction (no concurrent readers).
func (s *Store) AddRR(rr dns.RR) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addRRLocked(rr)
}

func (s *Store) addRRLocked(rr dns.RR) error {
	h := rr.Header()
	if h.Class != dns.ClassINET && h.Class != 0 {
		return nil
	}
	name := dnsname.Canonical(h.Name)
	rdata, err := PackRR(rr)
	if err != nil {
		return err
	}
	node := s.nodes[name]
	if node == nil {
		node = &Node{Name: name}
		s.nodes[name] = node
	}
	before := node.RecordCount()
	node.addPacked(h.Rrtype, h.Ttl, rdata)
	s.rrs += node.RecordCount() - before
	node.recomputeFlags(s.origin)
	if h.Rrtype == dns.TypeSOA {
		if soa, ok := rr.(*dns.SOA); ok {
			s.serial = soa.Serial
		}
	}
	s.indexRRLocked(name, rr)
	return nil
}

func (s *Store) RemoveRR(rr dns.RR) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removeRRLocked(rr)
}

func (s *Store) removeRRLocked(rr dns.RR) error {
	h := rr.Header()
	name := dnsname.Canonical(h.Name)
	node := s.nodes[name]
	if node == nil {
		return nil
	}
	rdata, err := PackRR(rr)
	if err != nil {
		return err
	}
	if node.removePacked(h.Rrtype, rdata) {
		s.rrs--
	}
	if node.RecordCount() == 0 {
		delete(s.nodes, name)
	} else {
		node.recomputeFlags(s.origin)
	}
	s.deindexRRLocked(name, rr)
	if h.Rrtype == dns.TypeSOA {
		if soa := s.soaLocked(); soa != nil {
			s.serial = soa.Serial
		}
	}
	return nil
}

func (s *Store) indexRRLocked(name string, rr dns.RR) {
	switch v := rr.(type) {
	case *dns.NSEC3:
		rec := nsec3Rec(name, v)
		s.nsec3.Set(rec.Hash, rec)
	case *dns.RRSIG:
		s.expiry.Set(expiryKey(v.Expiration, name, v.TypeCovered, v.KeyTag), ExpiryRec{
			Expiration:  v.Expiration,
			Owner:       name,
			TypeCovered: v.TypeCovered,
			KeyTag:      v.KeyTag,
		})
	}
}

func (s *Store) deindexRRLocked(name string, rr dns.RR) {
	switch v := rr.(type) {
	case *dns.NSEC3:
		hash, err := HashFromOwner(name)
		if err == nil {
			s.nsec3.Delete(string(hash))
		}
	case *dns.RRSIG:
		s.expiry.Delete(expiryKey(v.Expiration, name, v.TypeCovered, v.KeyTag))
	}
}

func expiryKey(exp uint32, name string, covered uint16, tag uint16) string {
	return fmt.Sprintf("%010d:%s:%d:%d", exp, name, covered, tag)
}

func (s *Store) soaLocked() *dns.SOA {
	n := s.nodes[s.origin]
	if n == nil {
		return nil
	}
	rrs, err := n.UnpackType(dns.TypeSOA)
	if err != nil || len(rrs) == 0 {
		return nil
	}
	soa, _ := rrs[0].(*dns.SOA)
	return soa
}

// SOA returns a copy of the apex SOA, or nil.
func (s *Store) SOA() *dns.SOA {
	s.mu.RLock()
	defer s.mu.RUnlock()
	soa := s.soaLocked()
	if soa == nil {
		return nil
	}
	cp := *soa
	return &cp
}

// DNSKEYs returns apex DNSKEY records.
func (s *Store) DNSKEYs() ([]*dns.DNSKEY, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := s.nodes[s.origin]
	if n == nil {
		return nil, nil
	}
	rrs, err := n.UnpackType(dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	out := make([]*dns.DNSKEY, 0, len(rrs))
	for _, rr := range rrs {
		if k, ok := rr.(*dns.DNSKEY); ok {
			out = append(out, k)
		}
	}
	return out, nil
}

// NSEC3PARAM returns the first apex NSEC3PARAM, if any.
func (s *Store) NSEC3PARAM() *dns.NSEC3PARAM {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := s.nodes[s.origin]
	if n == nil {
		return nil
	}
	rrs, err := n.UnpackType(dns.TypeNSEC3PARAM)
	if err != nil || len(rrs) == 0 {
		return nil
	}
	p, _ := rrs[0].(*dns.NSEC3PARAM)
	return p
}

func (s *Store) NSEC3Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nsec3.Len()
}

// Signing mode labels for denial-of-existence style.
const (
	SigningUnsigned = "unsigned"
	SigningNSEC     = "nsec"
	SigningNSEC3    = "nsec3"
	SigningMixed    = "mixed"
)

// SigningMode classifies the zone as unsigned, nsec, nsec3, or mixed
// based on presence of NSEC / NSEC3 / NSEC3PARAM records.
func (s *Store) SigningMode() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hasNSEC := false
	hasNSEC3PARAM := false
	for _, n := range s.nodes {
		if n.Has(dns.TypeNSEC) {
			hasNSEC = true
		}
		if n.Has(dns.TypeNSEC3PARAM) {
			hasNSEC3PARAM = true
		}
		if hasNSEC && hasNSEC3PARAM {
			break
		}
	}
	hasNSEC3 := s.nsec3.Len() > 0 || hasNSEC3PARAM
	if hasNSEC && hasNSEC3 {
		return SigningMixed
	}
	if hasNSEC3 {
		return SigningNSEC3
	}
	if hasNSEC {
		return SigningNSEC
	}
	return SigningUnsigned
}

func (s *Store) RRSIGCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.expiry.Len()
}

func (s *Store) ForEachNSEC3(fn func(*NSEC3Rec) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.nsec3.Scan(func(_ string, rec *NSEC3Rec) bool {
		return fn(rec)
	})
}

func (s *Store) NSEC3ByHash(hash string) *NSEC3Rec {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, _ := s.nsec3.Get(hash)
	return rec
}

// CoveringNSEC3 returns the NSEC3 that covers hash (predecessor if no exact match).
func (s *Store) CoveringNSEC3(hash string) *NSEC3Rec {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if rec, ok := s.nsec3.Get(hash); ok {
		return rec
	}
	var pred *NSEC3Rec
	s.nsec3.Descend(hash, func(_ string, rec *NSEC3Rec) bool {
		pred = rec
		return false
	})
	if pred != nil {
		return pred
	}
	// wrap: last in the ring
	s.nsec3.Reverse(func(_ string, rec *NSEC3Rec) bool {
		pred = rec
		return false
	})
	return pred
}

func (s *Store) NextNSEC3(hash string) *NSEC3Rec {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var next *NSEC3Rec
	found := false
	s.nsec3.Ascend(hash, func(k string, rec *NSEC3Rec) bool {
		if !found {
			if k == hash {
				found = true
				return true
			}
			// hash not present; this is the successor
			next = rec
			return false
		}
		next = rec
		return false
	})
	if next == nil {
		s.nsec3.Scan(func(_ string, rec *NSEC3Rec) bool {
			next = rec
			return false
		})
	}
	return next
}

func (s *Store) PredNSEC3(hash string) *NSEC3Rec {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var pred *NSEC3Rec
	s.nsec3.Descend(hash, func(k string, rec *NSEC3Rec) bool {
		if k == hash {
			return true
		}
		pred = rec
		return false
	})
	if pred == nil {
		s.nsec3.Reverse(func(_ string, rec *NSEC3Rec) bool {
			pred = rec
			return false
		})
	}
	return pred
}

// EarliestExpiry returns the soonest RRSIG expiration, or 0.
func (s *Store) EarliestExpiry() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var exp uint32
	s.expiry.Scan(func(_ string, rec ExpiryRec) bool {
		exp = rec.Expiration
		return false
	})
	return exp
}

// ExpiringBefore yields expiry records with Expiration <= cutoff.
func (s *Store) ExpiringBefore(cutoff uint32, fn func(ExpiryRec) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	end := fmt.Sprintf("%010d~", cutoff)
	s.expiry.Ascend("", func(k string, rec ExpiryRec) bool {
		if k > end {
			return false
		}
		if rec.Expiration > cutoff {
			return false
		}
		return fn(rec)
	})
}

// ApplyChanges applies adds/removes and returns the touched set. IXFR-style:
// each Change is a single RR.
func (s *Store) ApplyChanges(adds, removes []dns.RR) (*Touched, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &Touched{Names: map[string]struct{}{}, NSEC3: map[string]struct{}{}}
	for _, rr := range removes {
		name := dnsname.Canonical(rr.Header().Name)
		t.Names[name] = struct{}{}
		t.note(rr)
		if err := s.removeRRLocked(rr); err != nil {
			return t, err
		}
		t.Removed++
	}
	for _, rr := range adds {
		name := dnsname.Canonical(rr.Header().Name)
		t.Names[name] = struct{}{}
		t.note(rr)
		if err := s.addRRLocked(rr); err != nil {
			return t, err
		}
		t.Added++
	}
	return t, nil
}

func (t *Touched) note(rr dns.RR) {
	switch rr.Header().Rrtype {
	case dns.TypeDNSKEY:
		t.DNSKEY = true
	case dns.TypeNSEC3PARAM:
		t.NSEC3PARAM = true
	case dns.TypeSOA:
		t.SOA = true
	case dns.TypeNSEC3:
		if h, err := HashFromOwner(rr.Header().Name); err == nil {
			t.NSEC3[string(h)] = struct{}{}
		}
	}
}

// AllRRs returns every record (expensive; used for export / ZONEMD / snapshots).
func (s *Store) AllRRs() ([]dns.RR, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]dns.RR, 0, s.rrs)
	for _, n := range s.nodes {
		rrs, err := n.AllRRs()
		if err != nil {
			return nil, err
		}
		out = append(out, rrs...)
	}
	return out, nil
}

// WriteZoneFile writes a canonical-ish zone file (sorted owners and types).
func (s *Store) WriteZoneFile(w io.Writer) error {
	return s.WriteZoneFileAnnotated(w, nil)
}

// WriteZoneFileAnnotated writes a sorted master-file dump. Optional comment
// lines keyed by canonical owner are emitted immediately before that owner's
// records (or alone if the owner has no records).
func (s *Store) WriteZoneFileAnnotated(w io.Writer, comments map[string][]string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nameSet := make(map[string]struct{}, len(s.nodes)+len(comments))
	for name := range s.nodes {
		nameSet[name] = struct{}{}
	}
	normalized := make(map[string][]string, len(comments))
	for owner, lines := range comments {
		canon := dnsname.Canonical(owner)
		nameSet[canon] = struct{}{}
		normalized[canon] = append(normalized[canon], lines...)
	}
	comments = normalized

	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	slices.SortFunc(names, CanonicalCmp)

	for _, name := range names {
		if lines := comments[name]; len(lines) > 0 {
			for _, line := range lines {
				if _, err := fmt.Fprintln(w, line); err != nil {
					return err
				}
			}
		}
		n := s.nodes[name]
		if n == nil {
			continue
		}
		rrs, err := n.AllRRs()
		if err != nil {
			return err
		}
		slices.SortFunc(rrs, func(a, b dns.RR) int {
			if a.Header().Rrtype != b.Header().Rrtype {
				return int(a.Header().Rrtype) - int(b.Header().Rrtype)
			}
			return strings.Compare(a.String(), b.String())
		})
		for _, rr := range rrs {
			if _, err := fmt.Fprintln(w, rr.String()); err != nil {
				return err
			}
		}
	}
	return nil
}

const snapMagic = "DSA1"

// WriteSnapshot writes a compact snapshot: magic, origin, serial, time, then
// length-prefixed wire RRs.
func (s *Store) WriteSnapshot(w io.Writer) error {
	rrs, err := s.AllRRs()
	if err != nil {
		return err
	}
	s.mu.RLock()
	origin := s.origin
	serial := s.serial
	s.mu.RUnlock()
	if _, err := io.WriteString(w, snapMagic); err != nil {
		return err
	}
	if err := writeString(w, origin); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, serial); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, time.Now().Unix()); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(rrs))); err != nil {
		return err
	}
	buf := make([]byte, dns.MaxMsgSize)
	for _, rr := range rrs {
		n, err := dns.PackRR(rr, buf, 0, nil, false)
		if err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, uint16(n)); err != nil {
			return err
		}
		if _, err := w.Write(buf[:n]); err != nil {
			return err
		}
	}
	return nil
}

// ReadSnapshot reconstructs a store from WriteSnapshot output.
func ReadSnapshot(r io.Reader) (*Store, time.Time, error) {
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, time.Time{}, err
	}
	if string(magic) != snapMagic {
		return nil, time.Time{}, fmt.Errorf("bad snapshot magic")
	}
	origin, err := readString(r)
	if err != nil {
		return nil, time.Time{}, err
	}
	var serial uint32
	var saved int64
	var count uint32
	if err := binary.Read(r, binary.BigEndian, &serial); err != nil {
		return nil, time.Time{}, err
	}
	if err := binary.Read(r, binary.BigEndian, &saved); err != nil {
		return nil, time.Time{}, err
	}
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, time.Time{}, err
	}
	st := NewStore(origin)
	st.serial = serial
	for i := uint32(0); i < count; i++ {
		var n uint16
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return nil, time.Time{}, err
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, time.Time{}, err
		}
		rr, _, err := dns.UnpackRR(buf, 0)
		if err != nil {
			return nil, time.Time{}, err
		}
		if err := st.addRRLocked(rr); err != nil {
			return nil, time.Time{}, err
		}
	}
	return st, time.Unix(saved, 0), nil
}

func writeString(w io.Writer, s string) error {
	if err := binary.Write(w, binary.BigEndian, uint16(len(s))); err != nil {
		return err
	}
	_, err := io.WriteString(w, s)
	return err
}

func readString(r io.Reader) (string, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return "", err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func nsec3Rec(owner string, n *dns.NSEC3) *NSEC3Rec {
	hash, _ := HashFromOwner(owner)
	next, err := HashFromBase32(n.NextDomain)
	if err != nil {
		next = []byte(n.NextDomain)
	}
	return &NSEC3Rec{
		Hash:       string(hash),
		Owner:      dnsname.Canonical(owner),
		Next:       string(next),
		Iterations: n.Iterations,
		Salt:       saltBytes(n.Salt),
		Flags:      n.Flags,
		TypeBitMap: append([]uint16(nil), n.TypeBitMap...),
	}
}

func saltBytes(s string) []byte {
	if s == "" || s == "-" {
		return nil
	}
	// miekg stores salt as hex
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		var v byte
		fmt.Sscanf(s[i*2:i*2+2], "%02x", &v)
		b[i] = v
	}
	return b
}

// FromAXFR builds a store by consuming dns.RR values (e.g. transfer envelopes).
func FromAXFR(origin string, rrs []dns.RR) (*Store, error) {
	st := NewStore(origin)
	for _, rr := range rrs {
		if err := st.addRRLocked(rr); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// EqualRdata reports packed equality.
func EqualRdata(a, b []byte) bool { return bytes.Equal(a, b) }
