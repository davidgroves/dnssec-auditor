package testprimary

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/dnsname"
	"github.com/davidgroves/dnssec-auditor/internal/zone"
	"github.com/miekg/dns"
)

type changeset struct {
	From, To uint32
	Adds     []dns.RR
	Removes  []dns.RR
}

// Server is a test-only authoritative that applies UPDATEs literally.
type Server struct {
	mu       sync.Mutex
	zones    map[string]*zone.Store
	journal  map[string][]changeset
	tsig     map[string]string
	notifyTo string
	udp      *dns.Server
	tcp      *dns.Server
	Port     int
}

func New() *Server {
	return &Server{
		zones:   map[string]*zone.Store{},
		journal: map[string][]changeset{},
		tsig:    map[string]string{},
	}
}

func (s *Server) SetTSIG(name, secret string) {
	s.mu.Lock()
	s.tsig[dnsname.Canonical(name)] = secret
	s.mu.Unlock()
}

func (s *Server) SetNotify(addr string) {
	s.mu.Lock()
	s.notifyTo = addr
	s.mu.Unlock()
}

func (s *Server) Load(st *zone.Store) {
	s.mu.Lock()
	s.zones[st.Origin()] = st
	s.mu.Unlock()
}

func (s *Server) Store(name string) *zone.Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.zones[dnsname.Canonical(name)]
}

func (s *Server) PurgeJournal(name string) {
	s.mu.Lock()
	delete(s.journal, dnsname.Canonical(name))
	s.mu.Unlock()
}

func (s *Server) Apply(name string, adds, removes []dns.RR) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.zones[dnsname.Canonical(name)]
	if st == nil {
		return fmt.Errorf("unknown zone")
	}
	from := st.Serial()
	if _, err := st.ApplyChanges(adds, removes); err != nil {
		return err
	}
	to := st.Serial()
	if to == from {
		if soa := st.SOA(); soa != nil {
			oldSOA := new(dns.SOA)
			*oldSOA = *soa
			if err := st.RemoveRR(soa); err == nil {
				soa.Serial++
				if err := st.AddRR(soa); err == nil {
					to = soa.Serial
					removes = append(append([]dns.RR{}, removes...), oldSOA)
					adds = append(append([]dns.RR{}, adds...), soa)
				}
			}
		}
	}
	s.journal[st.Origin()] = append(s.journal[st.Origin()], changeset{From: from, To: to, Adds: adds, Removes: removes})
	go s.sendNotify(st.Origin())
	return nil
}

func (s *Server) Listen(addr string) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handle)
	udp := &dns.Server{Addr: addr, Net: "udp", Handler: mux, TsigSecret: s.tsig}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: mux, TsigSecret: s.tsig}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		pc.Close()
		return err
	}
	s.Port = ln.Addr().(*net.TCPAddr).Port
	// if addr was :0, UDP may have a different port — bind UDP to the same port
	if addr == "127.0.0.1:0" || addr == ":0" {
		pc.Close()
		pc, err = net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port)))
		if err != nil {
			ln.Close()
			return err
		}
	}
	udp.PacketConn = pc
	tcp.Listener = ln
	s.udp = udp
	s.tcp = tcp
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	return nil
}

func (s *Server) Close() {
	if s.udp != nil {
		s.udp.Shutdown()
	}
	if s.tcp != nil {
		s.tcp.Shutdown()
	}
}

func (s *Server) handle(w dns.ResponseWriter, r *dns.Msg) {
	if r.Opcode == dns.OpcodeUpdate {
		s.handleUpdate(w, r)
		return
	}
	if r.Opcode == dns.OpcodeQuery && len(r.Question) > 0 {
		switch r.Question[0].Qtype {
		case dns.TypeAXFR, dns.TypeIXFR:
			s.handleXFR(w, r)
			return
		case dns.TypeSOA:
			s.handleSOA(w, r)
			return
		}
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeRefused
	_ = w.WriteMsg(m)
}

func (s *Server) handleSOA(w dns.ResponseWriter, r *dns.Msg) {
	s.mu.Lock()
	st := s.zones[dnsname.Canonical(r.Question[0].Name)]
	s.mu.Unlock()
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	if st == nil {
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
		return
	}
	if soa := st.SOA(); soa != nil {
		m.Answer = []dns.RR{soa}
	}
	_ = w.WriteMsg(m)
}

func (s *Server) handleXFR(w dns.ResponseWriter, r *dns.Msg) {
	s.mu.Lock()
	st := s.zones[dnsname.Canonical(r.Question[0].Name)]
	journal := s.journal[dnsname.Canonical(r.Question[0].Name)]
	s.mu.Unlock()
	if st == nil {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
		return
	}
	soa := st.SOA()
	if soa == nil {
		return
	}
	if r.Question[0].Qtype == dns.TypeIXFR && len(r.Ns) > 0 {
		if qsoa, ok := r.Ns[0].(*dns.SOA); ok {
			if ch := findJournal(journal, qsoa.Serial, soa.Serial); ch != nil {
				s.writeIXFR(w, r, soa, qsoa, ch)
				return
			}
			// fall through to AXFR
		}
	}
	rrs, err := st.AllRRs()
	if err != nil {
		return
	}
	ch := make(chan *dns.Envelope, 4)
	go func() {
		defer close(ch)
		chunk := []dns.RR{soa}
		for _, rr := range rrs {
			if _, isSOA := rr.(*dns.SOA); isSOA {
				continue
			}
			chunk = append(chunk, rr)
			if len(chunk) >= 32 {
				ch <- &dns.Envelope{RR: chunk}
				chunk = nil
			}
		}
		chunk = append(chunk, soa)
		ch <- &dns.Envelope{RR: chunk}
	}()
	tr := new(dns.Transfer)
	_ = tr.Out(w, r, ch)
}

func (s *Server) writeIXFR(w dns.ResponseWriter, r *dns.Msg, newSOA, oldSOA *dns.SOA, ch *changeset) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = append(m.Answer, newSOA, oldSOA)
	m.Answer = append(m.Answer, ch.Removes...)
	m.Answer = append(m.Answer, newSOA)
	m.Answer = append(m.Answer, ch.Adds...)
	m.Answer = append(m.Answer, newSOA)
	_ = w.WriteMsg(m)
}

func findJournal(js []changeset, from, to uint32) *changeset {
	for i := range js {
		if js[i].From == from && js[i].To == to {
			return &js[i]
		}
	}
	return nil
}

func (s *Server) handleUpdate(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}
	name := dnsname.Canonical(r.Question[0].Name)
	var adds, removes []dns.RR
	// RFC 2136: Prerequisite in Answer, Update in Ns
	for _, rr := range r.Ns {
		if rr.Header().Class == dns.ClassANY || rr.Header().Class == dns.ClassNONE {
			removes = append(removes, rr)
			continue
		}
		adds = append(adds, rr)
	}
	_ = s.Apply(name, adds, removes)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeSuccess
	_ = w.WriteMsg(m)
}

func (s *Server) sendNotify(zone string) {
	s.mu.Lock()
	to := s.notifyTo
	s.mu.Unlock()
	if to == "" {
		return
	}
	m := new(dns.Msg)
	m.SetNotify(zone)
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	_, _, _ = c.Exchange(m, to)
}
