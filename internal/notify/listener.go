package notify

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/dnsname"
	"github.com/davidgroves/dnssec-auditor/internal/event"
	"github.com/davidgroves/dnssec-auditor/internal/metrics"
	"github.com/miekg/dns"
)

type Handler func(zone string)

type Listener struct {
	cfg     config.NotifyConfig
	keys    map[string]string
	keyName string
	keyAlg  string
	handler Handler
	metrics *metrics.Metrics
	bus     *event.Bus
	log     *slog.Logger
	nets    []*net.IPNet

	mu       sync.Mutex
	last     map[string]time.Time
	udpConn  *net.UDPConn
	tcpLn    net.Listener
	boundUDP int
	boundTCP int
}

func New(cfg config.NotifyConfig, tsig config.TSIGKey, h Handler, m *metrics.Metrics, bus *event.Bus, log *slog.Logger) (*Listener, error) {
	l := &Listener{
		cfg:     cfg,
		handler: h,
		metrics: m,
		bus:     bus,
		log:     log,
		last:    map[string]time.Time{},
	}
	if tsig.Name != "" && tsig.Secret != "" {
		l.keyName = dnsname.Canonical(tsig.Name)
		l.keys = map[string]string{l.keyName: tsig.Secret}
		l.keyAlg = tsig.Algorithm
		if l.keyAlg == "" {
			l.keyAlg = dns.HmacSHA256
		}
	}
	for _, cidr := range cfg.AllowedSources {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			ip := net.ParseIP(cidr)
			if ip == nil {
				return nil, fmt.Errorf("notify allowed_sources %q: %w", cidr, err)
			}
			if ip.To4() != nil {
				_, n, _ = net.ParseCIDR(ip.String() + "/32")
			} else {
				_, n, _ = net.ParseCIDR(ip.String() + "/128")
			}
		}
		l.nets = append(l.nets, n)
	}
	return l, nil
}

func (l *Listener) UDPPort() int { return l.boundUDP }
func (l *Listener) TCPPort() int { return l.boundTCP }

func (l *Listener) Start(ctx context.Context) error {
	if !l.cfg.Enabled {
		return nil
	}
	host := l.cfg.BindAddress
	if host == "" {
		host = "0.0.0.0"
	}
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(l.cfg.UDPPort)))
	if err != nil {
		return err
	}
	uc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	l.udpConn = uc
	l.boundUDP = uc.LocalAddr().(*net.UDPAddr).Port

	tcpAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, strconv.Itoa(l.cfg.TCPPort)))
	if err != nil {
		uc.Close()
		return err
	}
	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		uc.Close()
		return err
	}
	l.tcpLn = ln
	l.boundTCP = ln.Addr().(*net.TCPAddr).Port

	go l.serveUDP(ctx)
	go l.serveTCP(ctx)
	go func() {
		<-ctx.Done()
		uc.Close()
		ln.Close()
	}()
	l.log.Info("notify listener started", "udp", l.boundUDP, "tcp", l.boundTCP)
	return nil
}

func (l *Listener) serveUDP(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := l.udpConn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		resp := l.handle(append([]byte(nil), buf[:n]...), addr.IP, "udp")
		if resp != nil {
			_, _ = l.udpConn.WriteToUDP(resp, addr)
		}
	}
}

func (l *Listener) serveTCP(ctx context.Context) {
	for {
		c, err := l.tcpLn.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go func(conn net.Conn) {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			var hdr [2]byte
			if _, err := conn.Read(hdr[:]); err != nil {
				return
			}
			ln := int(binary.BigEndian.Uint16(hdr[:]))
			body := make([]byte, ln)
			if _, err := conn.Read(body); err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			resp := l.handle(body, net.ParseIP(host), "tcp")
			if resp == nil {
				return
			}
			out := make([]byte, 2+len(resp))
			binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
			copy(out[2:], resp)
			_, _ = conn.Write(out)
		}(c)
	}
}

func (l *Listener) handle(wire []byte, ip net.IP, transport string) []byte {
	result := "ok"
	defer func() {
		l.metrics.NotifiesReceived.WithLabelValues(transport, result).Inc()
	}()
	if !l.allowed(ip) {
		result = "acl"
		return nil
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		result = "parse"
		return nil
	}
	if msg.Opcode != dns.OpcodeNotify {
		result = "opcode"
		return refused(msg)
	}
	if l.cfg.RequireTSIG {
		if msg.IsTsig() == nil {
			result = "notauth"
			return notauth(msg)
		}
		if l.keys != nil {
			if err := dns.TsigVerify(wire, l.keys[l.keyName], "", false); err != nil {
				result = "notauth"
				return notauth(msg)
			}
		}
	}
	if len(msg.Question) == 0 {
		result = "question"
		return refused(msg)
	}
	zname := dnsname.Canonical(msg.Question[0].Name)
	l.bus.Publish(event.Event{Type: event.NotifyReceived, Zone: zname, Transport: transport, Result: "ok"})
	if l.debounce(zname) {
		if l.handler != nil {
			go l.handler(zname)
		}
	}
	resp := new(dns.Msg)
	resp.SetReply(msg)
	resp.Authoritative = true
	out, _ := resp.Pack()
	return out
}

func (l *Listener) debounce(zone string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[zone]; ok && time.Since(t) < 500*time.Millisecond {
		return false
	}
	l.last[zone] = time.Now()
	return true
}

func (l *Listener) allowed(ip net.IP) bool {
	if len(l.nets) == 0 {
		return true
	}
	if ip == nil {
		return false
	}
	for _, n := range l.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func refused(req *dns.Msg) []byte {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Rcode = dns.RcodeRefused
	b, _ := m.Pack()
	return b
}

func notauth(req *dns.Msg) []byte {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Rcode = dns.RcodeNotAuth
	b, _ := m.Pack()
	return b
}

func TSIGFromConfig(cfg *config.Config) config.TSIGKey {
	if cfg.Notify.TSIGKey == "" {
		return config.TSIGKey{}
	}
	k, ok := cfg.TSIGByName(cfg.Notify.TSIGKey)
	if !ok {
		return config.TSIGKey{}
	}
	if !strings.Contains(k.Algorithm, "hmac") && k.Algorithm != "" {
		k.Algorithm = dns.HmacSHA256
	}
	return k
}
