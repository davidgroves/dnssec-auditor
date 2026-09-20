package notify

import (
	"net"
	"testing"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/event"
	"github.com/davidgroves/dnssec-auditor/internal/metrics"
	"github.com/miekg/dns"
)

func TestHandleNotify(t *testing.T) {
	got := make(chan string, 1)
	m := metrics.New()
	bus := event.New(8)
	l, err := New(config.NotifyConfig{Enabled: true}, config.TSIGKey{}, func(z string) { got <- z }, m, bus, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := new(dns.Msg)
	msg.SetNotify("example.com.")
	wire, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	resp := l.handle(wire, net.ParseIP("127.0.0.1"), "udp")
	if resp == nil {
		t.Fatal("no response")
	}
	select {
	case z := <-got:
		if z != "example.com." {
			t.Fatalf("handler got %q", z)
		}
	case <-time.After(time.Second):
		t.Fatal("handler was not called")
	}
}

func TestRejectNonNotify(t *testing.T) {
	m := metrics.New()
	l, _ := New(config.NotifyConfig{Enabled: true}, config.TSIGKey{}, nil, m, event.New(1), nil)
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeSOA)
	wire, _ := msg.Pack()
	resp := l.handle(wire, net.ParseIP("127.0.0.1"), "udp")
	if resp == nil {
		t.Fatal("expected refused")
	}
}
