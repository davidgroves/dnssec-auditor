package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/davidgroves/dnssec-auditor/internal/dnsname"
	"github.com/davidgroves/dnssec-auditor/internal/testprimary"
	"github.com/davidgroves/dnssec-auditor/internal/zonegen"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:5353", "listen address")
	origin := flag.String("zone", "example.com.", "zone to generate")
	deleg := flag.Int("delegations", 8, "number of delegations")
	pack := flag.String("scenario-pack", "", "examples | defects | empty")
	notify := flag.String("notify", "", "host:port to send RFC 1996 NOTIFY to")
	tsig := flag.String("tsig", "", "TSIG name:secret (hmac-sha256)")
	flag.Parse()

	s := testprimary.New()
	switch *pack {
	case "examples":
		if err := loadExamplePack(s); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "defects":
		for i, name := range []string{"good", "rrsig-invalid", "rrsig-missing"} {
			origin := fmt.Sprintf("%s.pack.test.", name)
			g, err := zonegen.Small(origin)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if i == 1 {
				_ = zonegen.FlipRRSIG(g)
			}
			if i == 2 {
				_ = zonegen.DropRRSIG(g)
			}
			s.Load(g.Store)
		}
	default:
		g, err := zonegen.Generate(zonegen.Options{Origin: *origin, Delegations: *deleg, Seed: 1})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		s.Load(g.Store)
	}
	if *tsig != "" {
		name, secret, ok := strings.Cut(*tsig, ":")
		if !ok || name == "" || secret == "" {
			fmt.Fprintln(os.Stderr, "tsig must be name:secret")
			os.Exit(1)
		}
		s.SetTSIG(dnsname.Canonical(name), secret)
	}
	if *notify != "" {
		s.SetNotify(*notify)
	}
	if err := s.Listen(*addr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("testprimary listening on %s (udp/tcp port %d)\n", *addr, s.Port)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
	s.Close()
}
