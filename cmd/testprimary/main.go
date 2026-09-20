package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/davidgroves/dnssec-auditor/internal/testprimary"
	"github.com/davidgroves/dnssec-auditor/internal/zonegen"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:5353", "listen address")
	origin := flag.String("zone", "example.com.", "zone to generate")
	deleg := flag.Int("delegations", 8, "number of delegations")
	pack := flag.String("scenario-pack", "", "defects | empty")
	flag.Parse()

	s := testprimary.New()
	if *pack == "defects" {
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
	} else {
		g, err := zonegen.Generate(zonegen.Options{Origin: *origin, Delegations: *deleg, Seed: 1})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		s.Load(g.Store)
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
