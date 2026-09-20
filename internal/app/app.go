package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/api"
	"github.com/davidgroves/dnssec-auditor/internal/catalog"
	"github.com/davidgroves/dnssec-auditor/internal/chain"
	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/event"
	"github.com/davidgroves/dnssec-auditor/internal/logging"
	"github.com/davidgroves/dnssec-auditor/internal/metrics"
	"github.com/davidgroves/dnssec-auditor/internal/monitor"
	"github.com/davidgroves/dnssec-auditor/internal/notify"
	"github.com/davidgroves/dnssec-auditor/internal/state"
	"github.com/davidgroves/dnssec-auditor/internal/webhooks"
)

// App is the running auditor process.
type App struct {
	Cfg     *config.Config
	Log     *slog.Logger
	Metrics *metrics.Metrics
	Bus     *event.Bus
	Mgr     *monitor.Manager
	HTTP    *http.Server
	Notify  *notify.Listener
}

func New(cfg *config.Config, log *slog.Logger) *App {
	if log == nil {
		log = logging.Setup(cfg.Logging, os.Stdout)
	}
	m := metrics.New()
	bus := event.New(256)
	mgr := monitor.New(cfg, bus, m, log)
	return &App{Cfg: cfg, Log: log, Metrics: m, Bus: bus, Mgr: mgr}
}

func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if snap, err := state.Load(a.Cfg.State.File); err == nil {
		state.Apply(snap, a.Mgr)
	}
	if a.Cfg.State.ZoneSnapshots.Enabled {
		for _, z := range a.Mgr.List() {
			st, _, err := state.ReadSnapshot(a.Cfg.State.ZoneSnapshots, z.Name)
			if err != nil || st == nil {
				continue
			}
			z.AttachStore(st)
		}
	}

	wh := webhooks.New(a.Cfg.Webhooks, a.Metrics, a.Log)
	wh.Subscribe(a.Bus)
	go wh.Run(ctx)

	ln, err := notify.New(a.Cfg.Notify, notify.TSIGFromConfig(a.Cfg), func(zone string) {
		_ = a.Mgr.RequestRefresh(zone, false)
	}, a.Metrics, a.Bus, a.Log)
	if err != nil {
		return err
	}
	if err := ln.Start(ctx); err != nil {
		return err
	}
	a.Notify = ln
	a.Bus.Subscribe(func(e event.Event) {
		if e.Type != event.VerificationCompleted {
			return
		}
		z := a.Mgr.Get(e.Zone)
		if z == nil {
			return
		}
		_ = state.WriteSnapshot(a.Cfg.State.ZoneSnapshots, z)
	})

	go a.Mgr.Run(ctx)
	go a.watchCatalogs(ctx)
	ch := chain.New(a.Cfg.ChainOfTrust, a.Metrics, a.Bus)
	go ch.Run(ctx, a.Mgr)

	if a.Cfg.State.File != "" {
		go a.persistLoop(ctx)
	}

	srv := api.New(a.Cfg, a.Mgr, a.Metrics, a.Bus)
	a.HTTP = &http.Server{
		Addr:              a.Cfg.API.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		a.Log.Info("api listening", "addr", a.Cfg.API.Listen)
		if err := a.HTTP.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = a.HTTP.Shutdown(shctx)
		_ = state.Save(a.Cfg.State.File, a.Mgr, a.Metrics)
		return nil
	case err := <-errCh:
		return err
	}
}

func (a *App) persistLoop(ctx context.Context) {
	t := time.NewTicker(a.Cfg.State.SaveInterval.Duration())
	if a.Cfg.State.SaveInterval.Duration() <= 0 {
		t.Stop()
		return
	}
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = state.Save(a.Cfg.State.File, a.Mgr, a.Metrics)
		}
	}
}

func (a *App) watchCatalogs(ctx context.Context) {
	prev := map[string][]catalog.Member{}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, c := range a.Cfg.Catalogs {
				z := a.Mgr.Get(c.Name)
				if z == nil {
					a.Mgr.AddZone(c.Name, "config", a.Cfg.ResolveServers(c.Servers), c.TSIGKey)
					continue
				}
				st, _ := z.StoreAndChain()
				if st == nil {
					continue
				}
				_, members, err := catalog.Parse(st)
				if err != nil {
					continue
				}
				added, removed := catalog.Diff(prev[c.Name], members)
				prev[c.Name] = members
				for _, m := range added {
					if a.Mgr.Get(m.Zone) != nil {
						continue
					}
					a.Mgr.AddZone(m.Zone, "catalog:"+c.Name, a.Cfg.ResolveServers(c.MemberServers), c.MemberTSIGKey)
					a.Bus.Publish(event.Event{Type: event.CatalogMemberAdded, Zone: m.Zone, Catalog: c.Name})
					go a.Mgr.Refresh(ctx, a.Mgr.Get(m.Zone), false)
				}
				for _, m := range removed {
					z := a.Mgr.Get(m.Zone)
					if z != nil && z.Source == "catalog:"+c.Name {
						a.Mgr.RemoveZone(m.Zone)
						a.Bus.Publish(event.Event{Type: event.CatalogMemberRemoved, Zone: m.Zone, Catalog: c.Name})
					}
				}
				a.Metrics.CatalogMembers.WithLabelValues(c.Name).Set(float64(len(members)))
			}
		}
	}
}

// Serve is the CLI entry for `dnssec-auditor serve`.
func Serve(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	log := logging.Setup(cfg.Logging, os.Stdout)
	a := New(cfg, log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		return fmt.Errorf("run: %w", err)
	}
	return nil
}
