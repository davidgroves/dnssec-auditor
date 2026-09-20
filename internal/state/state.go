package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/dnssec"
	"github.com/davidgroves/dnssec-auditor/internal/metrics"
	"github.com/davidgroves/dnssec-auditor/internal/monitor"
	"github.com/davidgroves/dnssec-auditor/internal/zone"
)

type File struct {
	SavedAt time.Time           `json:"saved_at"`
	Zones   map[string]ZoneSnap `json:"zones"`
}

type ZoneSnap struct {
	LastValidAt time.Time        `json:"last_valid_at"`
	LastSerial  uint32           `json:"last_serial"`
	State       string           `json:"state"`
	Findings    []dnssec.Finding `json:"findings"`
	Source      string           `json:"source"`
}

func Load(path string) (*File, error) {
	if path == "" {
		return &File{Zones: map[string]ZoneSnap{}}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &File{Zones: map[string]ZoneSnap{}}, nil
		}
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if f.Zones == nil {
		f.Zones = map[string]ZoneSnap{}
	}
	return &f, nil
}

func Save(path string, mgr *monitor.Manager, m *metrics.Metrics) error {
	if path == "" {
		return nil
	}
	f := File{SavedAt: time.Now(), Zones: map[string]ZoneSnap{}}
	for _, z := range mgr.List() {
		v := z.Snapshot()
		f.Zones[v.Name] = ZoneSnap{
			LastValidAt: v.LastValidAt,
			LastSerial:  v.Serial,
			State:       v.State,
			Findings:    v.Findings,
			Source:      v.Source,
		}
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		m.StateSaves.WithLabelValues("error").Inc()
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		m.StateSaves.WithLabelValues("error").Inc()
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		m.StateSaves.WithLabelValues("error").Inc()
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		m.StateSaves.WithLabelValues("error").Inc()
		return err
	}
	m.StateSaves.WithLabelValues("ok").Inc()
	return nil
}

func Apply(f *File, mgr *monitor.Manager) {
	if f == nil {
		return
	}
	for name, snap := range f.Zones {
		z := mgr.Get(name)
		if z == nil {
			continue
		}
		z.Restore(snap.LastValidAt, snap.Findings)
	}
}

func WriteSnapshot(cfg config.SnapshotConfig, z *monitor.ZoneRuntime) error {
	if !cfg.Enabled || cfg.Dir == "" {
		return nil
	}
	st, _ := z.StoreAndChain()
	name := z.Name
	if st == nil {
		return nil
	}
	if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
		return err
	}
	path := snapFile(cfg.Dir, name)
	if cfg.MinInterval.Duration() > 0 {
		if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) < cfg.MinInterval.Duration() {
			return nil
		}
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	err = st.WriteSnapshot(f)
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func ReadSnapshot(cfg config.SnapshotConfig, name string) (*zone.Store, time.Time, error) {
	if !cfg.Enabled || cfg.Dir == "" {
		return nil, time.Time{}, os.ErrNotExist
	}
	path := snapFile(cfg.Dir, name)
	f, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer f.Close()
	return zone.ReadSnapshot(f)
}

func snapFile(dir, name string) string {
	safe := strings.TrimSuffix(name, ".")
	safe = strings.ReplaceAll(safe, "/", "_")
	if safe == "" {
		safe = "zone"
	}
	return filepath.Join(dir, safe+".snap")
}
