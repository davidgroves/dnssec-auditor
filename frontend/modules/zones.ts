import { api } from '../api/client';
import type { AppState, AttentionSortKey, CatalogView, SortDir, SortKey, ZoneSortKey } from '../state';
import type { ZoneView } from '../types';

export type ZoneContext = AppState & {
  toast: (msg: string, type: 'success' | 'error' | 'warning') => void;
  loadZones: (retries?: number) => Promise<void>;
  openZone: (name: string, opts?: { replace?: boolean }) => Promise<void>;
  refreshZone: (name: string, full?: boolean) => Promise<void>;
  downloadZone: (name: string) => Promise<void>;
  syncUrl?: (replace?: boolean) => void;
  show?: (view: AppState['view'], opts?: { replace?: boolean }) => void;
  filteredZones: () => ZoneView[];
  attentionZones: () => ZoneView[];
  sortBy: (key: ZoneSortKey) => void;
  sortIndicator: (key: ZoneSortKey) => string;
  attentionSortBy: (key: AttentionSortKey) => void;
  attentionSortIndicator: (key: AttentionSortKey) => string;
  stateRatio: (state: string) => string;
  formatLocalTime: (value: string | null | undefined) => string;
  formatRelativeTime: (value: string | null | undefined) => string;
  formatLastValid: (value: string | null | undefined) => string;
  formatLastValidTitle: (value: string | null | undefined) => string;
  formatSigning: (value: string | null | undefined) => string;
  isFullVerifyInProgress: (z: ZoneView | null | undefined) => boolean;
  fullVerifyButtonLabel: (z: ZoneView | null | undefined) => string;
};

/** True while the backend is running a full re-verify for this zone. */
export function isFullVerifyInProgress(z: ZoneView | null | undefined): boolean {
  return Boolean(z?.refresh_full);
}

export function fullVerifyButtonLabel(z: ZoneView | null | undefined): string {
  return isFullVerifyInProgress(z) ? 'full verify in progress' : 'Full re-verify';
}

/** Format a dashboard card as "13/32". */
export function formatStateRatio(count: number, total: number): string {
  return `${count}/${total}`;
}

function parseTimeMs(value: string | null | undefined): number | null {
  if (!value) {
    return null;
  }
  const t = new Date(value).getTime();
  if (Number.isNaN(t)) {
    return null;
  }
  return t;
}

/** Format an API timestamp in the browser's local timezone, truncated to seconds. */
export function formatLocalTime(value: string | null | undefined): string {
  const t = parseTimeMs(value);
  if (t === null || t <= 0) {
    return '';
  }
  return new Date(t).toLocaleString(undefined, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function plural(n: number, unit: string): string {
  return `${n} ${unit}${n === 1 ? '' : 's'}`;
}

/**
 * Human-friendly relative time: "5 mins ago" / "in 3 mins".
 * `nowMs` is injectable for tests.
 */
export function formatRelativeTime(value: string | null | undefined, nowMs: number = Date.now()): string {
  const t = parseTimeMs(value);
  if (t === null || t <= 0) {
    return '';
  }
  const delta = t - nowMs;
  const absSec = Math.round(Math.abs(delta) / 1000);
  if (absSec < 5) {
    return 'just now';
  }

  let amount: number;
  let unit: string;
  if (absSec < 60) {
    amount = absSec;
    unit = 'sec';
  } else if (absSec < 3600) {
    amount = Math.round(absSec / 60);
    unit = 'min';
  } else if (absSec < 86400) {
    amount = Math.round(absSec / 3600);
    unit = 'hour';
  } else {
    amount = Math.round(absSec / 86400);
    unit = 'day';
  }
  const label = plural(amount, unit);
  return delta < 0 ? `${label} ago` : `in ${label}`;
}

/** Last-valid column: unix epoch 0 / unset / invalid → "never". */
export function formatLastValid(value: string | null | undefined, nowMs: number = Date.now()): string {
  const t = parseTimeMs(value);
  if (t === null || t <= 0) {
    return 'never';
  }
  return formatRelativeTime(value, nowMs);
}

/** Tooltip for last-valid: exact local time, or empty when "never". */
export function formatLastValidTitle(value: string | null | undefined): string {
  return formatLocalTime(value);
}

/** Display label for zone signing / denial style. */
export function formatSigning(value: string | null | undefined): string {
  switch (value) {
    case 'nsec':
      return 'NSEC';
    case 'nsec3':
      return 'NSEC3';
    case 'mixed':
      return 'Mixed';
    case 'unsigned':
      return 'Unsigned';
    default:
      return value || 'Unsigned';
  }
}

function timeSortValue(value: string | null | undefined): number {
  const t = parseTimeMs(value);
  if (t === null || t <= 0) {
    return Number.NEGATIVE_INFINITY;
  }
  return t;
}

/** Compare two zones for a column. Returns negative if a < b. */
export function compareZones(a: ZoneView, b: ZoneView, key: SortKey, dir: SortDir): number {
  let cmp = 0;
  switch (key) {
    case 'name':
      cmp = a.name.localeCompare(b.name);
      break;
    case 'state':
      cmp = a.state.localeCompare(b.state);
      break;
    case 'serial':
      cmp = a.serial - b.serial;
      break;
    case 'last_valid_at':
      cmp = timeSortValue(a.last_valid_at) - timeSortValue(b.last_valid_at);
      break;
    case 'last_full_verified_at':
      cmp = timeSortValue(a.last_full_verified_at) - timeSortValue(b.last_full_verified_at);
      break;
    case 'next_refresh':
      cmp = timeSortValue(a.next_refresh) - timeSortValue(b.next_refresh);
      break;
    case 'errors':
      cmp = a.error_count - b.error_count;
      if (cmp === 0) {
        cmp = a.warning_count - b.warning_count;
      }
      break;
    case 'warnings':
      cmp = a.warning_count - b.warning_count;
      break;
  }
  if (cmp === 0 && key !== 'name') {
    cmp = a.name.localeCompare(b.name);
  }
  return dir === 'asc' ? cmp : -cmp;
}

/** First-click direction for a newly selected column. */
export function defaultSortDir(key: SortKey): SortDir {
  return key === 'name' || key === 'state' ? 'asc' : 'desc';
}

function toggleSort<K extends SortKey>(currentKey: K, currentDir: SortDir, key: K): { key: K; dir: SortDir } {
  if (currentKey === key) {
    return { key: currentKey, dir: currentDir === 'asc' ? 'desc' : 'asc' };
  }
  return { key, dir: defaultSortDir(key) };
}

function formatSortIndicator(currentKey: SortKey, currentDir: SortDir, key: SortKey): string {
  if (currentKey !== key) {
    return '';
  }
  return currentDir === 'asc' ? ' ▲' : ' ▼';
}

export function createZoneMethods() {
  return {
    formatLocalTime,
    formatRelativeTime,
    formatLastValid,
    formatLastValidTitle,
    formatSigning,
    isFullVerifyInProgress,
    fullVerifyButtonLabel,
    sortBy(this: ZoneContext, key: ZoneSortKey) {
      const next = toggleSort(this.sortKey, this.sortDir, key);
      this.sortKey = next.key;
      this.sortDir = next.dir;
    },
    sortIndicator(this: ZoneContext, key: ZoneSortKey) {
      return formatSortIndicator(this.sortKey, this.sortDir, key);
    },
    attentionSortBy(this: ZoneContext, key: AttentionSortKey) {
      const next = toggleSort(this.attentionSortKey, this.attentionSortDir, key);
      this.attentionSortKey = next.key;
      this.attentionSortDir = next.dir;
    },
    attentionSortIndicator(this: ZoneContext, key: AttentionSortKey) {
      return formatSortIndicator(this.attentionSortKey, this.attentionSortDir, key);
    },
    async loadZones(this: ZoneContext, retries = 0) {
      this.loading = true;
      let lastErr: unknown;
      for (let i = 0; i <= retries; i++) {
        try {
          const data = await api<{ zones: ZoneView[] }>('/v1/zones');
          this.zones = data.zones ?? [];
          const counts: Record<string, number> = {};
          for (const z of this.zones) {
            counts[z.state] = (counts[z.state] ?? 0) + 1;
          }
          this.counts = counts;
          try {
            const cats = await api<{ catalogs: CatalogView[] }>('/v1/catalogs');
            this.catalogs = cats.catalogs ?? [];
          } catch {
            this.catalogs = [];
          }
          lastErr = undefined;
          break;
        } catch (err) {
          lastErr = err;
          if (i < retries) {
            await new Promise((resolve) => setTimeout(resolve, 500));
          }
        }
      }
      if (lastErr) {
        this.toast(`Failed to load zones: ${lastErr}`, 'error');
      }
      this.loading = false;
    },
    async openZone(this: ZoneContext, name: string) {
      try {
        this.selected = await api<ZoneView>(`/v1/zones/${encodeURIComponent(name)}`);
        this.view = 'detail';
      } catch (err) {
        this.toast(`Failed to load ${name}: ${err}`, 'error');
      }
    },
    async refreshZone(this: ZoneContext, name: string, full = false) {
      if (full && this.selected?.name === name && isFullVerifyInProgress(this.selected)) {
        return;
      }
      try {
        await api(`/v1/zones/${encodeURIComponent(name)}/refresh${full ? '?full=true' : ''}`, {
          method: 'POST',
        });
        if (full) {
          this.toast(`Asked for a full verify of ${name}`, 'success');
          if (this.selected?.name === name) {
            this.selected = { ...this.selected, refreshing: true, refresh_full: true };
          }
          this.zones = this.zones.map((z) =>
            z.name === name ? { ...z, refreshing: true, refresh_full: true } : z,
          );
        } else {
          this.toast(`Refresh queued for ${name}`, 'success');
        }
        setTimeout(() => {
          void this.loadZones();
          if (this.selected?.name === name) {
            void this.openZone(name, { replace: true });
          }
        }, 1500);
      } catch (err) {
        this.toast(`Refresh failed: ${err}`, 'error');
      }
    },
    async downloadZone(this: ZoneContext, name: string) {
      try {
        const res = await fetch(`/v1/zones/${encodeURIComponent(name)}/dump`);
        if (!res.ok) {
          const text = await res.text();
          throw new Error(`${res.status} ${text}`);
        }
        const blob = await res.blob();
        const cd = res.headers.get('Content-Disposition') ?? '';
        const match = /filename="([^"]+)"/.exec(cd);
        const filename = match?.[1] ?? `${name.replace(/\.$/, '')}.txt`;
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      } catch (err) {
        this.toast(`Download failed: ${err}`, 'error');
      }
    },
    stateRatio(this: ZoneContext, state: string) {
      return formatStateRatio(this.counts[state] ?? 0, this.zones.length);
    },
    filteredZones(this: ZoneContext) {
      const q = this.filter.toLowerCase();
      return this.zones
        .filter((z) => !q || z.name.includes(q) || z.state.includes(q))
        .slice()
        .sort((a, b) => compareZones(a, b, this.sortKey, this.sortDir));
    },
    attentionZones(this: ZoneContext) {
      return this.zones
        .filter((z) => !z.valid)
        .slice()
        .sort((a, b) => compareZones(a, b, this.attentionSortKey, this.attentionSortDir));
    },
  };
}
