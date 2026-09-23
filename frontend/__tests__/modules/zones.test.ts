import { describe, expect, it, vi } from 'vitest';
import {
  compareZones,
  createZoneMethods,
  defaultSortDir,
  formatLastValid,
  formatLastValidTitle,
  formatLocalTime,
  formatRelativeTime,
  formatStateRatio,
  formatSigning,
  fullVerifyButtonLabel,
  isFullVerifyInProgress,
} from '../../modules/zones';
import type { ZoneView } from '../../types';

function zone(partial: Partial<ZoneView> & Pick<ZoneView, 'name'>): ZoneView {
  return {
    source: 'config',
    state: 'valid',
    valid: true,
    unsigned: false,
    serial: 1,
    records: 0,
    rrsigs: 0,
    nsec3: 0,
    last_valid_at: '',
    last_verified: '',
    last_transfer: '',
    next_refresh: '',
    verify_mode: '',
    last_method: '',
    error_count: 0,
    warning_count: 0,
    zonemd_stale: false,
    signing: 'nsec3',
    ...partial,
  };
}

describe('formatStateRatio', () => {
  it('formats count over total', () => {
    expect(formatStateRatio(13, 32)).toBe('13/32');
    expect(formatStateRatio(0, 32)).toBe('0/32');
    expect(formatStateRatio(0, 0)).toBe('0/0');
  });
});

describe('formatLocalTime', () => {
  it('returns empty for missing, invalid, or unix epoch 0', () => {
    expect(formatLocalTime(undefined)).toBe('');
    expect(formatLocalTime(null)).toBe('');
    expect(formatLocalTime('')).toBe('');
    expect(formatLocalTime('not-a-date')).toBe('');
    expect(formatLocalTime('1970-01-01T00:00:00Z')).toBe('');
  });

  it('formats UTC timestamps in local time to the second', () => {
    const out = formatLocalTime('2026-09-18T12:34:56.789Z');
    expect(out).toMatch(/\d/);
    expect(out).not.toMatch(/Z$/);
    expect(out).not.toMatch(/\.\d{3}/);
    const parsed = new Date('2026-09-18T12:34:56.789Z');
    expect(out).toBe(
      parsed.toLocaleString(undefined, {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      }),
    );
  });
});

describe('formatRelativeTime', () => {
  const now = Date.parse('2026-09-18T12:00:00Z');

  it('returns empty for missing or epoch 0', () => {
    expect(formatRelativeTime(undefined, now)).toBe('');
    expect(formatRelativeTime('1970-01-01T00:00:00Z', now)).toBe('');
  });

  it('formats past times', () => {
    expect(formatRelativeTime('2026-09-18T11:55:00Z', now)).toBe('5 mins ago');
    expect(formatRelativeTime('2026-09-18T11:59:00Z', now)).toBe('1 min ago');
    expect(formatRelativeTime('2026-09-18T10:00:00Z', now)).toBe('2 hours ago');
  });

  it('formats future times', () => {
    expect(formatRelativeTime('2026-09-18T12:03:00Z', now)).toBe('in 3 mins');
    expect(formatRelativeTime('2026-09-18T13:00:00Z', now)).toBe('in 1 hour');
  });

  it('uses just now for very recent deltas', () => {
    expect(formatRelativeTime('2026-09-18T12:00:02Z', now)).toBe('just now');
    expect(formatRelativeTime('2026-09-18T11:59:58Z', now)).toBe('just now');
  });
});

describe('formatLastValid', () => {
  const now = Date.parse('2026-09-18T12:00:00Z');

  it('shows never for unset, invalid, or unix epoch 0', () => {
    expect(formatLastValid(undefined, now)).toBe('never');
    expect(formatLastValid(null, now)).toBe('never');
    expect(formatLastValid('', now)).toBe('never');
    expect(formatLastValid('not-a-date', now)).toBe('never');
    expect(formatLastValid('1970-01-01T00:00:00Z', now)).toBe('never');
  });

  it('shows relative past times', () => {
    expect(formatLastValid('2026-09-18T11:55:00Z', now)).toBe('5 mins ago');
  });

  it('tooltip is exact local time when set, empty when never', () => {
    expect(formatLastValidTitle('1970-01-01T00:00:00Z')).toBe('');
    expect(formatLastValidTitle('2026-09-18T12:34:56Z')).toBe(formatLocalTime('2026-09-18T12:34:56Z'));
  });
});

describe('compareZones', () => {
  it('sorts by name and uses name as tie-breaker', () => {
    const a = zone({ name: 'a.example.', serial: 2 });
    const b = zone({ name: 'b.example.', serial: 1 });
    expect(compareZones(a, b, 'name', 'asc')).toBeLessThan(0);
    expect(compareZones(a, b, 'name', 'desc')).toBeGreaterThan(0);
    expect(compareZones(a, b, 'serial', 'asc')).toBeGreaterThan(0);
  });

  it('sorts errors then warnings', () => {
    const a = zone({ name: 'a.example.', error_count: 1, warning_count: 5 });
    const b = zone({ name: 'b.example.', error_count: 2, warning_count: 0 });
    expect(compareZones(a, b, 'errors', 'asc')).toBeLessThan(0);
    expect(compareZones(a, b, 'errors', 'desc')).toBeGreaterThan(0);
  });

  it('sorts warnings independently of errors', () => {
    const a = zone({ name: 'a.example.', error_count: 9, warning_count: 1 });
    const b = zone({ name: 'b.example.', error_count: 0, warning_count: 4 });
    expect(compareZones(a, b, 'warnings', 'asc')).toBeLessThan(0);
    expect(compareZones(a, b, 'warnings', 'desc')).toBeGreaterThan(0);
  });

  it('treats missing last_valid as oldest', () => {
    const never = zone({ name: 'n.example.', last_valid_at: '1970-01-01T00:00:00Z' });
    const recent = zone({ name: 'r.example.', last_valid_at: '2026-09-18T12:00:00Z' });
    expect(compareZones(never, recent, 'last_valid_at', 'asc')).toBeLessThan(0);
  });
});

describe('defaultSortDir', () => {
  it('uses asc for labels and desc for metrics', () => {
    expect(defaultSortDir('name')).toBe('asc');
    expect(defaultSortDir('state')).toBe('asc');
    expect(defaultSortDir('serial')).toBe('desc');
    expect(defaultSortDir('errors')).toBe('desc');
    expect(defaultSortDir('warnings')).toBe('desc');
  });
});

describe('attentionZones', () => {
  it('omits valid zones and sorts alphabetically by default', () => {
    const methods = createZoneMethods();
    const ctx = {
      zones: [
        zone({ name: 'z.example.', valid: false, state: 'invalid' }),
        zone({ name: 'ok.example.', valid: true, state: 'valid' }),
        zone({ name: 'a.example.', valid: false, state: 'stale' }),
      ],
      attentionSortKey: 'name' as const,
      attentionSortDir: 'asc' as const,
    };
    expect(methods.attentionZones.call(ctx as never).map((z) => z.name)).toEqual([
      'a.example.',
      'z.example.',
    ]);
  });

  it('keeps a stable order when the source array is shuffled', () => {
    const methods = createZoneMethods();
    const a = zone({ name: 'a.example.', valid: false });
    const b = zone({ name: 'b.example.', valid: false });
    const ctx = {
      zones: [b, a],
      attentionSortKey: 'name' as const,
      attentionSortDir: 'asc' as const,
    };
    expect(methods.attentionZones.call(ctx as never).map((z) => z.name)).toEqual([
      'a.example.',
      'b.example.',
    ]);
    ctx.zones = [a, b];
    expect(methods.attentionZones.call(ctx as never).map((z) => z.name)).toEqual([
      'a.example.',
      'b.example.',
    ]);
  });

  it('sorts independently of the zones table', () => {
    const methods = createZoneMethods();
    const ctx = {
      zones: [
        zone({ name: 'a.example.', valid: false, error_count: 1 }),
        zone({ name: 'b.example.', valid: false, error_count: 5 }),
      ],
      sortKey: 'name' as const,
      sortDir: 'asc' as const,
      attentionSortKey: 'name' as const,
      attentionSortDir: 'asc' as const,
    };
    methods.attentionSortBy.call(ctx as never, 'errors');
    expect(ctx.attentionSortKey).toBe('errors');
    expect(ctx.attentionSortDir).toBe('desc');
    expect(ctx.sortKey).toBe('name');
    expect(methods.attentionZones.call(ctx as never).map((z) => z.name)).toEqual([
      'b.example.',
      'a.example.',
    ]);
    expect(methods.attentionSortIndicator.call(ctx as never, 'errors')).toBe(' ▼');
    expect(methods.attentionSortIndicator.call(ctx as never, 'name')).toBe('');
  });
});

describe('formatSigning', () => {
  it('maps API values to display labels', () => {
    expect(formatSigning('unsigned')).toBe('Unsigned');
    expect(formatSigning('nsec')).toBe('NSEC');
    expect(formatSigning('nsec3')).toBe('NSEC3');
    expect(formatSigning('mixed')).toBe('Mixed');
    expect(formatSigning(undefined)).toBe('Unsigned');
  });
});

describe('isFullVerifyInProgress', () => {
  it('is true only while the backend reports an in-flight full verify', () => {
    expect(isFullVerifyInProgress(undefined)).toBe(false);
    expect(isFullVerifyInProgress(null)).toBe(false);
    expect(isFullVerifyInProgress(zone({ name: 'a.example.' }))).toBe(false);
    expect(isFullVerifyInProgress(zone({ name: 'a.example.', refreshing: true }))).toBe(false);
    expect(isFullVerifyInProgress(zone({ name: 'a.example.', refresh_full: true }))).toBe(true);
    expect(fullVerifyButtonLabel(zone({ name: 'a.example.' }))).toBe('Full re-verify');
    expect(fullVerifyButtonLabel(zone({ name: 'a.example.', refresh_full: true }))).toBe(
      'full verify in progress',
    );
  });
});

describe('refreshZone', () => {
  it('toasts when a full verify is requested and marks the zone in progress', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 202,
      json: async () => ({ status: 'refreshing', full: true }),
    });
    vi.stubGlobal('fetch', fetchMock);
    const methods = createZoneMethods();
    const toast = vi.fn();
    const selected = zone({ name: 'dnskey-zskonly.example.' });
    const ctx = {
      selected,
      zones: [selected],
      toast,
      loadZones: vi.fn(),
      openZone: vi.fn(),
    };
    await methods.refreshZone.call(ctx as never, 'dnskey-zskonly.example.', true);
    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/zones/dnskey-zskonly.example./refresh?full=true',
      expect.objectContaining({ method: 'POST' }),
    );
    expect(toast).toHaveBeenCalledWith(
      'Asked for a full verify of dnskey-zskonly.example.',
      'success',
    );
    expect(ctx.selected.refresh_full).toBe(true);
    expect(ctx.selected.refreshing).toBe(true);
    expect(ctx.zones[0].refresh_full).toBe(true);
    vi.unstubAllGlobals();
  });

  it('does not request a full verify when one is already in progress', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const methods = createZoneMethods();
    const toast = vi.fn();
    const selected = zone({ name: 'dnskey-zskonly.example.', refresh_full: true });
    const ctx = {
      selected,
      zones: [selected],
      toast,
      loadZones: vi.fn(),
      openZone: vi.fn(),
    };
    await methods.refreshZone.call(ctx as never, 'dnskey-zskonly.example.', true);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(toast).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it('keeps the queued refresh toast for incremental refresh', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 202,
      json: async () => ({ status: 'refreshing', full: false }),
    });
    vi.stubGlobal('fetch', fetchMock);
    const methods = createZoneMethods();
    const toast = vi.fn();
    const selected = zone({ name: 'example.com.' });
    const ctx = {
      selected,
      zones: [selected],
      toast,
      loadZones: vi.fn(),
      openZone: vi.fn(),
    };
    await methods.refreshZone.call(ctx as never, 'example.com.');
    expect(toast).toHaveBeenCalledWith('Refresh queued for example.com.', 'success');
    expect(ctx.selected.refresh_full).toBeUndefined();
    vi.unstubAllGlobals();
  });
});

describe('loadZones', () => {
  it('retries until the API is up', async () => {
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new Error('connect ECONNREFUSED'))
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ zones: [{ name: 'example.com.', state: 'valid' }] }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ catalogs: [] }),
      });
    vi.stubGlobal('fetch', fetchMock);
    const methods = createZoneMethods();
    const toast = vi.fn();
    const ctx = {
      loading: false,
      zones: [] as { name: string; state: string }[],
      catalogs: [] as unknown[],
      counts: {} as Record<string, number>,
      toast,
    };
    await methods.loadZones.call(ctx as never, 3);
    expect(ctx.zones).toEqual([{ name: 'example.com.', state: 'valid' }]);
    expect(ctx.counts).toEqual({ valid: 1 });
    expect(toast).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });
});
