import { describe, expect, it } from 'vitest';
import {
  compareZones,
  defaultSortDir,
  formatLastValid,
  formatLastValidTitle,
  formatLocalTime,
  formatRelativeTime,
  formatStateRatio,
  formatSigning,
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
