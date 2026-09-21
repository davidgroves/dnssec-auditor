import { describe, expect, it } from 'vitest';
import { buildPath, canonicalizeZone, encodeZonePath, parsePath, routeFromState } from '../../modules/router';

describe('canonicalizeZone', () => {
  it('adds a trailing dot', () => {
    expect(canonicalizeZone('broken.example')).toBe('broken.example.');
    expect(canonicalizeZone('broken.example.')).toBe('broken.example.');
  });
});

describe('parsePath', () => {
  it('maps top-level pages', () => {
    expect(parsePath('/')).toEqual({ view: 'dashboard' });
    expect(parsePath('/zones')).toEqual({ view: 'zones' });
    expect(parsePath('/zones/')).toEqual({ view: 'zones' });
    expect(parsePath('/catalogs')).toEqual({ view: 'catalogs' });
  });

  it('parses zone detail paths', () => {
    expect(parsePath('/zones/broken.example.')).toEqual({
      view: 'detail',
      zone: 'broken.example.',
    });
    expect(parsePath('/zones/broken.example')).toEqual({
      view: 'detail',
      zone: 'broken.example.',
    });
    expect(parsePath('/zones/foo%2Fbar.example.')).toEqual({
      view: 'detail',
      zone: 'foo/bar.example.',
    });
  });

  it('falls back for unknown paths', () => {
    expect(parsePath('/nope')).toEqual({ view: 'dashboard' });
  });
});

describe('buildPath', () => {
  it('builds paths for each view', () => {
    expect(buildPath({ view: 'dashboard' })).toBe('/');
    expect(buildPath({ view: 'zones' })).toBe('/zones');
    expect(buildPath({ view: 'catalogs' })).toBe('/catalogs');
    expect(buildPath({ view: 'detail', zone: 'broken.example.' })).toBe('/zones/broken.example');
  });
});

describe('encodeZonePath', () => {
  it('drops the trailing DNS dot so SPA hosts do not treat the path as a file', () => {
    expect(encodeZonePath('dnskey-zskonly.example.')).toBe('dnskey-zskonly.example');
    expect(encodeZonePath('dnskey-zskonly.example')).toBe('dnskey-zskonly.example');
  });
});

describe('routeFromState', () => {
  it('uses selected zone for detail', () => {
    expect(routeFromState('detail', 'a.example.')).toEqual({
      view: 'detail',
      zone: 'a.example.',
    });
    expect(routeFromState('detail', null)).toEqual({ view: 'zones' });
  });
});
