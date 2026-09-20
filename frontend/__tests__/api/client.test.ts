import { describe, expect, it, vi } from 'vitest';
import { api } from '../../api/client';

describe('api client', () => {
  it('throws on non-OK', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      text: async () => 'boom',
    }));
    await expect(api('/v1/zones')).rejects.toThrow('500');
    vi.unstubAllGlobals();
  });

  it('parses JSON', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ zones: [] }),
    }));
    await expect(api<{ zones: unknown[] }>('/v1/zones')).resolves.toEqual({ zones: [] });
    vi.unstubAllGlobals();
  });
});
