import { describe, expect, it } from 'vitest';
import { formatBytes } from '../../modules/memory';

describe('formatBytes', () => {
  it('formats zero and invalid as 0 B', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(-1)).toBe('0 B');
    expect(formatBytes(Number.NaN)).toBe('0 B');
  });

  it('formats bytes and kibibytes', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1024)).toBe('1.00 KiB');
    expect(formatBytes(12.4 * 1024 * 1024)).toBe('12.4 MiB');
  });
});
