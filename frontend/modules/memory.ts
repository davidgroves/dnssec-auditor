import { api } from '../api/client';
import type { AppState } from '../state';
import type { MemoryView } from '../types';

export type MemoryContext = AppState & {
  loadMemory: () => Promise<void>;
  formatBytes: (n: number) => string;
};

/** Format a byte count as "12.4 MiB". */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n <= 0) {
    return '0 B';
  }
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  if (i === 0) {
    return `${Math.round(v)} B`;
  }
  const digits = v >= 10 ? 1 : 2;
  return `${v.toFixed(digits)} ${units[i]}`;
}

export function createMemoryMethods() {
  return {
    formatBytes,
    async loadMemory(this: MemoryContext) {
      try {
        this.memory = await api<MemoryView>('/v1/memory');
      } catch {
        // Keep the last snapshot; cards stay at 0 B until the first success.
      }
    },
  };
}
