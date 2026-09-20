import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['frontend/__tests__/**/*.test.ts'],
    environment: 'node',
  },
});
