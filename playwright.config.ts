import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: 'frontend/__tests__/e2e',
  fullyParallel: false,
  workers: 1,
  use: {
    baseURL: 'http://localhost:5173',
  },
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:5173',
    reuseExistingServer: true,
  },
});
