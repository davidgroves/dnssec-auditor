import Alpine from 'alpinejs';
import { createApp } from './app';
import type { AppConfig } from './types';
import './styles/app.css';

declare global {
  interface Window {
    Alpine: typeof Alpine;
    createDnssecApp: (config: AppConfig) => ReturnType<typeof createApp>;
  }
}

export function createDnssecApp(config: AppConfig) {
  return createApp(config);
}

window.Alpine = Alpine;
window.createDnssecApp = createDnssecApp;
Alpine.start();

export { createApp };
export type { AppConfig } from './types';
