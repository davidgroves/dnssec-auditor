import type { AppState } from '../state';
import type { ThemeConfig } from '../types';

export type ThemeContext = AppState & {
  applyThemeFromConfig: (cfg: ThemeConfig) => void;
  toggleThemeMode: () => void;
};

export function createThemeMethods() {
  return {
    applyThemeFromConfig(this: ThemeContext, cfg: ThemeConfig) {
      const mode = this.themeMode;
      document.documentElement.dataset.theme = mode;
      if (!cfg.dark && !cfg.light) {
        return;
      }
      const tokens = mode === 'dark' ? cfg.dark : cfg.light;
      let el = document.getElementById('theme-overrides');
      if (!el) {
        el = document.createElement('style');
        el.id = 'theme-overrides';
        document.head.appendChild(el);
      }
      const body = Object.entries(tokens ?? {})
        .map(([k, v]) => `${k}: ${v};`)
        .join(' ');
      el.textContent = `:root[data-theme="${mode}"] { ${body} }`;
    },
    toggleThemeMode(this: ThemeContext) {
      this.themeMode = this.themeMode === 'dark' ? 'light' : 'dark';
      localStorage.setItem('dnssec-auditor.themeMode', this.themeMode);
      this.applyThemeFromConfig(this.config);
    },
  };
}

export function resolveInitialMode(cfg: ThemeConfig): 'dark' | 'light' {
  const stored = localStorage.getItem('dnssec-auditor.themeMode');
  if (stored === 'dark' || stored === 'light') {
    return stored;
  }
  if (cfg.default_mode === 'light' || cfg.default_mode === 'dark') {
    return cfg.default_mode;
  }
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}
