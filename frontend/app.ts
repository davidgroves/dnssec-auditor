import { api } from './api/client';
import { createMemoryMethods } from './modules/memory';
import {
  buildPath,
  parsePath,
  routeFromState,
  syncBrowserUrl,
  type Route,
} from './modules/router';
import { createThemeMethods, resolveInitialMode } from './modules/theme';
import { createZoneMethods } from './modules/zones';
import { createInitialState } from './state';
import type { AppConfig, ThemeConfig } from './types';

type NavOpts = { replace?: boolean };

// Alpine binds methods onto a single reactive object; keep the factory loosely typed.
export function createApp(config: AppConfig): Record<string, unknown> {
  const state = createInitialState(config);
  const zoneMethods = createZoneMethods();
  // Alpine provides `this` at runtime.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const methods: Record<string, any> = {
    ...createThemeMethods(),
    ...zoneMethods,
    ...createMemoryMethods(),
    toast(msg: string, type: 'success' | 'error' | 'warning') {
      this.toastMessage = msg;
      this.toastType = type;
      setTimeout(() => {
        this.toastMessage = '';
        this.toastType = '';
      }, 4000);
    },
    syncUrl(replace = false) {
      const route = routeFromState(this.view, this.selected?.name);
      syncBrowserUrl(buildPath(route), replace);
    },
    show(view: typeof state.view, opts: NavOpts = {}) {
      if (view === 'detail') {
        this.view = 'zones';
        this.selected = null;
      } else {
        this.selected = null;
        this.view = view;
      }
      this.syncUrl(opts.replace === true);
    },
    async openZone(name: string, opts: NavOpts = {}) {
      await zoneMethods.openZone.call(this as never, name);
      if (this.view === 'detail' && this.selected) {
        this.syncUrl(opts.replace === true);
      }
    },
    zoneHref(name: string) {
      return buildPath({ view: 'detail', zone: name });
    },
    async applyRoute(route: Route, replace = true) {
      switch (route.view) {
        case 'dashboard':
        case 'zones':
        case 'catalogs':
          this.selected = null;
          this.view = route.view;
          this.syncUrl(replace);
          return;
        case 'detail':
          await this.openZone(route.zone, { replace });
          if (this.view !== 'detail') {
            this.selected = null;
            this.view = 'zones';
            this.syncUrl(true);
          }
          return;
      }
    },
    async init() {
      try {
        const cfg = await api<ThemeConfig>('/ui/config');
        this.config = { ...this.config, ...cfg };
        this.themeMode = resolveInitialMode(this.config);
        this.applyThemeFromConfig(this.config);
      } catch {
        this.applyThemeFromConfig(this.config);
      }
      await this.loadZones(20);
      await this.loadMemory();
      await this.applyRoute(parsePath(window.location.pathname), true);
      window.addEventListener('popstate', () => {
        void this.applyRoute(parsePath(window.location.pathname), true);
      });
      this.listenEvents();
      setInterval(() => {
        void this.loadZones();
        void this.loadMemory();
      }, 15000);
    },
    listenEvents() {
      try {
        const es = new EventSource('/v1/events');
        es.onmessage = () => {
          void this.loadZones();
          if (this.selected) {
            void this.openZone(this.selected.name, { replace: true });
          }
        };
      } catch {
        // polling fallback already in init
      }
    },
  };
  return Object.assign(state, methods);
}
