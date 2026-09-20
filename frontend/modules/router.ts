export type AppView = 'dashboard' | 'zones' | 'detail' | 'catalogs';

export type Route =
  | { view: 'dashboard' }
  | { view: 'zones' }
  | { view: 'catalogs' }
  | { view: 'detail'; zone: string };

/** Normalize a zone name to a trailing-dot FQDN. */
export function canonicalizeZone(name: string): string {
  const trimmed = name.trim();
  if (!trimmed) {
    return trimmed;
  }
  return trimmed.endsWith('.') ? trimmed : `${trimmed}.`;
}

/**
 * Parse a URL pathname into an app route.
 * Pure — safe for unit tests without `window`.
 */
export function parsePath(pathname: string): Route {
  let path = pathname.trim();
  if (path.length > 1 && path.endsWith('/')) {
    path = path.slice(0, -1);
  }
  if (path === '' || path === '/') {
    return { view: 'dashboard' };
  }
  if (path === '/zones') {
    return { view: 'zones' };
  }
  if (path === '/catalogs') {
    return { view: 'catalogs' };
  }
  if (path.startsWith('/zones/')) {
    const raw = path.slice('/zones/'.length);
    if (raw) {
      try {
        return { view: 'detail', zone: canonicalizeZone(decodeURIComponent(raw)) };
      } catch {
        return { view: 'zones' };
      }
    }
  }
  return { view: 'dashboard' };
}

/** Build a pathname for a route. */
export function buildPath(route: Route): string {
  switch (route.view) {
    case 'dashboard':
      return '/';
    case 'zones':
      return '/zones';
    case 'catalogs':
      return '/catalogs';
    case 'detail':
      return `/zones/${encodeURIComponent(canonicalizeZone(route.zone))}`;
  }
}

export function routeFromState(view: AppView, selectedName: string | null | undefined): Route {
  if (view === 'detail' && selectedName) {
    return { view: 'detail', zone: selectedName };
  }
  if (view === 'detail') {
    return { view: 'zones' };
  }
  return { view };
}

/** Update the address bar; no-ops when already at `path`. */
export function syncBrowserUrl(path: string, replace = false): void {
  if (typeof window === 'undefined') {
    return;
  }
  if (window.location.pathname === path) {
    return;
  }
  if (replace) {
    window.history.replaceState(null, '', path);
  } else {
    window.history.pushState(null, '', path);
  }
}
