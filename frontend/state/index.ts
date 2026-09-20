import { emptyMemory, type AppConfig, type MemoryView, type ZoneView } from '../types';

export type CatalogView = {
  name: string;
  members: string[];
};

export type ZoneSortKey =
  | 'name'
  | 'state'
  | 'serial'
  | 'last_valid_at'
  | 'last_full_verified_at'
  | 'next_refresh'
  | 'errors';
export type SortDir = 'asc' | 'desc';

export type AppState = {
  config: AppConfig;
  themeMode: 'dark' | 'light';
  loading: boolean;
  zones: ZoneView[];
  catalogs: CatalogView[];
  selected: ZoneView | null;
  view: 'dashboard' | 'zones' | 'detail' | 'catalogs';
  toastMessage: string;
  toastType: 'success' | 'error' | 'warning' | '';
  filter: string;
  sortKey: ZoneSortKey;
  sortDir: SortDir;
  counts: Record<string, number>;
  memory: MemoryView;
};

export function createInitialState(config: AppConfig): AppState {
  return {
    config,
    themeMode: config.default_mode === 'light' ? 'light' : 'dark',
    loading: false,
    zones: [],
    catalogs: [],
    selected: null,
    view: 'dashboard',
    toastMessage: '',
    toastType: '',
    filter: '',
    sortKey: 'name',
    sortDir: 'asc',
    counts: {},
    memory: emptyMemory(),
  };
}
