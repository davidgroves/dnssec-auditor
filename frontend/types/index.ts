export type ThemeConfig = {
  app_name?: string;
  default_mode?: 'dark' | 'light';
  allow_mode_toggle?: boolean;
  logo?: string;
  dark?: Record<string, string>;
  light?: Record<string, string>;
};

export type Finding = {
  code: string;
  severity: 'error' | 'warning';
  owner: string;
  rrtype: number;
  rrtype_name: string;
  message: string;
  first_seen: string;
  last_seen: string;
};

export type ServerStatus = {
  name: string;
  serial: number;
  reachable: boolean;
  rtt_ns: number;
  error?: string;
};

export type SOAInfo = {
  mname: string;
  rname: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  minimum: number;
};

export type ZoneView = {
  name: string;
  source: string;
  state: string;
  valid: boolean;
  unsigned: boolean;
  serial: number;
  records: number;
  rrsigs: number;
  nsec3: number;
  signing: 'unsigned' | 'nsec' | 'nsec3' | 'mixed' | string;
  last_valid_at: string;
  last_verified: string;
  last_full_verified_at?: string;
  last_transfer: string;
  next_refresh: string;
  verify_mode: string;
  last_method: string;
  refreshing?: boolean;
  refresh_full?: boolean;
  error_count: number;
  warning_count: number;
  findings?: Finding[];
  servers?: ServerStatus[];
  soa?: SOAInfo;
  chain_of_trust_ok?: boolean;
  zonemd_ok?: boolean;
  zonemd_checked_at?: string;
  zonemd_stale: boolean;
};

export type MemoryView = {
  rss_bytes: number;
  virtual_bytes: number;
  heap_alloc_bytes: number;
  heap_sys_bytes: number;
  heap_inuse_bytes: number;
  stack_inuse_bytes: number;
  sys_bytes: number;
  next_gc_bytes: number;
  num_gc: number;
  goroutines: number;
  zone_store_bytes: number;
};

export function emptyMemory(): MemoryView {
  return {
    rss_bytes: 0,
    virtual_bytes: 0,
    heap_alloc_bytes: 0,
    heap_sys_bytes: 0,
    heap_inuse_bytes: 0,
    stack_inuse_bytes: 0,
    sys_bytes: 0,
    next_gc_bytes: 0,
    num_gc: 0,
    goroutines: 0,
    zone_store_bytes: 0,
  };
}

export type AppConfig = ThemeConfig;
