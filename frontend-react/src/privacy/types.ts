// Privacy page TypeScript interfaces

export interface AdGuardStats {
  total_queries: number;
  blocked_queries: number;
  block_percentage: number;
  top_blocked: TopBlocked[];
  status: 'ok' | 'unavailable';
}

export interface TopBlocked {
  domain: string;
  count: number;
  company?: string;
  category?: string;
}

export interface TopTracker {
  service: string;
  hits: number;
}

export interface RecentTracker {
  timestamp: string;
  service: string;
  source_ip: string;
  detection_type: string;
}

export interface TrackerStats {
  total_detected: number;
  top_trackers: TopTracker[];
  recent: RecentTracker[];
}

export interface VpnAlert {
  source_ip: string;
  last_seen: string;
  total_bytes: number;
  hits: number;
  vpn_service: string;
  stealth_hits: number;
  regular_hits: number;
  is_stealth: boolean;
  hostname?: string;
  mac_address?: string;
  display_name?: string;
  vendor?: string;
}

export interface BeaconAlert {
  source_ip: string;
  dest_ip: string;
  dest_sni?: string;
  last_seen: string;
  hits: number;
  score: number;
  dismissed: boolean;
  hostname?: string;
  mac_address?: string;
  display_name?: string;
  vendor?: string;
  dest_asn_org?: string;
  dest_country?: string;
  dest_ptr?: string;
  total_bytes?: number;
  total_hits?: number;
}

export interface BeaconStatus {
  running: boolean;
  scans_completed: number;
  last_scan_at?: string;
  last_findings: number;
  last_error?: string;
}

export interface SecurityStats {
  total_24h: number;
  total_7d: number;
  sparkline_7d: number[];
}

export interface PrivacyStatsResponse {
  adguard: AdGuardStats;
  trackers: TrackerStats;
  vpn_alerts: VpnAlert[];
  beaconing_alerts: BeaconAlert[];
  beaconing_status: BeaconStatus | null;
  security: SecurityStats;
}
