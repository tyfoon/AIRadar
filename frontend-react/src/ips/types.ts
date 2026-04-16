// IPS page TypeScript interfaces

export interface InboundAttack {
  source_ip: string;
  target_ip: string;
  target_name?: string | null;
  target_port: number;
  severity: string;       // "threat" | "blocked"
  conn_state: string;     // S0, REJ, S1, SF, etc.
  crowdsec_reason?: string;
  country_code?: string;
  asn?: number;
  asn_org?: string;
  hit_count: number;
  first_seen: string;
  last_seen: string;
}

export interface IpsStatus {
  enabled: boolean;
  crowdsec_running: boolean;
  inbound_attacks_24h?: number;
  inbound_blocked_24h?: number;
  inbound_connected_24h?: number;
  inbound_threats_24h?: number;
  inbound_unique_ips_24h?: number;
  blocklist_count?: number;
  inbound_attacks?: InboundAttack[];
  blocklist?: { ip: string; reason: string; duration: string }[];
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
  total_24h?: number;
  total_7d?: number;
  sparkline_7d?: number[];
}

export interface PrivacyStatsPayload {
  beaconing_alerts?: BeaconAlert[];
  beaconing_status?: BeaconStatus | null;
  security?: SecurityStats;
}
