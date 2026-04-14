export interface HealthSummary {
  ok: number;
  total: number;
  all_ok: boolean;
}

export interface HealthService {
  service: string;
  icon: string;
  status: 'ok' | 'warning' | 'error';
  response_ms: number;
  details: string;
}

export interface HealthResponse {
  summary: HealthSummary;
  services: HealthService[];
}

export interface SystemPerformance {
  host: {
    cpu_percent: number;
    cpu_count: number;
    memory: { used: number; total: number; percent: number };
    disk: { used: number; total: number; percent: number };
    load_avg: [number, number, number];
  };
  containers: {
    name: string;
    state: string;
    status: string;
    cpu_percent: number;
    memory_used: number;
    memory_limit: number;
    memory_percent: number;
    error?: string;
  }[];
  docker_error?: string;
}

export interface NetworkPerfPoint {
  ts: string;
  dns_ms: number | null;
  ping_gw_ms: number | null;
  ping_inet_ms: number | null;
  loss_pct: number | null;
  cpu_pct: number | null;
  mem_pct: number | null;
  load1: number | null;
  br_rx_bps: number | null;
  br_tx_bps: number | null;
}

export interface NetworkPerfResponse {
  hours: number;
  count: number;
  data: NetworkPerfPoint[];
}

export interface PrivacyStats {
  adguard: {
    total_queries: number;
    blocked_queries: number;
    block_percentage: number;
    status: string;
  };
  trackers: {
    total_detected: number;
    top_trackers: { service: string; hits: number }[];
  };
  vpn_alerts: any[];
  beaconing_alerts: any[];
  security: {
    total_24h: number;
    total_7d: number;
    sparkline_7d: number[];
  };
}

export interface IpsStatus {
  enabled: boolean;
  crowdsec_running: boolean;
  inbound_attacks_24h: number;
  inbound_blocked_24h: number;
  inbound_connected_24h: number;
  inbound_unique_ips_24h: number;
  inbound_threats_24h: number;
  alerts: {
    id: number;
    created_at: string;
    scenario: string;
    ip: string;
    country: string;
    as_name: string;
    events_count: number;
  }[];
  inbound_attacks: {
    source_ip: string;
    target_port: number;
    severity: string;
    crowdsec_reason: string;
    country_code: string;
    asn_org: string;
    hit_count: number;
    first_seen: string;
    last_seen: string;
  }[];
}

export interface FleetDevice {
  mac_address: string;
  hostname: string;
  display_name: string;
  vendor: string;
  device_type: string;
  health: 'green' | 'orange' | 'red';
  bytes_24h: number;
  hits_24h: number;
  destinations: number;
  anomalies: number;
  last_seen: string | null;
  online: boolean;
  baseline_status: 'learning' | 'building' | 'ready';
}

export interface FleetResponse {
  total_devices: number;
  total_bytes_24h: number;
  anomaly_devices: number;
  top_talker: string | null;
  devices: FleetDevice[];
}

export interface DashEvent {
  id: number;
  timestamp: string;
  source_ip: string;
  ai_service: string;
  category: string;
  bytes_transferred: number;
  possible_upload: boolean;
}
