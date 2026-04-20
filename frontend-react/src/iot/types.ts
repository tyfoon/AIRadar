// ---------------------------------------------------------------------------
// IoT Overview — shared TypeScript types
// ---------------------------------------------------------------------------

export interface FleetDevice {
  mac_address: string;
  hostname: string | null;
  display_name: string | null;
  vendor: string | null;
  device_type: string;
  health: 'green' | 'orange' | 'red';
  bytes_24h: number;
  hits_24h: number;
  destinations: number;
  anomalies: number;
  last_seen: string | null;
  ips: string[];
  baseline_status: 'learning' | 'building' | 'ready';
  baseline_days: number;
  orig_bytes_24h: number;
  resp_bytes_24h: number;
  top_countries: { cc: string; bytes: number }[];
  online: boolean;
  baseline_avg_bytes_24h: number | null;
  // LAN-to-LAN stats (backfilled with 0 for backward compat when the
  // backend hasn't been updated yet).
  lan_bytes_24h: number;
  lan_peers: number;
  lan_orig_bytes_24h: number;
  lan_resp_bytes_24h: number;
}

export interface FleetResponse {
  total_devices: number;
  total_bytes_24h: number;
  anomaly_devices: number;
  top_talker: string | null;
  devices: FleetDevice[];
}

export interface Anomaly {
  source_ip: string;
  detection_type: string;
  detail: string;
  hits: number;
  last_seen: string;
  dismissed: boolean;
  mac: string | null;
  hostname: string | null;
  display_name: string | null;
  vendor: string | null;
}

export interface AnomalyResponse {
  anomalies: Anomaly[];
}

export interface TrafficPoint {
  hour: string;
  tx: number;
  rx: number;
  connections: number;
  destinations: number;
}

export interface TrafficHistoryResponse {
  mac_address: string;
  days: number;
  bucket: '1h' | '5m';
  data: TrafficPoint[];
}

export interface NetworkNode {
  ip: string;
  mac: string | null;
  hostname: string | null;
  display_name: string | null;
  vendor: string | null;
  device_class: string | null;
  os_name: string | null;
  last_seen: string | null;
  edge_count?: number;        // # of edges touching this node
  is_gateway?: boolean;       // top-degree node — usually the router
  is_self?: boolean;          // matches one of AI-Radar's own NIC MACs
}

export interface NetworkEdge {
  source_ip: string;
  target_ip: string;
  source_mac?: string | null;
  target_mac?: string | null;
  port: number;
  port_label: string;
  bytes?: number;             // total (orig + resp)
  orig_bytes?: number;        // src → peer (upload from src POV)
  resp_bytes?: number;        // peer → src (download from src POV)
  hits: number;
  first_seen: string;
  last_seen: string;
  top_ports?: { proto_port: string; bytes: number; hits: number }[];
  // Infra chatter edges (DNS/NetBIOS/mDNS/ICMP/...) — filtered out by
  // the UI by default because they fan out to every peer and drown
  // out the actual device-to-device relationships.
  is_infrastructure?: boolean;
}

export interface NetworkGraphResponse {
  window_hours: number;
  nodes: NetworkNode[];
  edges: NetworkEdge[];
}

export interface DestinationHour {
  dest: string;
  hours: number[];       // 24 elements, bytes per hour-of-day
  total_bytes: number;
}

export interface DestinationHistoryResponse {
  mac_address: string;
  hours: number;
  destinations: DestinationHour[];
}

export type IotTab = 'anomalies' | 'fleet' | 'network';
