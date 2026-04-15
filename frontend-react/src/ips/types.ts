// IPS status payload from /api/ips/status. The backend returns additional
// nested objects we don't touch in React (vanilla _renderIpsThreats consumes
// the inbound_attacks / blocklist arrays directly), so we keep the interface
// intentionally loose — `any[]` on the two lists avoids duplicating the
// alert-card shape.

export interface IpsStatus {
  enabled: boolean;
  crowdsec_running: boolean;
  inbound_attacks_24h?: number;
  inbound_blocked_24h?: number;
  inbound_connected_24h?: number;
  inbound_threats_24h?: number;
  inbound_unique_ips_24h?: number;
  blocklist_count?: number;
  // Opaque to React — passed straight to window._renderIpsThreats
  inbound_attacks?: unknown[];
  blocklist?: unknown[];
}

export interface PrivacyStatsPayload {
  beaconing_alerts?: unknown[];
  beaconing_status?: unknown;
  security?: {
    total_24h?: number;
    total_7d?: number;
    sparkline_7d?: number[];
  };
}
