export interface ActiveAlert {
  alert_id: string;
  mac_address: string;
  hostname?: string;
  display_name?: string;
  vendor?: string;
  alert_type: string;
  service_or_dest: string;
  category?: string;
  timestamp: string;
  first_seen: string;
  hits: number;
  total_bytes: number;
  details: Record<string, any>;
}

export interface AlertsResponse {
  count: number;
  window_hours: number;
  alerts: ActiveAlert[];
}

export interface AiSummaryResponse {
  summary: string;
  alert_count: number;
  priority: 'high' | 'medium' | 'low';
  devices_to_check: string[];
  model: string;
  tokens: { prompt: number; response: number; total: number };
}
