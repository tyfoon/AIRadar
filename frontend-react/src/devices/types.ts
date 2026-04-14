import type { Device } from '../utils/devices';

export type { Device } from '../utils/devices';

export interface DeviceEvent {
  source_ip: string;
  ai_service: string;
  bytes_transferred: number;
  possible_upload: boolean;
  timestamp: string;
  detection_type: string;
  _cat: string;
  // Collapse fields
  _key?: string;
  _count?: number;
  _newest_ts?: string;
  _oldest_ts?: string;
  _newest_ms?: number;
  _oldest_ms?: number;
}

export interface Policy {
  service_name: string;
  action: 'block' | 'alert' | 'allow';
  scope: string;
  category?: string;
}

export interface DeviceMatrix {
  matrix: Record<string, Record<string, { count: number; uploads: number }>>;
  svcCategoryMap: Record<string, string>;
  allServices: Set<string>;
  deviceMacs: string[];
  globalMax: number;
}

export interface Connection {
  resp_ip: string;
  direction: string;
  country_code: string;
  asn: number;
  asn_org: string;
  ptr: string;
  service: string;
  bytes: number;
  hits: number;
}

export interface Group {
  id: number;
  name: string;
  parent_id: number | null;
  member_count: number;
  icon: string;
  color: string;
}

export interface GroupMember {
  mac_address: string;
}

export interface ReportData {
  report: string;
  cached: boolean;
  tokens?: {
    prompt_tokens?: number;
    response_tokens?: number;
    thinking_tokens?: number;
    total_tokens?: number;
  };
  model?: string;
  generated_at?: string;
  flags?: string | Record<string, unknown>;
}

export interface AskResponse {
  answer: string;
  tokens?: { prompt_tokens?: number; response_tokens?: number; total_tokens?: number };
  model?: string;
  elapsed_s?: string;
}

export interface DeviceMap {
  [mac: string]: Device;
}

export interface IpToMac {
  [ip: string]: string;
}
