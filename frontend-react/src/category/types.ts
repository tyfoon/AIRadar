// ---------------------------------------------------------------------------
// Types for AI / Cloud category pages
// ---------------------------------------------------------------------------

export interface DetectionEvent {
  id: number;
  timestamp: string;
  ai_service: string;
  detection_type: string;
  source_ip: string;
  possible_upload: boolean;
  bytes_transferred: number;
  category: string;
  description?: string;
}

export interface TimelineBucket {
  bucket: string;
  total: number;
  uploads: number;
  services: Record<string, number>;
}

export interface AdoptionMetrics {
  adoptionPct: number;
  aiDeviceCount: number;
  totalDevices: number;
  avgQueriesPerDay: number;
  activeToday: number;
  avgServicesPerUser: number;
  powerUsers: number;
  topService: string | null;
}

export interface DeviceBreakdown {
  mac: string;
  name: string;
  icon: string;
  count: number;
  services: string[];
  uploads: number;
}

export interface ServiceBreakdown {
  service: string;
  count: number;
  share: number;
  users: number;
}

export interface UploaderEntry {
  ip: string;
  name: string;
  mac: string | null;
  bytes: number;
  events: number;
  services: string[];
}
