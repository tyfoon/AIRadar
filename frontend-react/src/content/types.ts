// Content/Family page TypeScript interfaces

export interface CategoryMeta {
  key: string;
  label_en: string;
  label_nl?: string;
  icon?: string;
  color?: string;
}

export interface FamilyMetaResponse {
  categories: CategoryMeta[];
}

export interface OverviewCard {
  key: string;
  icon?: string;
  color?: string;
  label_en: string;
  label_nl?: string;
  bytes: number;
  hits: number;
  services: number;
  devices: number;
  trend_pct?: number;
  blocked?: boolean;
}

export interface HonestyInfo {
  encrypted_share_pct?: number;
  unknown_bytes: number;
  known_bytes: number;
}

export interface OverviewResponse {
  window_hours: number;
  group_id: number | null;
  cards: OverviewCard[];
  top_services?: { service_name: string; category: string; bytes: number; hits: number }[];
  recent_blocks?: { id: number; service: string; category: string; domain: string; is_active: boolean; created_at: string; expires_at: string | null }[];
  honesty: HonestyInfo;
}

export interface ServiceDevice {
  mac_address: string;
  display_name: string;
  hostname: string | null;
  vendor: string | null;
  device_class: string | null;
  online: boolean;
  bytes: number;
  hits: number;
}

export interface CategoryService {
  service_name: string;
  total_bytes: number;
  total_hits: number;
  device_count: number;
  blocked?: boolean;
  phantom?: boolean;
  top_devices: ServiceDevice[];
}

export interface DeviceService {
  service_name: string;
  bytes: number;
  hits: number;
}

export interface CategoryDevice {
  mac_address: string;
  display_name: string;
  hostname: string | null;
  vendor: string | null;
  device_class: string | null;
  online: boolean;
  total_bytes: number;
  total_hits: number;
  service_count: number;
  top_services: DeviceService[];
}

export interface CategoryPolicy {
  id: number;
  scope: string;
  mac_address: string | null;
  group_id: number | null;
  service_name: string | null;
  category: string;
  action: string;
  expires_at: string | null;
}

export interface CategoryResponse {
  category: string;
  meta: CategoryMeta;
  window_hours: number;
  group_id: number | null;
  total_bytes: number;
  total_hits: number;
  services: CategoryService[];
  devices: CategoryDevice[];
  policies: CategoryPolicy[];
}

export interface DeviceGroup {
  id: number;
  name: string;
  member_count?: number;
}
