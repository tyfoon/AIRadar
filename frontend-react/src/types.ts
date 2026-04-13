export interface Session {
  service: string;
  category: string;
  start: string;
  end: string;
  duration_seconds: number;
  events: number;
  bytes: number;
}

export interface ServiceTotal {
  service: string;
  category: string;
  duration_seconds: number;
  events: number;
  bytes: number;
}

export interface CategoryTotal {
  category: string;
  duration_seconds: number;
  events: number;
  bytes: number;
}

export interface ActivityResponse {
  mac_address: string;
  date: string;
  tz: string;
  categories: string[];
  sessions: Session[];
  totals_by_service: ServiceTotal[];
  totals_by_category: CategoryTotal[];
  grand_total_seconds: number;
}
