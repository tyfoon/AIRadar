export interface GeoDevice {
  mac: string;
  name: string;
  vendor: string;
  bytes: number;
}

export interface GeoCountry {
  country_code: string;
  bytes: number;
  hits: number;
  opposite_bytes: number;
  top_devices: GeoDevice[];
}

export interface GeoTrafficResponse {
  direction: 'outbound' | 'inbound';
  countries: GeoCountry[];
}

export interface CountryDetailDevice {
  mac: string;
  name: string;
  bytes: number;
}

export interface CountryDetailService {
  service: string;
  bytes: number;
  hits: number;
}

export interface CountryDetailIP {
  ip: string;
  bytes: number;
  hits: number;
  asn: number | null;
  asn_org: string | null;
  ptr: string | null;
  enriched: boolean;
}

export interface CountryDetailResponse {
  direction: string;
  total_bytes: number;
  total_hits: number;
  top_devices: CountryDetailDevice[];
  top_services: CountryDetailService[];
  top_ips: CountryDetailIP[];
}

export type Direction = 'outbound' | 'inbound';
