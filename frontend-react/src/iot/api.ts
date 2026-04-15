import type {
  FleetResponse,
  AnomalyResponse,
  TrafficHistoryResponse,
  NetworkGraphResponse,
  DestinationHistoryResponse,
} from './types';

export async function fetchFleet(): Promise<FleetResponse> {
  const r = await fetch('/api/iot/fleet');
  if (!r.ok) throw new Error(`Fleet API ${r.status}`);
  return r.json();
}

export async function fetchAnomalies(hours = 24): Promise<AnomalyResponse> {
  const r = await fetch(`/api/iot/anomalies?hours=${hours}`);
  if (!r.ok) throw new Error(`Anomalies API ${r.status}`);
  return r.json();
}

export async function fetchTrafficHistory(
  mac: string,
  days = 7,
): Promise<TrafficHistoryResponse> {
  const r = await fetch(
    `/api/iot/device/${encodeURIComponent(mac)}/traffic-history?days=${days}`,
  );
  if (!r.ok) throw new Error(`Traffic history API ${r.status}`);
  return r.json();
}

export async function fetchNetworkGraph(
  hours = 24,
): Promise<NetworkGraphResponse> {
  const r = await fetch(`/api/network/graph?hours=${hours}`);
  if (!r.ok) throw new Error(`Network graph API ${r.status}`);
  return r.json();
}

export async function fetchDestinationHistory(
  mac: string,
  hours = 24,
): Promise<DestinationHistoryResponse> {
  const r = await fetch(
    `/api/iot/device/${encodeURIComponent(mac)}/destination-history?hours=${hours}`,
  );
  if (!r.ok) throw new Error(`Destination history API ${r.status}`);
  return r.json();
}

export async function dismissAnomaly(
  sourceIp: string,
  detectionType: string,
  detail?: string,
): Promise<void> {
  const p = new URLSearchParams({ source_ip: sourceIp, detection_type: detectionType });
  if (detail) p.set('detail', detail);
  const r = await fetch(`/api/iot-anomaly?${p}`, { method: 'DELETE' });
  if (!r.ok) throw new Error(`Dismiss anomaly API ${r.status}`);
}
