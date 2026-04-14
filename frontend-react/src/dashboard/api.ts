import type {
  HealthResponse,
  SystemPerformance,
  NetworkPerfResponse,
  PrivacyStats,
  IpsStatus,
  FleetResponse,
  DashEvent,
} from './types';

const todayStart = () => {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  return d.toISOString();
};

export async function fetchHealth(): Promise<HealthResponse> {
  const r = await fetch('/api/health');
  return r.json();
}

export async function fetchSystemPerf(): Promise<SystemPerformance> {
  const r = await fetch('/api/system/performance');
  return r.json();
}

export async function fetchNetworkPerf(): Promise<NetworkPerfResponse> {
  const r = await fetch('/api/network/performance/history?hours=24');
  return r.json();
}

export async function fetchPrivacyStats(): Promise<PrivacyStats> {
  const r = await fetch('/api/privacy/stats');
  return r.json();
}

export async function fetchIpsStatus(): Promise<IpsStatus> {
  const r = await fetch('/api/ips/status');
  return r.json();
}

export async function fetchFleetSummary(): Promise<FleetResponse> {
  const r = await fetch('/api/iot/fleet');
  return r.json();
}

export async function fetchDashEvents(): Promise<DashEvent[]> {
  const r = await fetch(`/api/events?limit=1000&include_heartbeats=false&start=${todayStart()}`);
  return r.json();
}
