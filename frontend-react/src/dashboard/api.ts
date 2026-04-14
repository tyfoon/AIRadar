import type {
  HealthResponse,
  SystemPerformance,
  NetworkPerfResponse,
  PrivacyStats,
  IpsStatus,
  DashEvent,
} from './types';
import type { FleetResponse } from '../iot/types';

/** ISO timestamp for "hours ago from now" — used as rolling window start. */
export function hoursAgo(hours: number): string {
  return new Date(Date.now() - hours * 3600_000).toISOString();
}

export async function fetchHealth(): Promise<HealthResponse> {
  const r = await fetch('/api/health');
  return r.json();
}

export async function fetchSystemPerf(): Promise<SystemPerformance> {
  const r = await fetch('/api/system/performance');
  return r.json();
}

export async function fetchNetworkPerf(hours: number): Promise<NetworkPerfResponse> {
  const r = await fetch(`/api/network/performance/history?hours=${hours}`);
  return r.json();
}

export async function fetchPrivacyStats(hours: number): Promise<PrivacyStats> {
  const r = await fetch(`/api/privacy/stats?start=${hoursAgo(hours)}`);
  return r.json();
}

export async function fetchIpsStatus(): Promise<IpsStatus> {
  // IPS endpoint uses its own 24h window internally
  const r = await fetch('/api/ips/status');
  return r.json();
}

export async function fetchFleetSummary(): Promise<FleetResponse> {
  // Fleet endpoint uses its own 24h window internally
  const r = await fetch('/api/iot/fleet');
  return r.json();
}

export async function fetchDashEvents(hours: number): Promise<DashEvent[]> {
  const r = await fetch(`/api/events?limit=5000&include_heartbeats=true&start=${hoursAgo(hours)}`);
  return r.json();
}
