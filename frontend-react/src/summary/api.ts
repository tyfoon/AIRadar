import type { AlertsResponse, AiSummaryResponse } from './types';

export async function fetchActiveAlerts(hours = 24): Promise<AlertsResponse> {
  const r = await fetch(`/api/alerts/active?hours=${hours}`);
  return r.json();
}

export async function dismissAlert(
  mac: string, alertType: string, destination: string,
  expiresAt?: string, dismissedScore?: number,
): Promise<void> {
  await fetch('/api/exceptions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      mac_address: mac,
      alert_type: alertType,
      destination: destination || null,
      expires_at: expiresAt || null,
      dismissed_score: dismissedScore ?? null,
    }),
  });
}

export async function fetchAiSummary(hours = 24): Promise<AiSummaryResponse> {
  const r = await fetch(`/api/alerts/ai-summary?hours=${hours}`);
  return r.json();
}
