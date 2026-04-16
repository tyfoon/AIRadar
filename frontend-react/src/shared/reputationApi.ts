// ---------------------------------------------------------------------------
// Reputation API — bulk lookup + single-target deep check
// ---------------------------------------------------------------------------

export interface ReputationResult {
  urlhaus_status?: string;
  urlhaus_threat?: string;
  urlhaus_url_count?: number;
  urlhaus_checked_at?: string;
  threatfox_status?: string;
  threatfox_malware?: string;
  threatfox_checked_at?: string;
  abuseipdb_score?: number;
  abuseipdb_reports?: number;
  abuseipdb_checked_at?: string;
  vt_malicious?: number;
  vt_total?: number;
  vt_checked_at?: string;
}

export interface ReputationCheckResponse {
  result: ReputationResult;
  errors?: string[];
  rate_limits?: Record<string, { used: number; max: number }>;
}

/** Bulk-fetch cached reputation for a list of IPs/domains. Filters out private ranges. */
export async function fetchReputationBulk(targets: string[]): Promise<Record<string, ReputationResult>> {
  const unique = [...new Set(targets.filter(t => t && !t.startsWith('192.168.') && !t.startsWith('10.') && !t.startsWith('127.')))];
  if (!unique.length) return {};
  try {
    const res = await fetch('/api/reputation/bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targets: unique }),
    });
    const data = await res.json();
    return data.results || {};
  } catch {
    return {};
  }
}

/** Deep reputation check for a single target (calls all providers). */
export async function checkReputation(target: string): Promise<ReputationCheckResponse> {
  const res = await fetch('/api/reputation/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
