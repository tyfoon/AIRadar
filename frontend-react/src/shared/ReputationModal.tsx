import { useState, useEffect } from 'react';
import { checkReputation, type ReputationResult, type ReputationCheckResponse } from './reputationApi';

interface ReputationModalProps {
  target: string | null;
  onClose: () => void;
}

export default function ReputationModal({ target, onClose }: ReputationModalProps) {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<ReputationCheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!target) { setData(null); setError(null); return; }
    let cancelled = false;
    setLoading(true);
    setData(null);
    setError(null);
    checkReputation(target)
      .then(res => { if (!cancelled) setData(res); })
      .catch(err => { if (!cancelled) setError(err.message || 'Unknown error'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [target]);

  if (!target) return null;

  return (
    <div className="fixed inset-0 z-[120] flex items-center justify-center" onClick={onClose}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div
        className="relative w-full max-w-md mx-4 bg-slate-800 border border-slate-700 rounded-xl shadow-2xl p-5"
        onClick={e => e.stopPropagation()}
      >
        {loading && (
          <div className="text-center py-6">
            <div className="animate-spin inline-block w-6 h-6 border-2 border-slate-400 border-t-transparent rounded-full" />
            <p className="text-sm text-slate-400 mt-2">Checking {target}...</p>
          </div>
        )}

        {error && (
          <p className="text-red-400 text-sm">Error: {error}</p>
        )}

        {data && <ResultPanel target={target} data={data} />}

        <button
          onClick={onClose}
          className="mt-4 w-full text-xs py-1.5 rounded bg-slate-700 hover:bg-slate-600 text-slate-300 transition"
        >
          Close
        </button>
      </div>
    </div>
  );
}

function fmtCheckedAt(iso?: string): string {
  if (!iso) return '';
  try { return new Date(iso).toLocaleTimeString(); } catch { return ''; }
}

function ResultPanel({ target, data }: { target: string; data: ReputationCheckResponse }) {
  const r = data.result;
  const errors = data.errors || [];
  const rl = data.rate_limits || {};

  return (
    <>
      <h3 className="text-sm font-bold text-slate-200 mb-3">
        <i className="ph-duotone ph-magnifying-glass text-xs mr-1" /> {target}
      </h3>
      <div className="space-y-2">
        <RepRow
          service="URLhaus"
          value={urlhausLabel(r)}
          checkedAt={r.urlhaus_checked_at}
        />
        <RepRow
          service="ThreatFox"
          value={threatfoxLabel(r)}
          checkedAt={r.threatfox_checked_at}
        />
        <RepRow
          service="AbuseIPDB"
          value={abuseipdbLabel(r, errors)}
          checkedAt={r.abuseipdb_checked_at}
        />
        <RepRow
          service="VirusTotal"
          value={vtLabel(r, errors)}
          checkedAt={r.vt_checked_at}
        />
      </div>

      {(rl.abuseipdb || rl.virustotal) && (
        <p className="text-[10px] text-slate-500 mt-3">
          Daily usage:{' '}
          {[
            rl.abuseipdb ? `AbuseIPDB: ${rl.abuseipdb.used}/${rl.abuseipdb.max}` : null,
            rl.virustotal ? `VT: ${rl.virustotal.used}/${rl.virustotal.max}` : null,
          ].filter(Boolean).join(' \u00b7 ')}
        </p>
      )}
    </>
  );
}

function RepRow({ service, value, checkedAt }: { service: string; value: string; checkedAt?: string }) {
  const timeStr = fmtCheckedAt(checkedAt);
  return (
    <div className="flex items-start gap-2 text-xs">
      <span className="text-slate-400 w-20 shrink-0 font-medium">{service}</span>
      <span className="text-slate-200 flex-1">
        {value}
        {timeStr && <span className="text-[10px] text-slate-600 ml-2">{timeStr}</span>}
      </span>
    </div>
  );
}

function urlhausLabel(r: ReputationResult): string {
  if (r.urlhaus_status === 'malware')
    return `\uD83D\uDD34 Malware${r.urlhaus_threat ? ' \u2014 ' + r.urlhaus_threat : ''} (${r.urlhaus_url_count || 0} URLs)`;
  if (r.urlhaus_status === 'clean') return '\u2705 Clean';
  return '\u23F3 Not checked';
}

function threatfoxLabel(r: ReputationResult): string {
  if (r.threatfox_status === 'c2')
    return `\uD83D\uDD34 C2 Server${r.threatfox_malware ? ' \u2014 ' + r.threatfox_malware : ''}`;
  if (r.threatfox_status === 'clean') return '\u2705 Clean';
  return '\u23F3 Not checked';
}

function abuseipdbLabel(r: ReputationResult, errors: string[]): string {
  if (r.abuseipdb_score != null) {
    const sc = r.abuseipdb_score;
    const icon = sc >= 75 ? '\uD83D\uDD34' : sc >= 25 ? '\uD83D\uDFE0' : '\uD83D\uDFE2';
    return `${icon} ${sc}% abuse confidence (${r.abuseipdb_reports || 0} reports)`;
  }
  return errors.find(e => e.includes('AbuseIPDB')) || 'No API key configured';
}

function vtLabel(r: ReputationResult, errors: string[]): string {
  if (r.vt_malicious != null) {
    const m = r.vt_malicious;
    const icon = m >= 5 ? '\uD83D\uDD34' : m >= 1 ? '\uD83D\uDFE0' : '\uD83D\uDFE2';
    return `${icon} ${m}/${r.vt_total} vendors flagged malicious`;
  }
  return errors.find(e => e.includes('VirusTotal')) || 'No API key configured';
}
