// ---------------------------------------------------------------------------
// ReputationModal — compact deep-check UI for a single IP/domain.
//
// Shows an aggregate verdict strip + per-provider rows with plain-English
// interpretations of raw scores. Tight by design: most interactions are a
// quick "is this IP sketchy?" glance, not a forensic deep dive.
//
// Providers: URLhaus (malware) · ThreatFox (C2) · AbuseIPDB (0-100 score)
// · VirusTotal (X of Y vendors).
// ---------------------------------------------------------------------------

import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { checkReputation, type ReputationResult, type ReputationCheckResponse } from './reputationApi';

interface ReputationModalProps {
  target: string | null;
  onClose: () => void;
}

type Severity = 'clean' | 'low' | 'suspicious' | 'malicious' | 'unknown';

const SEVERITY_THEME: Record<Severity, {
  icon: string;
  color: string;    // text color class
  bg: string;       // soft background class
  border: string;   // border class
  label: string;
}> = {
  clean:       { icon: 'ph-shield-check',   color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', label: 'Clean' },
  low:         { icon: 'ph-shield',         color: 'text-lime-400',    bg: 'bg-lime-500/10',    border: 'border-lime-500/30',    label: 'Low risk' },
  suspicious:  { icon: 'ph-warning',        color: 'text-amber-400',   bg: 'bg-amber-500/10',   border: 'border-amber-500/30',   label: 'Suspicious' },
  malicious:   { icon: 'ph-shield-warning', color: 'text-red-400',     bg: 'bg-red-500/10',     border: 'border-red-500/30',     label: 'Malicious' },
  unknown:     { icon: 'ph-question',       color: 'text-slate-400',   bg: 'bg-slate-500/10',   border: 'border-slate-500/30',   label: 'Unknown' },
};

export default function ReputationModal({ target, onClose }: ReputationModalProps) {
  useEffect(() => {
    if (!target) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [target, onClose]);

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['reputation-check', target],
    queryFn: () => checkReputation(target!),
    enabled: !!target,
    staleTime: 60_000,
    retry: false,
  });

  if (!target) return null;

  return (
    <div className="fixed inset-0 z-[120] flex items-center justify-center p-4" onClick={onClose}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div
        className="relative w-full max-w-sm bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg shadow-2xl overflow-hidden flex flex-col max-h-[85vh]"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex-shrink-0 flex items-center justify-between px-3 py-2 border-b border-slate-200 dark:border-slate-700">
          <div className="flex items-center gap-1.5 min-w-0">
            <i className="ph-duotone ph-magnifying-glass text-sm text-indigo-400 flex-shrink-0" />
            <h3 className="text-xs font-semibold text-slate-700 dark:text-slate-100 font-mono truncate" title={target}>
              {target}
            </h3>
          </div>
          <button
            onClick={onClose}
            className="w-6 h-6 flex items-center justify-center rounded hover:bg-slate-100 dark:hover:bg-white/[0.08] text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors text-base leading-none"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-3 space-y-2">
          {isLoading && (
            <div className="flex items-center justify-center gap-2 py-6">
              <div className="w-4 h-4 border-2 border-slate-300 dark:border-slate-600 border-t-indigo-500 rounded-full animate-spin" />
              <p className="text-[11px] text-slate-500 dark:text-slate-400">Checking providers&hellip;</p>
            </div>
          )}

          {isError && (
            <div className="flex items-center gap-2 py-4 px-2">
              <i className="ph-duotone ph-warning-circle text-lg text-red-400" />
              <div className="min-w-0">
                <p className="text-xs text-slate-600 dark:text-slate-300">Check failed</p>
                <p className="text-[10px] text-slate-400 dark:text-slate-500 truncate">
                  {(error as Error)?.message || 'Unknown error'}
                </p>
              </div>
            </div>
          )}

          {data && <ResultPanel data={data} />}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ResultPanel
// ---------------------------------------------------------------------------

function ResultPanel({ data }: { data: ReputationCheckResponse }) {
  const r = data.result;
  const errors = data.errors || [];
  const rl = data.rate_limits || {};

  const verdict = aggregateVerdict(r);
  const theme = SEVERITY_THEME[verdict.severity];

  return (
    <>
      {/* Verdict strip — single row */}
      <div className={`rounded-md border ${theme.border} ${theme.bg} px-2.5 py-2 flex items-center gap-2`}>
        <i className={`ph-duotone ${theme.icon} text-lg ${theme.color} flex-shrink-0`} />
        <div className="min-w-0 flex-1">
          <div className={`text-xs font-bold ${theme.color} leading-tight`}>{verdict.label}</div>
          <div className="text-[10px] text-slate-600 dark:text-slate-400 leading-tight mt-0.5 line-clamp-2">
            {verdict.subtitle}
          </div>
        </div>
      </div>

      {/* Provider rows */}
      <div className="space-y-1.5">
        <UrlhausRow r={r} />
        <ThreatfoxRow r={r} />
        <AbuseipdbRow r={r} errors={errors} />
        <VirusTotalRow r={r} errors={errors} />
      </div>

      {/* Rate limits footer */}
      {(rl.abuseipdb || rl.virustotal) && (
        <div className="flex items-center gap-2 pt-1.5 mt-1 border-t border-slate-200 dark:border-slate-700/60 text-[10px] text-slate-500 dark:text-slate-400">
          <i className="ph-duotone ph-gauge text-xs" />
          {rl.abuseipdb && <UsagePill name="AbuseIPDB" used={rl.abuseipdb.used} max={rl.abuseipdb.max} />}
          {rl.virustotal && <UsagePill name="VT" used={rl.virustotal.used} max={rl.virustotal.max} />}
        </div>
      )}
    </>
  );
}

function UsagePill({ name, used, max }: { name: string; used: number; max: number }) {
  const pct = max ? Math.min(100, (used / max) * 100) : 0;
  const color = pct >= 90 ? 'text-red-400' : pct >= 60 ? 'text-amber-400' : 'text-slate-400';
  return <span className={`tabular-nums ${color}`}>{name}: {used}/{max}</span>;
}

// ---------------------------------------------------------------------------
// Provider rows — one compact block each
// ---------------------------------------------------------------------------

interface RowProps {
  name: string;
  severity: Severity;
  verdict: string;
  detail?: React.ReactNode;
  meta?: React.ReactNode;     // right-side value like "12/94" or "87%"
  checkedAt?: string;
  children?: React.ReactNode; // optional extra row (progress bar etc.)
}

function Row({ name, severity, verdict, detail, meta, checkedAt, children }: RowProps) {
  const theme = SEVERITY_THEME[severity];
  return (
    <div className="rounded-md border border-slate-200 dark:border-slate-700/60 bg-slate-50 dark:bg-white/[0.02] px-2.5 py-1.5">
      <div className="flex items-center gap-2">
        <i className={`ph-duotone ${theme.icon} text-sm ${theme.color} flex-shrink-0`} />
        <span className="text-[11px] font-semibold text-slate-700 dark:text-slate-200 flex-shrink-0">{name}</span>
        <span className={`text-[11px] font-medium ${theme.color} truncate flex-1`}>{verdict}</span>
        {meta && <span className="text-[10px] tabular-nums text-slate-500 dark:text-slate-400 flex-shrink-0">{meta}</span>}
      </div>
      {children}
      {(detail || checkedAt) && (
        <div className="text-[10px] text-slate-500 dark:text-slate-400 leading-tight mt-0.5 ml-5">
          {detail}
          {detail && checkedAt && <span className="text-slate-400 dark:text-slate-600"> · </span>}
          {checkedAt && <span className="text-slate-400 dark:text-slate-600">{fmtCheckedAt(checkedAt)}</span>}
        </div>
      )}
    </div>
  );
}

function NotCheckedRow({ name, reason }: { name: string; reason: string }) {
  return (
    <div className="rounded-md border border-slate-200 dark:border-slate-700/60 bg-slate-50 dark:bg-white/[0.02] px-2.5 py-1.5 opacity-60">
      <div className="flex items-center gap-2">
        <i className="ph-duotone ph-clock-countdown text-sm text-slate-400 flex-shrink-0" />
        <span className="text-[11px] font-semibold text-slate-600 dark:text-slate-300 flex-shrink-0">{name}</span>
        <span className="text-[10px] text-slate-500 dark:text-slate-400 truncate flex-1">{reason}</span>
      </div>
    </div>
  );
}

// --- URLhaus ---
function UrlhausRow({ r }: { r: ReputationResult }) {
  if (r.urlhaus_status === 'malware') {
    return (
      <Row
        name="URLhaus"
        severity="malicious"
        verdict="Malware distributor"
        detail={
          <>
            {r.urlhaus_threat && <>Tagged <span className="font-mono text-slate-600 dark:text-slate-300">{r.urlhaus_threat}</span></>}
            {r.urlhaus_url_count ? ` · ${r.urlhaus_url_count} URL${r.urlhaus_url_count === 1 ? '' : 's'}` : null}
          </>
        }
        checkedAt={r.urlhaus_checked_at}
      />
    );
  }
  if (r.urlhaus_status === 'clean') {
    return <Row name="URLhaus" severity="clean" verdict="Not in malware DB" checkedAt={r.urlhaus_checked_at} />;
  }
  return <NotCheckedRow name="URLhaus" reason="Not yet checked" />;
}

// --- ThreatFox ---
function ThreatfoxRow({ r }: { r: ReputationResult }) {
  if (r.threatfox_status === 'c2') {
    return (
      <Row
        name="ThreatFox"
        severity="malicious"
        verdict="C2 infrastructure"
        detail={r.threatfox_malware ? <>Associated with <span className="font-mono text-slate-600 dark:text-slate-300">{r.threatfox_malware}</span></> : 'Command & control server'}
        checkedAt={r.threatfox_checked_at}
      />
    );
  }
  if (r.threatfox_status === 'clean') {
    return <Row name="ThreatFox" severity="clean" verdict="Not a known C2" checkedAt={r.threatfox_checked_at} />;
  }
  return <NotCheckedRow name="ThreatFox" reason="Not yet checked" />;
}

// --- AbuseIPDB (progress bar) ---
function AbuseipdbRow({ r, errors }: { r: ReputationResult; errors: string[] }) {
  if (r.abuseipdb_score == null) {
    const err = errors.find(e => e.includes('AbuseIPDB'));
    return <NotCheckedRow name="AbuseIPDB" reason={err || 'No API key — see Settings'} />;
  }
  const sc = r.abuseipdb_score;
  const reports = r.abuseipdb_reports || 0;
  const severity: Severity = sc >= 75 ? 'malicious' : sc >= 25 ? 'suspicious' : sc >= 1 ? 'low' : 'clean';
  const verdict =
    sc >= 75 ? 'High abuse confidence' :
    sc >= 25 ? 'Some abuse reports' :
    sc >= 1  ? 'Minor abuse reports' :
               'No abuse reports';
  const detail = reports === 0
    ? 'Not reported'
    : `${reports} report${reports === 1 ? '' : 's'}`;
  const barColor = sc >= 75 ? 'bg-red-500' : sc >= 25 ? 'bg-amber-500' : sc >= 1 ? 'bg-lime-500' : 'bg-emerald-500';

  return (
    <Row
      name="AbuseIPDB"
      severity={severity}
      verdict={verdict}
      meta={<span className={`font-bold ${SEVERITY_THEME[severity].color}`}>{sc}%</span>}
      detail={detail}
      checkedAt={r.abuseipdb_checked_at}
    >
      <div className="ml-5 mt-1 h-1 rounded-full bg-slate-200 dark:bg-white/[0.06] overflow-hidden">
        <div className={`h-full ${barColor} transition-all`} style={{ width: `${Math.max(2, sc)}%` }} />
      </div>
    </Row>
  );
}

// --- VirusTotal ---
function VirusTotalRow({ r, errors }: { r: ReputationResult; errors: string[] }) {
  if (r.vt_malicious == null) {
    const err = errors.find(e => e.includes('VirusTotal'));
    return <NotCheckedRow name="VirusTotal" reason={err || 'No API key — see Settings'} />;
  }
  const m = r.vt_malicious;
  const total = r.vt_total || 0;
  const severity: Severity = m >= 5 ? 'malicious' : m >= 1 ? 'suspicious' : 'clean';
  const verdict =
    m >= 5 ? 'Multiple vendors flagged' :
    m >= 1 ? 'A few vendors flagged' :
             'All vendors clean';
  const detail = m === 0
    ? `${total} engine${total === 1 ? '' : 's'} clean`
    : `${m} of ${total} malicious`;

  return (
    <Row
      name="VirusTotal"
      severity={severity}
      verdict={verdict}
      meta={<><span className={`font-bold ${SEVERITY_THEME[severity].color}`}>{m}</span>/{total}</>}
      detail={detail}
      checkedAt={r.vt_checked_at}
    />
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fmtCheckedAt(iso?: string): string {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    const now = new Date();
    const sameDay = d.toDateString() === now.toDateString();
    if (sameDay) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch { return ''; }
}

interface Verdict { severity: Severity; label: string; subtitle: string; }

function aggregateVerdict(r: ReputationResult): Verdict {
  if (r.urlhaus_status === 'malware' || r.threatfox_status === 'c2') {
    const parts: string[] = [];
    if (r.urlhaus_status === 'malware') parts.push('malware');
    if (r.threatfox_status === 'c2') parts.push('C2');
    return { severity: 'malicious', label: 'Known malicious', subtitle: `Flagged for ${parts.join(' & ')} by abuse.ch.` };
  }
  if ((r.abuseipdb_score ?? 0) >= 75 || (r.vt_malicious ?? 0) >= 5) {
    return { severity: 'malicious', label: 'Likely malicious', subtitle: 'High abuse score or multiple vendors flagged this.' };
  }
  if ((r.abuseipdb_score ?? 0) >= 25 || (r.vt_malicious ?? 0) >= 1) {
    return { severity: 'suspicious', label: 'Suspicious', subtitle: 'Some providers flagged this. Review details below.' };
  }
  if ((r.abuseipdb_score ?? 0) >= 1) {
    return { severity: 'low', label: 'Low risk', subtitle: 'A few abuse reports, no critical threat signals.' };
  }
  const anyClean =
    r.urlhaus_status === 'clean' || r.threatfox_status === 'clean' ||
    r.abuseipdb_score === 0 || r.vt_malicious === 0;
  if (anyClean) {
    return { severity: 'clean', label: 'Looks clean', subtitle: 'No threat signals from the checked providers.' };
  }
  return { severity: 'unknown', label: 'No data', subtitle: 'No providers returned data for this target.' };
}
