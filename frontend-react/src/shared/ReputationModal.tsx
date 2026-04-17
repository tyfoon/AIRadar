// ---------------------------------------------------------------------------
// ReputationModal — rich deep-check UI for a single IP/domain
//
// Shows an aggregate verdict banner (Safe / Low risk / Suspicious / Malicious)
// followed by per-provider cards with plain-English interpretations of raw
// scores. Users don't need to know that AbuseIPDB's 0-100 is "confidence"
// or that 5+ VT detections is typical threshold for malicious — the card
// tells them directly.
//
// Providers:
//   URLhaus     — malware distribution (clean / malware)
//   ThreatFox   — C2 infrastructure (clean / c2)
//   AbuseIPDB   — 0-100 abuse confidence + report count
//   VirusTotal  — X of Y vendors flagged as malicious
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
  iconColor: string;
  bg: string;
  border: string;
  label: string;
}> = {
  clean:       { icon: 'ph-shield-check',   iconColor: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', label: 'Clean' },
  low:         { icon: 'ph-shield',         iconColor: 'text-lime-400',    bg: 'bg-lime-500/10',    border: 'border-lime-500/30',    label: 'Low risk' },
  suspicious:  { icon: 'ph-warning',        iconColor: 'text-amber-400',   bg: 'bg-amber-500/10',   border: 'border-amber-500/30',   label: 'Suspicious' },
  malicious:   { icon: 'ph-shield-warning', iconColor: 'text-red-400',     bg: 'bg-red-500/10',     border: 'border-red-500/30',     label: 'Malicious' },
  unknown:     { icon: 'ph-question',       iconColor: 'text-slate-400',   bg: 'bg-slate-500/10',   border: 'border-slate-500/30',   label: 'Unknown' },
};

export default function ReputationModal({ target, onClose }: ReputationModalProps) {
  // Close on Escape
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
        className="relative w-full max-w-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex-shrink-0 flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-slate-700">
          <div className="flex items-center gap-2 min-w-0">
            <i className="ph-duotone ph-magnifying-glass text-base text-indigo-400 flex-shrink-0" />
            <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-100 font-mono truncate" title={target}>
              {target}
            </h3>
          </div>
          <button
            onClick={onClose}
            className="w-7 h-7 flex items-center justify-center rounded-lg hover:bg-slate-100 dark:hover:bg-white/[0.08] text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors text-lg leading-none"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {isLoading && (
            <div className="flex flex-col items-center justify-center py-10 gap-3">
              <div className="w-8 h-8 border-2 border-slate-300 dark:border-slate-600 border-t-indigo-500 rounded-full animate-spin" />
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Checking threat intel providers&hellip;
              </p>
            </div>
          )}

          {isError && (
            <div className="text-center py-6">
              <i className="ph-duotone ph-warning-circle text-3xl text-red-400" />
              <p className="text-sm text-slate-600 dark:text-slate-300 mt-2">
                Failed to check reputation
              </p>
              <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">
                {(error as Error)?.message || 'Unknown error'}
              </p>
            </div>
          )}

          {data && <ResultPanel data={data} />}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ResultPanel — aggregate verdict + per-provider cards
// ---------------------------------------------------------------------------

function ResultPanel({ data }: { data: ReputationCheckResponse }) {
  const r = data.result;
  const errors = data.errors || [];
  const rl = data.rate_limits || {};

  const verdict = aggregateVerdict(r);
  const theme = SEVERITY_THEME[verdict.severity];

  return (
    <>
      {/* Aggregate verdict banner */}
      <div className={`rounded-lg border ${theme.border} ${theme.bg} p-4`}>
        <div className="flex items-start gap-3">
          <i className={`ph-duotone ${theme.icon} text-3xl ${theme.iconColor} flex-shrink-0`} />
          <div className="min-w-0">
            <div className={`text-sm font-bold ${theme.iconColor}`}>{verdict.label}</div>
            <div className="text-xs text-slate-600 dark:text-slate-300 mt-0.5">{verdict.subtitle}</div>
          </div>
        </div>
      </div>

      {/* Provider cards */}
      <div className="space-y-2">
        <UrlhausCard r={r} />
        <ThreatfoxCard r={r} />
        <AbuseipdbCard r={r} errors={errors} />
        <VirusTotalCard r={r} errors={errors} />
      </div>

      {/* Rate limits footer */}
      {(rl.abuseipdb || rl.virustotal) && (
        <div className="flex items-center gap-3 pt-3 border-t border-slate-200 dark:border-slate-700 text-[10px] text-slate-500 dark:text-slate-400">
          <i className="ph-duotone ph-gauge text-sm" />
          <span>Daily limits</span>
          {rl.abuseipdb && <UsagePill name="AbuseIPDB" used={rl.abuseipdb.used} max={rl.abuseipdb.max} />}
          {rl.virustotal && <UsagePill name="VirusTotal" used={rl.virustotal.used} max={rl.virustotal.max} />}
        </div>
      )}
    </>
  );
}

function UsagePill({ name, used, max }: { name: string; used: number; max: number }) {
  const pct = max ? Math.min(100, (used / max) * 100) : 0;
  const color = pct >= 90 ? 'text-red-400' : pct >= 60 ? 'text-amber-400' : 'text-slate-400';
  return (
    <span className={`tabular-nums ${color}`}>
      {name}: {used}/{max}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Provider cards
// ---------------------------------------------------------------------------

interface CardProps {
  title: string;
  severity: Severity;
  verdict: string;
  detail?: React.ReactNode;
  checkedAt?: string;
  rightMeta?: React.ReactNode;
}

function ProviderCard({ title, severity, verdict, detail, checkedAt, rightMeta }: CardProps) {
  const theme = SEVERITY_THEME[severity];
  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-white/[0.02] p-3">
      <div className="flex items-start justify-between gap-2 mb-1.5">
        <div className="flex items-center gap-2 min-w-0">
          <i className={`ph-duotone ${theme.icon} text-base ${theme.iconColor} flex-shrink-0`} />
          <span className="text-xs font-semibold text-slate-700 dark:text-slate-200">{title}</span>
        </div>
        {rightMeta && <div className="text-[10px] tabular-nums text-slate-500 dark:text-slate-400 flex-shrink-0">{rightMeta}</div>}
      </div>
      <div className={`text-xs font-medium ${theme.iconColor} ml-6`}>{verdict}</div>
      {detail && <div className="text-[11px] text-slate-500 dark:text-slate-400 ml-6 mt-1">{detail}</div>}
      {checkedAt && (
        <div className="text-[10px] text-slate-400 dark:text-slate-500 ml-6 mt-1.5">
          Checked {fmtCheckedAt(checkedAt)}
        </div>
      )}
    </div>
  );
}

function NotCheckedCard({ title, reason }: { title: string; reason: string }) {
  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-white/[0.02] p-3 opacity-60">
      <div className="flex items-center gap-2 mb-1">
        <i className="ph-duotone ph-clock-countdown text-base text-slate-400 flex-shrink-0" />
        <span className="text-xs font-semibold text-slate-600 dark:text-slate-300">{title}</span>
      </div>
      <div className="text-[11px] text-slate-500 dark:text-slate-400 ml-6">{reason}</div>
    </div>
  );
}

// --- URLhaus ---
function UrlhausCard({ r }: { r: ReputationResult }) {
  if (r.urlhaus_status === 'malware') {
    return (
      <ProviderCard
        title="URLhaus"
        severity="malicious"
        verdict="Known malware distributor"
        detail={
          <>
            {r.urlhaus_threat && <>Tagged as <span className="font-mono text-slate-600 dark:text-slate-300">{r.urlhaus_threat}</span></>}
            {r.urlhaus_url_count ? ` · ${r.urlhaus_url_count} malicious URL${r.urlhaus_url_count === 1 ? '' : 's'} observed` : null}
          </>
        }
        checkedAt={r.urlhaus_checked_at}
      />
    );
  }
  if (r.urlhaus_status === 'clean') {
    return (
      <ProviderCard
        title="URLhaus"
        severity="clean"
        verdict="Not in malware database"
        detail="abuse.ch has not observed this target distributing malware."
        checkedAt={r.urlhaus_checked_at}
      />
    );
  }
  return <NotCheckedCard title="URLhaus" reason="Not yet checked against the malware database." />;
}

// --- ThreatFox ---
function ThreatfoxCard({ r }: { r: ReputationResult }) {
  if (r.threatfox_status === 'c2') {
    return (
      <ProviderCard
        title="ThreatFox"
        severity="malicious"
        verdict="Known C2 infrastructure"
        detail={r.threatfox_malware ? <>Associated with <span className="font-mono text-slate-600 dark:text-slate-300">{r.threatfox_malware}</span></> : 'Command & control server identified by abuse.ch.'}
        checkedAt={r.threatfox_checked_at}
      />
    );
  }
  if (r.threatfox_status === 'clean') {
    return (
      <ProviderCard
        title="ThreatFox"
        severity="clean"
        verdict="Not a known C2 server"
        detail="Not listed in the command & control infrastructure database."
        checkedAt={r.threatfox_checked_at}
      />
    );
  }
  return <NotCheckedCard title="ThreatFox" reason="Not yet checked against the C2 database." />;
}

// --- AbuseIPDB ---
function AbuseipdbCard({ r, errors }: { r: ReputationResult; errors: string[] }) {
  if (r.abuseipdb_score == null) {
    const err = errors.find(e => e.includes('AbuseIPDB'));
    return <NotCheckedCard title="AbuseIPDB" reason={err || 'No API key configured — add one in Settings → Reputation.'} />;
  }

  const sc = r.abuseipdb_score;
  const reports = r.abuseipdb_reports || 0;
  const severity: Severity = sc >= 75 ? 'malicious' : sc >= 25 ? 'suspicious' : sc >= 1 ? 'low' : 'clean';
  const verdict =
    sc >= 75 ? 'High abuse confidence' :
    sc >= 25 ? 'Some abuse reports' :
    sc >= 1  ? 'Minor abuse reports' :
               'No abuse reports';
  const detail =
    reports === 0
      ? 'This IP has not been reported for abuse.'
      : `${reports} user${reports === 1 ? '' : 's'} ${reports === 1 ? 'has' : 'have'} reported this IP for abusive activity.`;

  const theme = SEVERITY_THEME[severity];
  const barColor = sc >= 75 ? 'bg-red-500' : sc >= 25 ? 'bg-amber-500' : sc >= 1 ? 'bg-lime-500' : 'bg-emerald-500';

  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-white/[0.02] p-3">
      <div className="flex items-start justify-between gap-2 mb-1.5">
        <div className="flex items-center gap-2 min-w-0">
          <i className={`ph-duotone ${theme.icon} text-base ${theme.iconColor} flex-shrink-0`} />
          <span className="text-xs font-semibold text-slate-700 dark:text-slate-200">AbuseIPDB</span>
        </div>
        <div className="text-[10px] tabular-nums text-slate-500 dark:text-slate-400">
          <span className={`font-bold ${theme.iconColor}`}>{sc}%</span> confidence
        </div>
      </div>
      <div className={`text-xs font-medium ${theme.iconColor} ml-6`}>{verdict}</div>
      {/* Progress bar */}
      <div className="ml-6 mt-1.5 h-1.5 rounded-full bg-slate-200 dark:bg-white/[0.06] overflow-hidden">
        <div className={`h-full ${barColor} transition-all`} style={{ width: `${Math.max(2, sc)}%` }} />
      </div>
      <div className="text-[11px] text-slate-500 dark:text-slate-400 ml-6 mt-1.5">{detail}</div>
      {r.abuseipdb_checked_at && (
        <div className="text-[10px] text-slate-400 dark:text-slate-500 ml-6 mt-1.5">
          Checked {fmtCheckedAt(r.abuseipdb_checked_at)}
        </div>
      )}
    </div>
  );
}

// --- VirusTotal ---
function VirusTotalCard({ r, errors }: { r: ReputationResult; errors: string[] }) {
  if (r.vt_malicious == null) {
    const err = errors.find(e => e.includes('VirusTotal'));
    return <NotCheckedCard title="VirusTotal" reason={err || 'No API key configured — add one in Settings → Reputation.'} />;
  }

  const m = r.vt_malicious;
  const total = r.vt_total || 0;
  const severity: Severity = m >= 5 ? 'malicious' : m >= 1 ? 'suspicious' : 'clean';
  const verdict =
    m >= 5 ? 'Multiple vendors flagged' :
    m >= 1 ? 'A few vendors flagged' :
             'All vendors clean';
  const detail =
    m === 0
      ? `${total} security ${total === 1 ? 'engine' : 'engines'} checked · none flagged as malicious.`
      : `${m} of ${total} security vendors classified this as malicious.`;

  return (
    <ProviderCard
      title="VirusTotal"
      severity={severity}
      verdict={verdict}
      detail={detail}
      checkedAt={r.vt_checked_at}
      rightMeta={<><span className={`font-bold ${SEVERITY_THEME[severity].iconColor}`}>{m}</span>/{total} flagged</>}
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
  // Hard malicious signals
  if (r.urlhaus_status === 'malware' || r.threatfox_status === 'c2') {
    const parts: string[] = [];
    if (r.urlhaus_status === 'malware') parts.push('malware distribution');
    if (r.threatfox_status === 'c2') parts.push('C2 infrastructure');
    return {
      severity: 'malicious',
      label: 'Known malicious',
      subtitle: `Flagged for ${parts.join(' and ')} by abuse.ch threat intelligence.`,
    };
  }
  if ((r.abuseipdb_score ?? 0) >= 75 || (r.vt_malicious ?? 0) >= 5) {
    return {
      severity: 'malicious',
      label: 'Likely malicious',
      subtitle: 'High abuse confidence or multiple security vendors flagged this target.',
    };
  }

  // Suspicious signals
  if ((r.abuseipdb_score ?? 0) >= 25 || (r.vt_malicious ?? 0) >= 1) {
    return {
      severity: 'suspicious',
      label: 'Suspicious activity',
      subtitle: 'Some providers have flagged this target. Review the per-provider details below.',
    };
  }

  // Low risk — minor abuse reports
  if ((r.abuseipdb_score ?? 0) >= 1) {
    return {
      severity: 'low',
      label: 'Low risk',
      subtitle: 'A small number of abuse reports exist, but no critical threat signals.',
    };
  }

  // Clean signals
  const anyClean =
    r.urlhaus_status === 'clean' ||
    r.threatfox_status === 'clean' ||
    r.abuseipdb_score === 0 ||
    r.vt_malicious === 0;

  if (anyClean) {
    return {
      severity: 'clean',
      label: 'Looks clean',
      subtitle: 'No threat signals found in the checked providers.',
    };
  }

  return {
    severity: 'unknown',
    label: 'No data available',
    subtitle: 'None of the configured providers returned data for this target.',
  };
}
