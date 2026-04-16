import type { ReputationResult } from './reputationApi';

interface ReputationBadgeProps {
  ip: string;
  cache: Record<string, ReputationResult>;
}

export default function ReputationBadge({ ip, cache }: ReputationBadgeProps) {
  const r = cache[ip];
  if (!r) return null;

  const badges: { cls: string; label: string }[] = [];

  if (r.urlhaus_status === 'malware')
    badges.push({ cls: 'bg-red-600 text-white', label: `Malware${r.urlhaus_threat ? ` (${r.urlhaus_threat})` : ''}` });

  if (r.threatfox_status === 'c2')
    badges.push({ cls: 'bg-red-700 text-white', label: `C2${r.threatfox_malware ? ` (${r.threatfox_malware})` : ''}` });

  if (r.abuseipdb_score != null) {
    const sc = r.abuseipdb_score;
    const bg = sc >= 75 ? 'bg-red-600' : sc >= 25 ? 'bg-amber-600' : 'bg-emerald-600';
    badges.push({ cls: `${bg} text-white`, label: `Abuse: ${sc}%` });
  }

  if (r.vt_malicious != null && r.vt_total != null) {
    const bg = r.vt_malicious >= 5 ? 'bg-red-600' : r.vt_malicious >= 1 ? 'bg-amber-600' : 'bg-emerald-600';
    badges.push({ cls: `${bg} text-white`, label: `VT: ${r.vt_malicious}/${r.vt_total}` });
  }

  if (!badges.length) return null;

  return (
    <>
      {badges.map((b, i) => (
        <span key={i} className={`inline-flex text-[10px] px-1.5 py-0.5 rounded-full font-bold ${b.cls}`}>
          {b.label}
        </span>
      ))}
    </>
  );
}
