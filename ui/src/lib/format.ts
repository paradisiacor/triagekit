import type { Severity, Verdict } from './types';
export const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info'];
export const SEV_COLOR: Record<Severity, string> = { Critical: '#ff3d5a', High: '#ff6a3d', Medium: '#f7b52c', Low: '#6cb6ff', Info: '#8b95a3' };
export const VERDICT_COLOR: Record<Verdict, string> = { 'Looks clean': '#34e0a1', 'Incomplete check': '#a7b4c6', 'Needs attention': '#f7b52c', 'At risk': '#ff6a3d', 'Likely compromised': '#ff3d5a' };
export const VERDICT_LINE: Record<Verdict, string> = {
  'Looks clean': 'No signs of malware or risky settings were found.',
  'Incomplete check': 'Nothing bad was found in what was checked, but parts of the check could not run. See the grey items below.',
  'Needs attention': 'No signs of an active infection, but a few things should be fixed.',
  'At risk': 'Important protections are missing or something suspicious was found.',
  'Likely compromised': 'Strong signs of malware. Disconnect from the internet and follow the steps below.',
};
export const fmtTime = (iso?: string | null) => iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'n/a';
export const fmtShort = (iso?: string | null) => iso ? new Date(iso).toLocaleString(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit' }) : 'n/a';
export function ago(iso?: string | null) {
  if (!iso) return 'never';
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return 'just now'; if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`; return `${Math.round(s / 86400)} days ago`;
}
export const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? '' : 's'}`;

export interface Area { key: string; name: string; short: string; cats: string[] }
export const AREAS: Area[] = [
  { key: 'av', name: 'Antivirus', short: 'Antivirus', cats: ['Defender', 'Scanners'] },
  { key: 'sys', name: 'Windows settings', short: 'Settings', cats: ['System', 'Hardening', 'Accounts'] },
  { key: 'proc', name: 'Programs & drivers', short: 'Programs', cats: ['Processes', 'Software', 'Drivers'] },
  { key: 'start', name: 'Startup & persistence', short: 'Startup', cats: ['Persistence'] },
  { key: 'net', name: 'Network & certificates', short: 'Network', cats: ['Network', 'Certificates'] },
  { key: 'priv', name: 'Camera, mic & privacy', short: 'Privacy', cats: ['Privacy'] },
  { key: 'evt', name: 'Activity logs', short: 'Logs', cats: ['Events'] },
  { key: 'web', name: 'Browsers', short: 'Browsers', cats: ['Browser'] },
  { key: 'acct', name: 'Accounts & sessions', short: 'Sessions', cats: ['Sessions', 'Gaming'] },
  { key: 'mal', name: 'Files & malware', short: 'Files', cats: ['Files', 'YARA', 'Reputation'] },
];
/** Risk 0..1 per area from findings (same diminishing logic as the score). */
export function areaRisk(findings: { severity: Severity; category: string }[], area: Area) {
  const w: Record<Severity, number> = { Critical: 1, High: .7, Medium: .35, Low: .12, Info: 0 };
  const fs = findings.filter((f) => area.cats.includes(f.category));
  let r = 0; for (const f of fs) r = r + (1 - r) * w[f.severity];
  return Math.min(1, r);
}
export function worst(fs: { severity: Severity }[]): Severity | null { return SEVERITIES.find((s) => fs.some((f) => f.severity === s)) ?? null; }
