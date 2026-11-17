export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export type Verdict = 'Looks clean' | 'Incomplete check' | 'Needs attention' | 'At risk' | 'Likely compromised';
export type Counts = Record<Severity, number>;

export interface Finding { severity: Severity; category: string; title: string; detail: string; recommendation: string; mitre?: string | null; ruleId?: string | null; evidence?: unknown; accepted?: boolean; acceptedReason?: string | null }
export interface Highlight { severity: Severity; category: string; title: string; recommendation: string; count: number; ruleId?: string | null; mitre?: string | null }
export interface ScanSummary { id: number; time: string; score: number; verdict: Verdict; counts: Counts; quick: boolean }
export interface DiffItem { severity: Severity; title: string }
export interface ScanDetail { summary: ScanSummary; findings: Finding[]; highlights: Highlight[]; diff: { first: boolean; new: DiffItem[]; resolved: DiffItem[] } }
export interface AgentConfig { dailyScanTime: string; quickScheduledScans: boolean; notifyOnNewFindings: boolean; keepScans: number }
export interface AppState {
  version: string; edition: string; elevated: boolean; machine: string; os?: string; scanning: boolean; exePath?: string; exeSha256?: string; webview?: string;
  rules: { version: string; trusted: boolean };
  update?: { version: string; notes: string; published: string; size: number; status?: string | null } | null;
  agent: { installed: boolean; running: boolean; nextScan?: string | null; config: AgentConfig };
}
export interface Settings {
  path?: string; modules?: string[];
  values: { runDefenderQuickScan: boolean; runYara: boolean; runAutoruns: boolean; eventLogDays: number; recentFileDays: number; onlineLookups: boolean; onlineLookupsAsked?: boolean; reputationCircl: boolean; reputationDefender: boolean; scanArchives?: boolean; rememberFileChecks?: boolean; checkForUpdates?: boolean };
  secrets: Record<'virusTotal' | 'malwareBazaar', { set: boolean; hint?: string }>;
}
export interface SuppressionItem { id: string; kind: 'finding' | 'rule' | 'path' | 'file'; title: string; reason: string; ruleId?: string | null; path?: string | null; created: string; until?: string | null }
