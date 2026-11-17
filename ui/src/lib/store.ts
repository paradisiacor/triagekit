import { useSyncExternalStore } from 'react';
import { call, on } from './api';
import type { AppState, ScanDetail, ScanSummary, Settings, Counts, Verdict } from './types';

export type Route = 'overview' | 'scan' | 'findings' | 'history' | 'protection' | 'settings' | 'about' | 'doctor' | 'safestart';
export interface CheckState { name: string; state: 'wait' | 'run' | 'ok'; ms?: number; t0?: number; outcome?: 'ok' | 'skipped' | 'failed'; note?: string | null }
export interface ScanRun { running: boolean; quick: boolean; deep?: boolean; doctor?: boolean; checks: CheckState[]; index: number; total: number; status: string; started: number; stopping: boolean;
  result: null | { id: number; score: number; verdict: Verdict; counts: Counts; newCount: number; resolvedCount: number } }
export interface Toast { id: number; text: string; kind: 'ok' | 'err' }
export interface State {
  route: Route; app: AppState | null; scans: ScanSummary[]; detail: ScanDetail | null; settings: Settings | null;
  scan: ScanRun; toasts: Toast[]; focusRule: string | null; loaded: boolean; doctorRev?: number;
}

const idleScan: ScanRun = { running: false, quick: false, checks: [], index: 0, total: 0, status: '', started: 0, stopping: false, result: null };
const ROUTES = ['overview', 'scan', 'findings', 'history', 'protection', 'settings', 'about', 'doctor', 'safestart'];
const initialRoute = (ROUTES.includes(location.hash.slice(1)) ? location.hash.slice(1) : 'overview') as Route;
let state: State = { route: initialRoute, app: null, scans: [], detail: null, settings: null, scan: idleScan, toasts: [], focusRule: null, loaded: false };
const subs = new Set<() => void>();
export function set(patch: Partial<State> | ((s: State) => Partial<State>)) {
  state = { ...state, ...(typeof patch === 'function' ? patch(state) : patch) };
  subs.forEach((f) => f());
}
export function get() { return state; }
export function useStore<T>(sel: (s: State) => T): T {
  return useSyncExternalStore((cb) => { subs.add(cb); return () => subs.delete(cb); }, () => sel(state));
}

let toastSeq = 0;
export function toast(text: string, kind: Toast['kind'] = 'ok') {
  const id = ++toastSeq;
  set((s) => ({ toasts: [...s.toasts, { id, text, kind }] }));
  setTimeout(() => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })), 5000);
}
export async function safe<T>(fn: () => Promise<T>): Promise<T | null> {
  try { return await fn(); } catch (e: any) { toast(e?.message || String(e), 'err'); return null; }
}
export function go(route: Route, extra: Partial<State> = {}) { set({ route, ...extra }); }

export async function refresh(force = false) {
  const [app, scans] = await Promise.all([safe(() => call<AppState>('app.state')), safe(() => call<ScanSummary[]>('scans.list'))]);
  const list = scans ?? [];
  let detail = state.detail;
  const get = (id: number) => safe(() => call<ScanDetail>('scan.get', { id }));
  if (!list.length) detail = null;
  else if (force) detail = (await get(detail?.summary.id ?? list[0].id)) ?? detail;
  else if (detail?.summary.id !== list[0].id) detail = await get(list[0].id);
  set((s) => ({ app: app ?? s.app, scans: list, detail, loaded: true, scan: app?.scanning && !s.scan.running ? { ...s.scan, running: true } : s.scan }));
}
export async function openScan(id: number) {
  const d = await safe(() => call<ScanDetail>('scan.get', { id }));
  if (d) set({ detail: d, route: 'findings', focusRule: null });
}
export async function loadSettings() { const st = await safe(() => call<Settings>('settings.get')); if (st) set({ settings: st }); return st; }

export function startScan(mode: 'quick' | 'full' | 'deep' | 'doctor') {
  if (state.scan.running) { go('scan'); return; }
  const offline = state.settings ? !state.settings.values.onlineLookups : false;
  safe(async () => { await call('scan.start', { mode, offline }); go('scan'); });
}

// ---- live scan events
on('scan.started', (d) => { measured.clear(); reveal.length = 0; const now = Date.now();
  // Checks show as waiting until the app says they started ("scan.checkStart"): later groups (deep scan,
  // reputation, the live measurement) wait for earlier ones.
  set({ scan: { ...idleScan, running: true, quick: d.quick, deep: !!d.deep, doctor: !!d.doctor, checks: d.checks.map((name: string) => ({ name, state: 'wait' })), total: d.checks.length, status: 'Starting…', started: now } }); });
on('scan.checkStart', (d) => set((s) => ({ scan: { ...s.scan, checks: s.scan.checks.map((c): CheckState => c.name === d.name && c.state === 'wait' ? { ...c, state: 'run', t0: Date.now() } : c) } })));
// Checks run in parallel groups. "scan.progress" arrives when a check FINISHES (index = how many are done) and
// "scan.checkDone" carries its measured time. Many checks finish within milliseconds of each other, so finished
// checks are revealed one at a time (about 0.4 s apart) and the result screen waits until all are shown. This only
// paces the display: the checks themselves never run slower.
const REVEAL_MS = 420;
const measured = new Map<string, { ms: number; outcome?: 'ok' | 'skipped' | 'failed'; note?: string | null }>();
const reveal: { name: string; index: number; total: number }[] = [];
let revealTimer: ReturnType<typeof setInterval> | null = null;
let drained: (() => void)[] = [];
function revealNext() {
  const d = reveal.shift();
  if (!d) { if (revealTimer) clearInterval(revealTimer); revealTimer = null; const w = drained; drained = []; w.forEach((f) => f()); return; }
  set((s) => {
    const m = measured.get(d.name);
    const checks = s.scan.checks.map((c): CheckState => c.name === d.name ? { ...c, state: 'ok', ms: m?.ms ?? c.ms, outcome: m?.outcome ?? 'ok', note: m?.note } : c);
    return { scan: { ...s.scan, checks, index: Math.max(s.scan.index, checks.filter((c) => c.state === 'ok').length), total: d.total, status: '' } };
  });
}
function whenRevealed(): Promise<void> {
  if (!reveal.length && !revealTimer) return Promise.resolve();
  return new Promise((r) => drained.push(r));
}
on('scan.progress', (d) => {
  reveal.push({ name: d.name, index: d.index, total: d.total });
  if (!revealTimer) { revealNext(); revealTimer = setInterval(revealNext, REVEAL_MS); }
});
on('scan.checkDone', (d) => { measured.set(d.name, { ms: d.ms, outcome: d.state, note: d.note }); });
on('scan.status', (d) => set((s) => ({ scan: { ...s.scan, status: d.text } })));
on('scan.finished', async (d) => {
  await whenRevealed();
  await new Promise((r) => setTimeout(r, 700));   // let 100% register before the result appears
  if (d.doctor) {
    set((s) => ({ scan: { ...s.scan, running: false, stopping: false, result: null, checks: s.scan.checks.map((c) => ({ ...c, state: 'ok' as const })) }, route: 'doctor', doctorRev: (s.doctorRev ?? 0) + 1 }));
    toast('PC Doctor finished');
    return;
  }
  set((s) => ({ scan: { ...s.scan, running: false, stopping: false, result: d, index: s.scan.total, checks: s.scan.checks.map((c) => c.state === 'ok' ? c : { ...c, state: 'ok' }) } }));
  toast(`Check finished · ${d.verdict} (${d.score}/100)`);
  set({ detail: null });
  await refresh();
});
on('scan.failed', (d) => { set((s) => ({ scan: { ...s.scan, running: false, stopping: false } })); toast(d?.message || 'The scan failed.', 'err'); });
on('app.changed', () => refresh());
