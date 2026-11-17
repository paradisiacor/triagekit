import { useEffect, useRef, useState } from 'react';
import { motion } from 'motion/react';
import clsx from 'clsx';
import { PackageSearch, Binoculars, FileUp, FolderUp, Loader2, ShieldAlert, ShieldCheck, ShieldX, ShieldQuestion, ChevronDown, Lightbulb, X, Camera, ArrowRight, RotateCcw, Trash2, CircleSlash, Info } from 'lucide-react';
import { call, on, sendFiles } from '../lib/api';
import { safe, toast, useStore } from '../lib/store';
import { SEV_COLOR, ago, fmtTime, plural } from '../lib/format';
import type { Severity } from '../lib/types';
import { Glass, PageHeader, Sev, confirmDialog } from '../components/ui';

// ---------------------------------------------------------------- types (shapes come from the app as JSON)
interface Pick { token: string; name: string; path: string; folder: boolean; size: number }
interface SFinding { severity: Severity; title: string; detail: string; recommendation: string; ruleId?: string }
interface SItem { path: string; kind: string; size: number; sha256?: string; signer?: string; signature: string; risk: Severity; reasons: string[]; note?: string }
interface CheckResult { target: string; name: string; started: string; seconds: number; verdict: 'NoThreatsFound' | 'Suspicious' | 'Dangerous' | 'KnownMalware'; headline: string; summary: string;
  downloadedFrom?: string; files: number; programs: number; archives: number; onlineLookups: boolean; notChecked: string[]; items: SItem[]; findings: SFinding[]; stopped: boolean }
interface Change { category: string; kind: string; text: string; severity: Severity; why: string }
interface WatchResult { before: string; after: string; verdict: 'NothingWorrying' | 'Review' | 'Dangerous'; headline: string; summary: string; newFindings: SFinding[]; goneFindings: SFinding[]; added: Change[]; removed: Change[]; unchanged: number; notes: string[] }
interface WatchState { before: { taken: string; machine: string; items: number; findings: number } | null; last?: string | null }

const VERDICT_UI = {
  NoThreatsFound: { color: '#34e0a1', icon: ShieldCheck }, Suspicious: { color: '#f7b52c', icon: ShieldQuestion },
  Dangerous: { color: '#ff6a3d', icon: ShieldAlert }, KnownMalware: { color: '#ff3d5a', icon: ShieldX },
  NothingWorrying: { color: '#34e0a1', icon: ShieldCheck }, Review: { color: '#f7b52c', icon: ShieldQuestion },
} as const;

const fmtSize = (n: number) => n >= 1 << 30 ? `${(n / (1 << 30)).toFixed(1)} GB` : n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} B`;

export default function SafeStart() {
  const [tab, setTab] = useState<'check' | 'watch'>(() => (sessionStorage.getItem('tk.safestart.tab') as any) || 'check');
  useEffect(() => { try { sessionStorage.setItem('tk.safestart.tab', tab); } catch { } }, [tab]);
  return (
    <div className="mx-auto max-w-[1180px]">
      <PageHeader eyebrow="Safe Start" title="Check it before you run it"
        sub="Downloaded a game, a mod, a crack or a tool? TriageKit looks inside without running anything, and Install Watch shows exactly what an install changed." />
      <div className="mb-5 inline-flex rounded-2xl border border-white/10 bg-white/[0.03] p-1" role="tablist">
        {([['check', 'Check a download', PackageSearch], ['watch', 'Install Watch', Binoculars]] as const).map(([k, label, I]) => (
          <button key={k} role="tab" aria-selected={tab === k} onClick={() => setTab(k)}
            className={clsx('flex items-center gap-2 rounded-xl px-4 py-2 text-[13.5px] transition-colors', tab === k ? 'bg-white/10 text-ink' : 'text-muted hover:text-ink')}>
            <I className="h-4 w-4" />{label}
          </button>
        ))}
      </div>
      {tab === 'check' ? <CheckTab /> : <WatchTab />}
    </div>
  );
}

// ================================================================ Check a download
function CheckTab() {
  const elevated = useStore((s) => !!s.app?.elevated);
  const [picked, setPicked] = useState<Pick | null>(null);
  const [running, setRunning] = useState<{ name: string; text: string; files: number } | null>(null);
  const [result, setResult] = useState<CheckResult | null>(null);
  const [history, setHistory] = useState<{ id: string; name: string; verdict: CheckResult['verdict']; started: string; files: number }[]>([]);
  const [over, setOver] = useState(false);
  const loadHistory = () => safe(() => call('safestart.history')).then((h: any) => h && setHistory(h));

  useEffect(() => {
    loadHistory();
    const offs = [
      on('safestart.dropped', (d) => { if (d) { setPicked(d); setResult(null); } else toast("That item can't be checked."); }),
      on('safestart.started', (d) => setRunning({ name: d.name, text: 'Starting…', files: 0 })),
      on('safestart.progress', (d) => setRunning((r) => r && { ...r, text: d.text, files: d.files })),
      on('safestart.done', (d) => { setRunning(null); setResult(d.result); setPicked(null); loadHistory(); }),
      on('safestart.failed', (d) => { setRunning(null); toast(d.message); }),
    ];
    return () => offs.forEach((f) => f());
  }, []);

  const pick = (folder: boolean) => safe(() => call<Pick | null>('safestart.pick', { folder })).then((p) => { if (p) { setPicked(p); setResult(null); } });
  const start = (p: Pick) => safe(() => call('safestart.check', { token: p.token }));
  const open = (id: string) => safe(() => call<CheckResult>('safestart.get', { id })).then((r) => r && setResult(r));

  if (running) return <Working title={`Checking ${running.name}`} text={running.text} sub={`${plural(running.files, 'file')} looked at · nothing is opened or run`} onStop={() => call('safestart.cancel')} />;
  if (result) return <CheckResultView r={result} onBack={() => setResult(null)} />;

  return (
    <div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
      <Glass strong className={clsx('relative overflow-hidden p-8 transition-colors', over && '!border-brand/60 !bg-brand/[0.07]')}
        onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)}
        onDrop={(e) => { e.preventDefault(); setOver(false); if (e.dataTransfer.files.length) sendFiles(e.dataTransfer.files); }}>
        <div className="absolute -right-20 -top-20 h-64 w-64 rounded-full bg-brand opacity-[0.12] blur-[90px]" />
        {picked ? (
          <div className="relative">
            <div className="label">Ready to check</div>
            <div className="mt-3 flex items-center gap-3">
              <div className="grid h-12 w-12 place-items-center rounded-2xl border border-white/10 bg-white/5 text-brand-2">{picked.folder ? <FolderUp className="h-5 w-5" /> : <FileUp className="h-5 w-5" />}</div>
              <div className="min-w-0"><div className="truncate text-[17px]">{picked.name}</div><div className="select-text truncate font-mono text-[11.5px] text-dim">{picked.path}{!picked.folder && picked.size ? ` · ${fmtSize(picked.size)}` : ''}</div></div>
            </div>
            <div className="mt-6 flex flex-wrap gap-2">
              <button className="btn btn-primary btn-lg" onClick={() => start(picked)}><PackageSearch className="h-4 w-4" />Check it</button>
              <button className="btn btn-lg" onClick={() => setPicked(null)}>Choose something else</button>
            </div>
          </div>
        ) : (
          <div className="relative flex flex-col items-start">
            <div className="grid h-14 w-14 place-items-center rounded-2xl border border-white/10 bg-white/5 text-brand-2"><PackageSearch className="h-6 w-6" /></div>
            <h2 className="mt-5 text-[22px] font-[400] tracking-[-0.02em]">Choose a download to check</h2>
            <p className="mt-2 max-w-[56ch] text-[13.5px] leading-relaxed text-muted">A file, a whole folder or an archive (ZIP, RAR, 7z, TAR, GZip), including archives inside archives. Nothing is unpacked to disk or run.</p>
            <div className="mt-6 flex flex-wrap gap-2">
              <button className="btn btn-primary btn-lg" onClick={() => pick(false)}><FileUp className="h-4 w-4" />Choose file</button>
              <button className="btn btn-lg" onClick={() => pick(true)}><FolderUp className="h-4 w-4" />Choose folder</button>
            </div>
            <p className="mt-4 text-[12px] text-dim">{elevated ? 'Windows doesn\'t allow dragging files into apps running as administrator, so use the buttons.' : 'Or drop a file or folder here.'}</p>
          </div>
        )}
      </Glass>
      <Glass className="p-6">
        <div className="label">What gets checked</div>
        <ul className="mt-3 space-y-2.5 text-[13px] leading-relaxed text-muted">
          {['Every program, script and shortcut, even inside archives', 'Signatures: is it really from who it claims, and unchanged since signing?', 'TriageKit\'s malware rules for stealers, loaders and droppers',
            'Tricks used in cracks and fake downloads: disguised files, fake installers, padded loaders, "disable your antivirus" readmes', 'File fingerprints with reputation services, if you allowed online lookups'].map((t) => (
            <li key={t} className="flex gap-2.5"><ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-ok" />{t}</li>
          ))}
        </ul>
        {history.length > 0 && (
          <>
            <div className="label mt-7">Recent checks</div>
            <div className="mt-2 flex flex-col">
              {history.slice(0, 6).map((h) => {
                const v = VERDICT_UI[h.verdict];
                return (
                  <button key={h.id} onClick={() => open(h.id)} className="flex items-center gap-3 rounded-xl px-2 py-2 text-left hover:bg-white/[0.04]">
                    <v.icon className="h-4 w-4 shrink-0" style={{ color: v.color }} />
                    <span className="min-w-0 flex-1 truncate text-[13px]">{h.name}</span>
                    <span className="shrink-0 font-mono text-[11px] text-dim">{ago(h.started)}</span>
                  </button>
                );
              })}
            </div>
          </>
        )}
      </Glass>
    </div>
  );
}

function CheckResultView({ r, onBack }: { r: CheckResult; onBack: () => void }) {
  const v = VERDICT_UI[r.verdict];
  const [allItems, setAllItems] = useState(false);
  const flagged = r.items.filter((i) => i.reasons.length > 0 || i.note);
  const shownItems = allItems ? r.items : flagged.slice(0, 50);
  return (
    <div className="flex flex-col gap-4">
      <Glass strong className="relative overflow-hidden p-8">
        <div className="absolute -right-24 -top-24 h-72 w-72 rounded-full opacity-25 blur-[90px]" style={{ background: v.color }} />
        <div className="relative flex flex-wrap items-start gap-6">
          <div className="grid h-16 w-16 shrink-0 place-items-center rounded-2xl border" style={{ color: v.color, borderColor: v.color + '55', background: v.color + '14' }}><v.icon className="h-8 w-8" /></div>
          <div className="min-w-0 flex-1">
            <div className="label">{r.name} · checked {fmtTime(r.started)} · {r.seconds < 1 ? '<1' : Math.round(r.seconds)} s</div>
            <h2 className="mt-2 text-[28px] font-[380] leading-tight tracking-[-0.02em]" style={{ color: v.color }}>{r.headline}</h2>
            <p className="mt-2 max-w-[80ch] text-[14px] leading-relaxed text-muted">{r.summary}</p>
            <div className="mt-5 flex flex-wrap gap-2 font-mono text-[11.5px] text-dim">
              <span className="chip">{plural(r.files, 'file')}</span><span className="chip">{plural(r.programs, 'program')} &amp; scripts</span>
              {r.archives > 0 && <span className="chip">{plural(r.archives, 'archive')} opened</span>}
              <span className="chip">{r.onlineLookups ? 'reputation looked up online' : 'no online lookups'}</span>
              {r.downloadedFrom && <span className="chip">downloaded from {r.downloadedFrom}</span>}
            </div>
          </div>
          <button className="btn" onClick={onBack}><RotateCcw className="h-4 w-4" />Check another</button>
        </div>
      </Glass>

      {r.findings.length > 0 && (
        <Glass className="p-2">
          <div className="px-4 pb-1 pt-3 label">Why ({r.findings.length})</div>
          {r.findings.slice().sort((a, b) => sevRank(a.severity) - sevRank(b.severity)).map((f, i) => <FindingRow key={i} f={f} />)}
        </Glass>
      )}

      {r.notChecked.length > 0 && (
        <Glass className="p-6">
          <div className="flex items-center gap-2 text-[14px]"><CircleSlash className="h-4 w-4 text-med" />Couldn't be checked ({r.notChecked.length})</div>
          <ul className="mt-3 space-y-1.5 font-mono text-[12px] text-muted">{r.notChecked.slice(0, 30).map((n, i) => <li key={i} className="select-text break-all">{n}</li>)}</ul>
          {r.notChecked.length > 30 && <div className="mt-2 text-[12px] text-dim">…and {r.notChecked.length - 30} more</div>}
        </Glass>
      )}

      <Glass className="p-6">
        <div className="flex items-center justify-between gap-4">
          <div className="text-[14px]">{allItems ? `All files (${r.items.length})` : flagged.length ? `Files with remarks (${flagged.length})` : 'No file needed a remark'}</div>
          {r.items.length > 0 && <button className="btn btn-sm" onClick={() => setAllItems(!allItems)}>{allItems ? 'Show only remarks' : `Show all ${r.items.length}`}</button>}
        </div>
        {shownItems.length > 0 && (
          <div className="mt-4 overflow-x-auto">
            <table className="w-full min-w-[720px] text-left text-[12.5px]">
              <thead className="label"><tr><th className="py-2 pr-3">Risk</th><th className="pr-3">File</th><th className="pr-3">Type</th><th className="pr-3">Signature</th><th className="pr-3 text-right">Size</th></tr></thead>
              <tbody>
                {shownItems.slice(0, 500).map((i, k) => (
                  <tr key={k} className="border-t border-white/[0.06] align-top">
                    <td className="py-2 pr-3"><Sev s={i.risk} /></td>
                    <td className="max-w-[460px] pr-3"><div className="select-text break-all font-mono text-[11.5px] text-ink">{i.path}</div>{i.reasons.map((x, n) => <div key={n} className="text-[12px] text-muted">{x}</div>)}{i.note && <div className="text-[12px] text-dim">{i.note}</div>}</td>
                    <td className="pr-3 text-muted">{i.kind}</td>
                    <td className="pr-3 text-muted">{i.signature}{i.signer ? <div className="text-[11.5px] text-dim">{i.signer}</div> : null}</td>
                    <td className="pr-3 text-right font-mono text-dim">{fmtSize(i.size)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {shownItems.length > 500 && <div className="mt-2 text-[12px] text-dim">Showing the first 500.</div>}
          </div>
        )}
      </Glass>
      <p className="px-1 text-[12px] text-dim">A clean result lowers the risk but can't prove a download is safe. Nothing was opened, unpacked to disk or run.</p>
    </div>
  );
}

// ================================================================ Install Watch
function WatchTab() {
  const [state, setState] = useState<WatchState | null>(null);
  const [running, setRunning] = useState<{ after: boolean; index: number; total: number; name: string } | null>(null);
  const [result, setResult] = useState<WatchResult | null>(null);
  const load = () => safe(() => call<WatchState>('watch.state')).then((s) => s && setState(s));
  useEffect(() => {
    load();
    const offs = [
      on('watch.started', (d) => setRunning({ after: d.after, index: 0, total: d.total, name: 'Starting…' })),
      on('watch.progress', (d) => setRunning((r) => r && { ...r, index: d.index, total: d.total, name: d.name })),
      on('watch.done', (d) => { setRunning(null); if (d.after) setResult(d.result); else toast('"Before" snapshot saved. Now install or run the program.'); load(); }),
      on('watch.failed', (d) => { setRunning(null); toast(d.message); }),
    ];
    return () => offs.forEach((f) => f());
  }, []);

  if (running) return <Working title={running.after ? 'Taking the "after" snapshot' : 'Taking the "before" snapshot'} text={running.name}
    sub={`${running.index} of ${running.total} areas · about 20–60 seconds`} pct={running.total ? running.index / running.total : 0} onStop={() => call('safestart.cancel')} />;
  if (result) return <WatchResultView r={result} onBack={() => { setResult(null); load(); }} />;
  if (!state) return null;

  const before = state.before;
  const steps = [
    { n: 1, title: 'Take a "before" snapshot', text: 'Records startup entries, tasks, services, drivers, Defender settings and exclusions, root certificates, browser extensions, hosts, proxy, DNS and installed programs.', done: !!before },
    { n: 2, title: 'Install or run the program', text: 'Do it as usual. You can close TriageKit or restart the PC in between; the snapshot is kept.', done: false },
    { n: 3, title: 'Compare', text: 'TriageKit takes an "after" snapshot and shows exactly what changed, with the risky changes first.', done: false },
  ];
  return (
    <div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
      <Glass strong className="relative overflow-hidden p-8">
        <div className="absolute -left-20 -bottom-24 h-64 w-64 rounded-full bg-brand opacity-[0.12] blur-[90px]" />
        <div className="relative flex flex-col gap-5">
          {steps.map((s) => (
            <div key={s.n} className="flex gap-4">
              <div className={clsx('grid h-9 w-9 shrink-0 place-items-center rounded-xl border font-mono text-[13px]', s.done ? 'border-ok/40 bg-ok/10 text-ok' : (s.n === 1 && !before) || (s.n > 1 && before) ? 'border-brand/50 bg-brand/10 text-brand-2' : 'border-white/10 text-dim')}>{s.done ? '✓' : s.n}</div>
              <div><div className="text-[15px]">{s.title}</div><div className="mt-1 max-w-[62ch] text-[13px] leading-relaxed text-muted">{s.text}</div>
                {s.n === 1 && before && <div className="mt-1.5 font-mono text-[11.5px] text-dim">Taken {fmtTime(before.taken)} ({ago(before.taken)}) · {plural(before.items, 'item')} recorded{before.machine ? ` on ${before.machine}` : ''}</div>}
              </div>
            </div>
          ))}
          <div className="mt-2 flex flex-wrap gap-2 pl-[52px]">
            {before ? (
              <>
                <button className="btn btn-primary btn-lg" onClick={() => safe(() => call('watch.after'))}><Binoculars className="h-4 w-4" />Compare now</button>
                <button className="btn btn-lg" onClick={async () => { if (await confirmDialog('Take a new "before" snapshot?', 'The current one will be replaced. Only do this if you haven\'t installed anything since it was taken.', 'Replace')) safe(() => call('watch.before')); }}><Camera className="h-4 w-4" />New snapshot</button>
                <button className="btn btn-lg" title="Delete the snapshot" onClick={() => safe(() => call('watch.discard')).then(load)}><Trash2 className="h-4 w-4" /></button>
              </>
            ) : <button className="btn btn-primary btn-lg" onClick={() => safe(() => call('watch.before'))}><Camera className="h-4 w-4" />Take "before" snapshot</button>}
          </div>
        </div>
      </Glass>
      <Glass className="p-6">
        <div className="label">Good to know</div>
        <ul className="mt-3 space-y-2.5 text-[13px] leading-relaxed text-muted">
          <li className="flex gap-2.5"><Info className="mt-0.5 h-4 w-4 shrink-0 text-brand-2" />Check the download first; Install Watch is for what happens once you run it.</li>
          <li className="flex gap-2.5"><Info className="mt-0.5 h-4 w-4 shrink-0 text-brand-2" />Take the snapshot right before installing: other programs updating in between also show up.</li>
          <li className="flex gap-2.5"><Info className="mt-0.5 h-4 w-4 shrink-0 text-brand-2" />Nothing is blocked or undone. You decide what to remove, and the result tells you how.</li>
        </ul>
        {state.last && <button className="btn btn-sm mt-6" onClick={() => safe(() => call<WatchResult>('safestart.get', { id: state.last })).then((r) => r && setResult(r))}>Open the last comparison <ArrowRight className="h-3.5 w-3.5" /></button>}
      </Glass>
    </div>
  );
}

function WatchResultView({ r, onBack }: { r: WatchResult; onBack: () => void }) {
  const v = VERDICT_UI[r.verdict];
  const groups = Array.from(new Set(r.added.map((a) => a.category)));
  return (
    <div className="flex flex-col gap-4">
      <Glass strong className="relative overflow-hidden p-8">
        <div className="absolute -right-24 -top-24 h-72 w-72 rounded-full opacity-25 blur-[90px]" style={{ background: v.color }} />
        <div className="relative flex flex-wrap items-start gap-6">
          <div className="grid h-16 w-16 shrink-0 place-items-center rounded-2xl border" style={{ color: v.color, borderColor: v.color + '55', background: v.color + '14' }}><v.icon className="h-8 w-8" /></div>
          <div className="min-w-0 flex-1">
            <div className="label">Install Watch · {fmtTime(r.before)} → {fmtTime(r.after)}</div>
            <h2 className="mt-2 text-[28px] font-[380] leading-tight tracking-[-0.02em]" style={{ color: v.color }}>{r.headline}</h2>
            <p className="mt-2 max-w-[80ch] text-[14px] leading-relaxed text-muted">{r.summary}</p>
            <div className="mt-5 flex flex-wrap gap-2 font-mono text-[11.5px] text-dim">
              <span className="chip">{plural(r.added.length, 'change')}</span><span className="chip">{plural(r.newFindings.length, 'new finding')}</span>
              {r.removed.length > 0 && <span className="chip">{r.removed.length} removed</span>}<span className="chip">{r.unchanged} unchanged</span>
            </div>
            {r.notes.map((n, i) => <div key={i} className="mt-3 text-[12.5px] text-med">{n}</div>)}
          </div>
          <button className="btn" onClick={onBack}><RotateCcw className="h-4 w-4" />Back</button>
        </div>
      </Glass>
      {r.newFindings.length > 0 && (
        <Glass className="p-2"><div className="px-4 pb-1 pt-3 label">New findings ({r.newFindings.length})</div>{r.newFindings.map((f, i) => <FindingRow key={i} f={f} />)}</Glass>
      )}
      {groups.map((g) => (
        <Glass key={g} className="p-6">
          <div className="text-[14px]">{g === 'Setting' ? 'Security settings changed' : `${g}${r.added.filter((a) => a.category === g).length > 1 ? 's' : ''} added`}</div>
          <div className="mt-1 text-[12.5px] text-muted">{r.added.find((a) => a.category === g)?.why}</div>
          <div className="mt-3 flex flex-col gap-1.5">
            {r.added.filter((a) => a.category === g).map((a, i) => (
              <div key={i} className="flex items-start gap-3 rounded-xl bg-white/[0.02] px-3 py-2"><Sev s={a.severity} /><span className="select-text break-all font-mono text-[12px] text-ink">{a.text}</span></div>
            ))}
          </div>
        </Glass>
      ))}
      {r.removed.length > 0 && (
        <details className="glass p-6"><summary className="cursor-pointer text-[14px]">Removed ({r.removed.length})</summary>
          <div className="mt-3 flex flex-col gap-1">{r.removed.map((a, i) => <div key={i} className="select-text break-all font-mono text-[12px] text-muted">{a.category}: {a.text}</div>)}</div>
        </details>
      )}
    </div>
  );
}

// ================================================================ shared
const sevRank = (s: Severity) => ['Critical', 'High', 'Medium', 'Low', 'Info'].indexOf(s);

function FindingRow({ f }: { f: SFinding }) {
  const [open, setOpen] = useState(sevRank(f.severity) <= 1);
  return (
    <div className="rounded-2xl px-4 py-3 hover:bg-white/[0.025]">
      <button className="flex w-full items-start gap-3 text-left" onClick={() => setOpen(!open)}>
        <Sev s={f.severity} /><span className="min-w-0 flex-1 text-[14px] leading-snug">{f.title}</span>
        <ChevronDown className={clsx('mt-0.5 h-4 w-4 shrink-0 text-dim transition-transform', open && 'rotate-180')} />
      </button>
      {open && (
        <motion.div initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} className="mt-2 pl-[68px]">
          <pre className="select-text whitespace-pre-wrap break-words font-sans text-[13px] leading-relaxed text-muted">{f.detail}</pre>
          {f.recommendation && <div className="mt-2 flex gap-2 rounded-xl border border-white/[0.06] bg-white/[0.03] px-3 py-2 text-[13px]" style={{ borderColor: SEV_COLOR[f.severity] + '33' }}><Lightbulb className="mt-0.5 h-4 w-4 shrink-0 text-brand-2" />{f.recommendation}</div>}
        </motion.div>
      )}
    </div>
  );
}

function Working({ title, text, sub, pct, onStop }: { title: string; text: string; sub: string; pct?: number; onStop: () => void }) {
  const t0 = useRef(Date.now());
  const [, tick] = useState(0);
  useEffect(() => { const i = setInterval(() => tick((x) => x + 1), 500); return () => clearInterval(i); }, []);
  const secs = Math.round((Date.now() - t0.current) / 1000);
  return (
    <Glass strong className="relative overflow-hidden p-10">
      <div className="absolute -right-24 -top-24 h-72 w-72 rounded-full bg-brand opacity-20 blur-[90px]" />
      <div className="relative flex items-start gap-5">
        <div className="grid h-14 w-14 shrink-0 place-items-center rounded-2xl border border-brand/40 bg-brand/10 text-brand-2"><Loader2 className="h-6 w-6 animate-spin" /></div>
        <div className="min-w-0 flex-1">
          <div className="label">{secs} s</div>
          <h2 className="mt-1 truncate text-[24px] font-[380] tracking-[-0.02em]">{title}</h2>
          <div className="mt-2 truncate font-mono text-[12px] text-muted">{text}</div>
          <div className="mt-1 text-[12.5px] text-dim">{sub}</div>
          {pct !== undefined && <div className="mt-5 h-1.5 overflow-hidden rounded-full bg-white/[0.06]"><motion.div className="h-full rounded-full bg-brand" animate={{ width: `${Math.max(4, pct * 100)}%` }} /></div>}
        </div>
        <button className="btn" onClick={onStop}><X className="h-4 w-4" />Stop</button>
      </div>
    </Glass>
  );
}
