import { lazy, Suspense, useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Check, Loader2, Circle, X, Radar, Zap, Play, ArrowRight, FileText, RefreshCw, TriangleAlert, ScanSearch } from 'lucide-react';
import clsx from 'clsx';
import { call } from '../lib/api';
import { get, go, safe, set, startScan, useStore } from '../lib/store';
import { VERDICT_COLOR, VERDICT_LINE, plural } from '../lib/format';
import { Glass, PageHeader, confirmDialog, Counter } from '../components/ui';

const ShieldScene = lazy(() => import('../three/ShieldScene'));

export default function ScanPage() {
  const sc = useStore((s) => s.scan);
  const app = useStore((s) => s.app);
  const detail = useStore((s) => s.detail);
  const [now, setNow] = useState(Date.now());
  useEffect(() => { if (!sc.running) return; const t = setInterval(() => setNow(Date.now()), 250); return () => clearInterval(t); }, [sc.running]);

  if (!sc.running && !sc.result) {
    const Mode = ({ id, icon: I, title, time, items, primary }: any) => (
      <motion.button whileHover={{ y: -3 }} onClick={async () => {
        if (id === 'deep' && !(await confirmDialog('Start a deep check?', 'TriageKit will read every program and script in your user folders, ProgramData and Program Files and check them with its malware rules, in addition to the full check. It can take 20–60 minutes and uses more disk and CPU. Nothing is changed, deleted or uploaded. Only file fingerprints are looked up, as in a full check.', 'Start deep check'))) return;
        startScan(id);
      }} className="glass group flex flex-col !rounded-[26px] p-8 text-left">
        <div className="flex items-center justify-between">
          <div className={clsx('grid h-12 w-12 place-items-center rounded-2xl', primary ? 'bg-brand/15 text-brand-2' : 'bg-white/[0.06] text-ink')}><I className="h-5 w-5" /></div>
          <span className="chip">{time}</span>
        </div>
        <h2 className="mt-6 text-[26px] font-[350] tracking-[-0.02em]">{title}</h2>
        <ul className="mt-4 flex flex-col gap-2 text-[13.5px] text-muted">{items.map((x: string) => <li key={x} className="flex gap-2.5"><Check className="mt-0.5 h-4 w-4 shrink-0 text-ok" />{x}</li>)}</ul>
        <div className="mt-8"><span className={clsx('btn', primary && 'btn-primary')}><Play className="h-4 w-4" fill="currentColor" />Start {title.toLowerCase()}</span></div>
      </motion.button>
    );
    return (
      <div className="mx-auto max-w-[1100px]">
        <PageHeader eyebrow="Scan" title="Check this PC" sub="Read-only: TriageKit looks, it never changes, deletes or uploads anything." />
        <div className="grid grid-cols-3 gap-4">
          <Mode id="quick" icon={Zap} title="Quick check" time="≈ 1 min" items={['Antivirus, firewall and Windows settings', 'Programs, drivers and startup items', 'Certificates, privacy, crashes, disks, Discord', 'No file sweep, no online lookups']} />
          <Mode id="full" icon={Radar} title="Full check" time="5–10 min" primary items={['Everything in the quick check', 'Microsoft Defender quick scan', 'Malware rules on unsigned programs and scripts', 'Injected code in Windows processes', 'Reputation lookups by file fingerprint']} />
          <Mode id="deep" icon={ScanSearch} title="Deep check" time="20–60 min" items={['Everything in the full check', 'Malware rules on every unsigned program and script', 'User folders, ProgramData and Program Files', 'Asks for your OK before it starts']} />
        </div>
        {app && !app.elevated && (
          <Glass className="mt-4 flex items-center gap-3 p-5 text-[13.5px] text-muted"><TriangleAlert className="h-5 w-5 shrink-0 text-med" />TriageKit is running without administrator rights, so some checks will be incomplete. Restart it with “Run as administrator” for a full result.</Glass>
        )}
      </div>
    );
  }

  const done = !sc.running;
  // Percentage by expected work, not by count: the 20-second live measurement is most of a PC Doctor run, so the
  // number keeps moving while it runs instead of sitting at one value. Never reaches 100 before the check is done.
  // Typical durations: the deep scan reads every program and script (often 20+ minutes), so the number keeps
  // climbing slowly through it instead of sitting at 97%.
  const expected = (n: string) => /\((\d+) s\)/.test(n) ? Number(/\((\d+) s\)/.exec(n)![1]) * 1000 : /deep scan/i.test(n) ? 20 * 60000 : /yara|reputation/i.test(n) ? 60000 : /file|malware/i.test(n) ? 15000 : 3000;
  const totalW = sc.checks.reduce((a, c) => a + expected(c.name), 0) || 1;
  const doneW = sc.checks.reduce((a, c) => a + (c.state === 'ok' ? expected(c.name) : c.state === 'run' && c.t0 ? Math.min(0.92, (now - c.t0) / expected(c.name)) * expected(c.name) : 0), 0);
  const pct = done ? 100 : Math.min(99, Math.round((100 * doneW) / totalW));
  const r = sc.result;
  const tone = done && r ? VERDICT_COLOR[r.verdict] : '#4c9dff';
  const current = sc.checks.find((c) => c.state === 'run')?.name ?? (sc.running ? 'Finishing…' : 'Starting…');

  return (
    <div className="mx-auto max-w-[1320px]">
      <PageHeader eyebrow={done ? 'Finished' : sc.doctor ? 'PC Doctor in progress' : `${sc.deep ? 'Deep' : sc.quick ? 'Quick' : 'Full'} check in progress`} title={done ? 'Check complete' : sc.doctor ? 'Examining this PC' : 'Checking this PC'}
        sub={done ? 'Nothing on this PC was changed.' : 'Keep working as usual. Only file fingerprints are looked up; your files never leave this PC.'}
        actions={done
          ? <button className="btn" onClick={() => set({ scan: { ...get().scan, result: null } })}><RefreshCw className="h-4 w-4" />New check</button>
          : <button className="btn" disabled={sc.stopping} onClick={async () => { if (await confirmDialog('Stop the check?', 'Checks that already ran are kept and a partial report is written.', 'Stop check', true)) { set({ scan: { ...get().scan, stopping: true } }); await safe(() => call('scan.cancel')); } }}><X className="h-4 w-4" />{sc.stopping ? 'Stopping…' : 'Stop'}</button>} />

      <Glass className="grid min-h-[380px] grid-cols-[1fr_1.1fr] overflow-hidden !rounded-[28px]">
        <div className="relative">
          <Suspense fallback={null}><ShieldScene tone={tone} hotspots={Array(8).fill(tone)} scanning={!done} emblem={done && r ? (r.verdict === 'Looks clean' ? 'check' : 'alert') : 'none'} compact /></Suspense>
        </div>
        <div className="flex flex-col justify-center p-10">
          <AnimatePresence mode="wait">
            {done && r ? (
              <motion.div key="done" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                <div className="flex items-end gap-3"><Counter value={r.score} className="num text-[110px] leading-[0.85]" /><span className="mb-2 font-mono text-dim">/100</span></div>
                <div className="mt-4 text-[22px] font-[400]" style={{ color: tone }}>{r.verdict}</div>
                <p className="mt-2 max-w-[46ch] text-[14.5px] text-muted">{VERDICT_LINE[r.verdict]} {r.newCount ? `${plural(r.newCount, 'new issue')} since the previous check.` : ''}</p>
                <div className="mt-8 flex gap-2">
                  <button className="btn btn-primary btn-lg" onClick={() => go('findings')}>See what to fix<ArrowRight className="h-4 w-4" /></button>
                  <button className="btn btn-lg" onClick={() => detail && call('report.open', { id: detail.summary.id })}><FileText className="h-4 w-4" />Full report</button>
                </div>
              </motion.div>
            ) : (
              <motion.div key="run" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                <div className="flex items-end gap-2"><span className="num text-[110px] leading-[0.85]">{pct}</span><span className="mb-3 font-mono text-[18px] text-dim">%</span></div>
                <div className="label mt-8">Now checking</div>
                <AnimatePresence mode="wait">
                  <motion.div key={current} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 8 }} className="mt-2 text-[26px] font-[350] tracking-[-0.02em]">{current}</motion.div>
                </AnimatePresence>
                <div className="relative mt-5 h-1.5 overflow-hidden rounded-full bg-white/[0.07]">
                  <motion.div className="absolute inset-y-0 left-0 rounded-full bg-gradient-to-r from-brand to-brand-2 shadow-[0_0_16px] shadow-brand" animate={{ width: `${pct}%` }} transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }} />
                  <div className="absolute inset-0 animate-[shimmer_2s_linear_infinite] bg-[linear-gradient(90deg,transparent,#ffffff22,transparent)] bg-[length:50%_100%]" />
                </div>
                <div className="mt-3 h-5 truncate font-mono text-[12px] text-muted">{sc.status}</div>
                <div className="mt-1 text-[12px] text-dim">{sc.total} checks · started {new Date(sc.started).toLocaleTimeString()}</div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </Glass>

      <div className="mt-4 grid grid-cols-[repeat(auto-fill,minmax(230px,1fr))] gap-2.5">
        {sc.checks.map((c, i) => (
          <motion.div key={c.name} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.02 }}
            className={clsx('glass flex items-center gap-3 !rounded-2xl px-4 py-3.5 transition-colors', c.state === 'run' && '!border-brand/40 !bg-brand/[0.06]')}>
            <div className={clsx('grid h-8 w-8 place-items-center rounded-xl', c.state === 'ok' ? 'bg-ok/15 text-ok' : c.state === 'run' ? 'bg-brand/15 text-brand-2' : 'bg-white/[0.05] text-dim')}>
              {c.state === 'ok' ? <Check className="h-4 w-4" /> : c.state === 'run' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Circle className="h-3.5 w-3.5" strokeDasharray="3 3" />}
            </div>
            <div className="min-w-0">
              <div className={clsx('truncate text-[13.5px]', c.state === 'wait' ? 'text-muted' : 'text-ink')}>{c.name}</div>
              <div className="font-mono text-[11px] text-dim">{c.state === 'ok' ? (c.ms != null ? (c.ms < 1000 ? `${Math.max(1, Math.round(c.ms))} ms` : `${(c.ms / 1000).toFixed(1)} s`) : 'done') : c.state === 'run' ? 'checking…' : 'waiting'}</div>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
