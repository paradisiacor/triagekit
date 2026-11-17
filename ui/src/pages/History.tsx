import { useEffect, useState } from 'react';
import { motion } from 'motion/react';
import { ChevronRight, FileText, History as HistoryIcon, ArrowUpRight, ArrowDownRight } from 'lucide-react';
import clsx from 'clsx';
import { call } from '../lib/api';
import { openScan, safe, useStore } from '../lib/store';
import { VERDICT_COLOR, fmtTime, plural } from '../lib/format';
import type { ScanDetail } from '../lib/types';
import { Glass, PageHeader, Sev, Empty } from '../components/ui';
import { TrendChart } from '../components/charts';

export default function HistoryPage() {
  const scans = useStore((s) => s.scans);
  const [sel, setSel] = useState<number | null>(null);
  const [det, setDet] = useState<ScanDetail | null>(null);
  const id = sel ?? scans[0]?.id;
  useEffect(() => { if (id != null) { setDet(null); safe(() => call<ScanDetail>('scan.get', { id })).then(setDet); } }, [id]);

  if (!scans.length) return (
    <div className="mx-auto max-w-[1100px]"><PageHeader eyebrow="History" title="No checks yet" />
      <Glass><Empty icon={<HistoryIcon className="h-6 w-6" />} title="Your checks will be listed here" text="Run checks regularly to see your score over time and exactly what changed." /></Glass></div>);

  const best = Math.max(...scans.map((s) => s.score)), avg = Math.round(scans.reduce((a, s) => a + s.score, 0) / scans.length);
  const delta = scans.length > 1 ? scans[0].score - scans[1].score : 0;

  return (
    <div className="mx-auto max-w-[1320px]">
      <PageHeader eyebrow="History" title="Score over time" sub={`${plural(scans.length, 'check')} on this device`} />
      <Glass className="p-7">
        <div className="mb-4 flex gap-10">
          {[['Latest', scans[0].score], ['Average', avg], ['Best', best]].map(([l, v]) => (
            <div key={l as string}><div className="label">{l}</div><div className="num mt-1 text-[40px] leading-none">{v}</div></div>
          ))}
          <div><div className="label">Change</div>
            <div className={clsx('mt-1 flex items-center gap-1 text-[40px] leading-none num', delta > 0 ? 'text-ok' : delta < 0 ? 'text-high' : '')}>{delta > 0 ? <ArrowUpRight className="h-7 w-7" /> : delta < 0 ? <ArrowDownRight className="h-7 w-7" /> : null}{Math.abs(delta)}</div></div>
        </div>
        <TrendChart scans={scans.slice(0, 30)} height={220} onPick={setSel} picked={id} />
      </Glass>

      <div className="mt-4 grid grid-cols-1 items-start gap-4 xl:grid-cols-[1.1fr_1fr]">
        <Glass className="overflow-hidden">
          <div className="px-6 pb-3 pt-5 text-[15px] font-medium">All checks</div>
          {scans.map((s) => (
            <button key={s.id} onClick={() => setSel(s.id)} className={clsx('flex w-full items-center gap-4 border-t border-white/[0.05] px-6 py-3.5 text-left transition hover:bg-white/[0.03]', id === s.id && 'bg-white/[0.05]')}>
              <div className="num grid h-11 w-14 place-items-center rounded-xl text-[22px]" style={{ color: VERDICT_COLOR[s.verdict], background: VERDICT_COLOR[s.verdict] + '17' }}>{s.score}</div>
              <div className="min-w-0 flex-1"><div className="text-[14px]">{s.verdict}</div><div className="text-[12px] text-muted">{fmtTime(s.time)} · {s.quick ? 'Quick' : 'Full'}</div></div>
              <div className="flex gap-1.5">{(['Critical', 'High', 'Medium'] as const).filter((k) => s.counts[k]).map((k) => <Sev key={k} s={k}>{s.counts[k]} {k[0]}</Sev>)}</div>
              <ChevronRight className="h-4 w-4 text-dim" />
            </button>
          ))}
        </Glass>
        <div className="sticky top-0">
          <Glass strong className="p-7">
            {!det ? <div className="text-muted">Loading…</div> : (
              <motion.div key={det.summary.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                <div className="label">{fmtTime(det.summary.time)}</div>
                <div className="mt-2 text-[26px] font-[350]" style={{ color: VERDICT_COLOR[det.summary.verdict] }}>{det.summary.verdict}</div>
                <div className="text-[13px] text-muted">Score {det.summary.score}/100 · {det.summary.quick ? 'quick' : 'full'} check</div>
                <h3 className="mt-6 text-[14px] font-medium">New since the previous check <span className="text-dim">({det.diff.new.length})</span></h3>
                <div className="mt-2 flex flex-col gap-2">
                  {det.diff.new.length ? det.diff.new.slice(0, 10).map((x, i) => <div key={i} className="flex items-start gap-2.5 text-[13px]"><Sev s={x.severity} /><span className="pt-0.5">{x.title}</span></div>)
                    : <div className="text-[13px] text-muted">{det.diff.first ? 'This was the first check.' : 'Nothing new.'}</div>}
                </div>
                <h3 className="mt-6 text-[14px] font-medium">Fixed or gone <span className="text-dim">({det.diff.resolved.length})</span></h3>
                <div className="mt-2 flex flex-col gap-2">
                  {det.diff.resolved.length ? det.diff.resolved.slice(0, 10).map((x, i) => <div key={i} className="flex items-start gap-2.5 text-[13px]"><span className="chip sev" style={{ ['--c' as any]: '#34e0a1' }}>Fixed</span><span className="pt-0.5 text-muted line-through decoration-white/20">{x.title}</span></div>)
                    : <div className="text-[13px] text-muted">Nothing resolved.</div>}
                </div>
                <div className="mt-7 flex gap-2">
                  <button className="btn btn-primary" onClick={() => openScan(det.summary.id)}>Open findings</button>
                  <button className="btn" onClick={() => call('report.open', { id: det.summary.id })}><FileText className="h-4 w-4" />Report</button>
                </div>
              </motion.div>
            )}
          </Glass>
        </div>
      </div>
    </div>
  );
}
