import { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'motion/react';
import { Search, FileText, FolderOpen, Copy, ExternalLink, Sparkles, ChevronDown, ScanSearch, Play, Lightbulb, CheckCheck, Share2, EyeOff, X } from 'lucide-react';
import clsx from 'clsx';
import { call } from '../lib/api';
import { refresh, safe, set, startScan, toast, useStore } from '../lib/store';
import { AREAS, SEVERITIES, SEV_COLOR, fmtTime, plural } from '../lib/format';
import type { Finding, Severity } from '../lib/types';
import { Glass, PageHeader, Sev, Empty } from '../components/ui';

export default function Findings() {
  const d = useStore((s) => s.detail);
  const focus = useStore((s) => s.focusRule);
  const [sev, setSev] = useState<Severity | null>(null);
  const [area, setArea] = useState('');
  const [q, setQ] = useState('');
  const [sel, setSel] = useState<Finding | null>(null);
  const [showAll, setShowAll] = useState(false);
  const [accepting, setAccepting] = useState<Finding | null>(null);
  const [showAccepted, setShowAccepted] = useState(false);

  // A short list is shown straight away; only long lists start folded so the page opens on "what to do first".
  const autoOpened = useRef(false);
  useEffect(() => {
    if (!d || autoOpened.current) return;
    autoOpened.current = true;
    if (d.findings.length <= 15) setShowAll(true);
  }, [d]);

  // Deep links from the overview ("area:net" or a rule id).
  useEffect(() => {
    if (!d || !focus) return;
    if (focus.startsWith('area:')) { setArea(focus.slice(5)); setSev(null); setShowAll(true); setSel(null); setQ(''); window.scrollTo?.({ top: 0 }); document.querySelector('main')?.scrollTo?.({ top: 0 }); }
    else { const f = d.findings.find((x) => x.ruleId === focus || x.title === focus); if (f) { setSel(f); setShowAll(true); } }
    set({ focusRule: null });
  }, [focus, d]);

  const list = useMemo(() => (d?.findings ?? []).filter((f) => {
    if (f.accepted && !showAccepted) return false;
    if (sev && f.severity !== sev) return false;
    if (area) { const a = AREAS.find((x) => x.key === area); if (a && !a.cats.includes(f.category)) return false; }
    if (q) { const t = `${f.title} ${f.detail} ${f.category} ${f.ruleId ?? ''}`.toLowerCase(); if (!t.includes(q.toLowerCase())) return false; }
    return true;
  }).sort((a, b) => Number(!!a.accepted) - Number(!!b.accepted)), [d, sev, area, q, showAccepted]);
  const acceptedCount = (d?.findings ?? []).filter((f) => f.accepted).length;
  const current = sel && list.includes(sel) ? sel : list[0] ?? null;

  if (!d) return (
    <div className="mx-auto max-w-[1100px]"><PageHeader eyebrow="Findings" title="Nothing to show yet" />
      <Glass><Empty icon={<ScanSearch className="h-6 w-6" />} title="Run a check first" text="Findings from your latest check appear here." action={<button className="btn btn-primary" onClick={() => startScan('full')}><Play className="h-4 w-4" fill="currentColor" />Run full check</button>} /></Glass>
    </div>);

  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, d.findings.filter((f) => f.severity === s && !f.accepted).length])) as Record<Severity, number>;

  return (
    <div className="mx-auto max-w-[1320px]">
      <PageHeader eyebrow={`${d.summary.quick ? 'Quick' : 'Full'} check · ${fmtTime(d.summary.time)}`} title="Findings"
        sub={`${d.summary.verdict} · score ${d.summary.score}/100 · ${plural(d.findings.length, 'item')} recorded`}
        actions={<>
          <button className="btn" onClick={() => call('report.open', { id: d.summary.id })}><FileText className="h-4 w-4" />Full report</button>
          <button className="btn" title="A copy without your name, PC name, IP addresses and serial numbers" onClick={() => safe(async () => { await call('report.share', { id: d.summary.id }); toast('Shareable report saved as report-shareable.html'); })}><Share2 className="h-4 w-4" />Shareable report</button>
          <button className="btn btn-ghost" onClick={() => call('report.folder', { id: d.summary.id })}><FolderOpen className="h-4 w-4" />Evidence</button>
        </>} />

      {/* Opened from an area on the overview: show that area first, clearly, instead of the general summary. */}
      {area && (() => { const a = AREAS.find((x) => x.key === area); return (
        <Glass className="mb-5 flex items-center gap-3 p-4">
          <span className="label">Area</span><span className="text-[15px] font-medium">{a?.name}</span>
          <span className="chip">{plural(list.length, 'item')}</span>
          <button className="btn btn-ghost ml-auto !h-9" onClick={() => setArea('')}><X className="h-4 w-4" />Show all areas</button>
        </Glass>); })()}
      {/* Highlights: what most people need (hidden while one area is shown) */}
      {!area && <>
      <div className="mb-3 flex items-center gap-2"><Sparkles className="h-4 w-4 text-brand-2" /><h2 className="text-[17px] font-medium">What to do first</h2><span className="label ml-2">similar items grouped</span></div>
      {d.highlights.length === 0 ? (
        <Glass className="p-6 text-[14px] text-muted">Nothing important to fix. Only minor or informational items were found.</Glass>
      ) : (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2 2xl:grid-cols-3">
          {d.highlights.map((h, i) => (
            <motion.button key={i} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
              onClick={() => { const f = d.findings.find((x) => x.ruleId === h.ruleId) ?? null; setSel(f); setShowAll(true); setSev(null); setArea(''); setQ(''); setTimeout(() => document.getElementById('all')?.scrollIntoView({ behavior: 'smooth' }), 50); }}
              className="glass group relative flex flex-col overflow-hidden !rounded-[22px] p-5 text-left transition hover:border-white/20">
              <div className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent, ${SEV_COLOR[h.severity]}, transparent)` }} />
              <div className="flex items-center gap-2"><Sev s={h.severity} /><span className="chip">{h.category}</span>{h.count > 1 && <span className="chip">×{h.count}</span>}</div>
              <div className="mt-3 text-[15px] font-medium leading-snug">{h.title}</div>
              <div className="mt-3 flex gap-2.5 rounded-2xl bg-white/[0.035] p-3 text-[13px] leading-relaxed text-muted"><Lightbulb className="mt-0.5 h-4 w-4 shrink-0 text-brand-2" />{h.recommendation}</div>
            </motion.button>
          ))}
        </div>
      )}

      </>}
      {/* All findings: details for those who want them */}
      <button id="all" onClick={() => setShowAll(!showAll)} className={clsx('flex w-full items-center gap-3 text-left', !area && 'mt-8')}>
        <h2 className="text-[17px] font-medium">{area ? 'Findings in this area' : 'All findings'}</h2><span className="chip">{area ? list.length : d.findings.length - acceptedCount}</span>
        <span className="h-px flex-1 bg-white/[0.06]" />
        <span className="flex items-center gap-1 text-[13px] text-muted">{showAll ? 'Hide details' : 'Show all details'}<ChevronDown className={clsx('h-4 w-4 transition', showAll && 'rotate-180')} /></span>
      </button>

      <AnimatePresence initial={false}>
        {showAll && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
            <div className="mt-4 flex flex-wrap items-center gap-2">
              <button className={clsx('chip !h-8 !px-3.5 transition', !sev && '!border-brand/50 !text-ink')} onClick={() => setSev(null)}>All <b className="text-ink">{d.findings.length - acceptedCount}</b></button>
              {SEVERITIES.filter((s) => counts[s]).map((s) => (
                <button key={s} className={clsx('chip !h-8 !px-3.5 transition', sev === s && '!text-ink')} style={sev === s ? { borderColor: SEV_COLOR[s], background: SEV_COLOR[s] + '1f' } : undefined} onClick={() => setSev(sev === s ? null : s)}>
                  <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEV_COLOR[s] }} />{s}<b className="text-ink">{counts[s]}</b>
                </button>
              ))}
              {acceptedCount > 0 && <button className={clsx('chip !h-8 !px-3.5 transition', showAccepted && '!border-brand/50 !text-ink')} onClick={() => setShowAccepted(!showAccepted)}><CheckCheck className="h-3.5 w-3.5" />Accepted <b className="text-ink">{acceptedCount}</b></button>}
              <select value={area} onChange={(e) => setArea(e.target.value)} className="field !h-8 !rounded-full !font-sans !text-[12.5px]">
                <option value="">All areas</option>{AREAS.map((a) => <option key={a.key} value={a.key}>{a.name}</option>)}
              </select>
              <label className="field ml-auto flex !h-9 w-[280px] items-center gap-2 !rounded-full"><Search className="h-4 w-4 text-dim" /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search findings" className="w-full bg-transparent font-sans text-[13px] outline-none" /></label>
            </div>

            <div className="mt-4 grid grid-cols-[minmax(340px,1fr)_1.2fr] items-start gap-4 pb-2">
              <Glass className="overflow-hidden">
                {list.length === 0 && <div className="p-10 text-center text-[13.5px] text-muted">No findings match these filters.</div>}
                {list.map((f, i) => (
                  <button key={i} onClick={() => setSel(f)} className={clsx('relative flex w-full items-start gap-3.5 border-b border-white/[0.05] px-5 py-3.5 text-left transition last:border-0 hover:bg-white/[0.03]', current === f && 'bg-white/[0.05]')}>
                    {current === f && <motion.span layoutId="fsel" className="absolute inset-y-2 left-0 w-[3px] rounded-r-full bg-brand" />}
                    <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ background: SEV_COLOR[f.severity] }} />
                    <div className={clsx('min-w-0 flex-1', f.accepted && 'opacity-55')}><div className="text-[13.5px] leading-snug">{f.accepted && <span className="chip mr-1.5 !h-5 !px-2 !text-[10.5px]">Accepted</span>}{f.title}</div><div className="mt-1 font-mono text-[11px] text-dim">{f.category}{f.ruleId ? ` · ${f.ruleId}` : ''}</div></div>
                  </button>
                ))}
              </Glass>
              <div className="sticky top-0">
                <AnimatePresence mode="wait">
                  {current && (
                    <motion.div key={current.title + current.detail} initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.25 }}>
                      <Glass strong className="p-7">
                        <div className="flex flex-wrap items-center gap-2"><Sev s={current.severity} /><span className="chip">{current.category}</span>{current.ruleId && <span className="chip">{current.ruleId}</span>}</div>
                        <h2 className="select-text mt-4 text-[24px] font-[380] leading-tight tracking-[-0.02em]">{current.title}</h2>
                        {current.accepted && <div className="mt-3 flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-[13px] text-muted"><CheckCheck className="h-4 w-4 text-brand-2" />Accepted: {current.acceptedReason || 'by you'} · not counted in the score. Undo in Settings.</div>}
                        {current.detail && <pre className="select-text mt-4 whitespace-pre-wrap break-words font-mono text-[12.5px] leading-relaxed text-muted">{current.detail}</pre>}
                        {current.recommendation && (
                          <div className="mt-5 rounded-2xl border border-brand/25 bg-brand/[0.07] p-4">
                            <div className="label !text-brand-2">What to do</div>
                            <p className="select-text mt-2 text-[14px] leading-relaxed">{current.recommendation}</p>
                          </div>
                        )}
                        <div className="mt-5 flex flex-wrap gap-2">
                          {current.mitre && <button className="chip !h-8 hover:!text-ink" onClick={() => call('shell.open', { url: `https://attack.mitre.org/techniques/${current.mitre!.replace('.', '/')}/` })}><ExternalLink className="h-3.5 w-3.5" />MITRE ATT&CK {current.mitre}</button>}
                          {!current.accepted && current.severity !== 'Info' && <button className="chip !h-8 hover:!text-ink" onClick={() => setAccepting(current)}><EyeOff className="h-3.5 w-3.5" />This is fine…</button>}
                          <button className="chip !h-8 hover:!text-ink" onClick={() => { navigator.clipboard?.writeText(`${current.severity}: ${current.title}\n${current.detail}\nWhat to do: ${current.recommendation}`); toast('Copied to clipboard'); }}><Copy className="h-3.5 w-3.5" />Copy</button>
                        </div>
                        {current.evidence != null && (
                          <details className="mt-5 group">
                            <summary className="label cursor-pointer list-none hover:text-ink">Technical evidence ›</summary>
                            <pre className="select-text mt-3 max-h-[320px] overflow-auto rounded-2xl border border-white/[0.06] bg-black/40 p-4 font-mono text-[11.5px] leading-relaxed text-muted">{JSON.stringify(current.evidence, null, 2)}</pre>
                          </details>
                        )}
                      </Glass>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
      {accepting && <AcceptDialog f={accepting} onClose={() => setAccepting(null)} />}
    </div>
  );
}

/** "This is fine": accept one finding or every finding of its kind, optionally for a limited time. */
function AcceptDialog({ f, onClose }: { f: Finding; onClose: () => void }) {
  const [kind, setKind] = useState<'finding' | 'rule'>('finding');
  const [reason, setReason] = useState('');
  const [days, setDays] = useState(0);
  const canRule = !!f.ruleId && f.severity !== 'Critical' && !f.ruleId.startsWith('collector.');
  const save = () => safe(async () => {
    await call('findings.accept', { kind, ruleId: f.ruleId, category: f.category, title: f.title, severity: f.severity, reason, days });
    toast(kind === 'rule' ? 'Findings of this type are now accepted' : 'Finding accepted'); onClose(); await refresh(true);
  });
  const opt = (k: 'finding' | 'rule', title: string, text: string, disabled = false) => (
    <button disabled={disabled} onClick={() => setKind(k)} className={clsx('w-full rounded-2xl border p-4 text-left transition', kind === k ? 'border-brand/50 bg-brand/[0.08]' : 'border-white/[0.08] hover:border-white/20', disabled && 'cursor-not-allowed opacity-40')}>
      <div className="text-[14px] font-medium">{title}</div><div className="mt-1 text-[12.5px] leading-relaxed text-muted">{text}</div>
    </button>);
  return createPortal(
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 backdrop-blur-sm" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <motion.div initial={{ opacity: 0, scale: 0.96, y: 8 }} animate={{ opacity: 1, scale: 1, y: 0 }} role="dialog" aria-modal="true" className="glass glass-strong w-[min(540px,94vw)] p-7">
        <div className="flex items-start justify-between gap-4"><h2 className="text-[22px] font-[400] tracking-[-0.02em]">Mark as fine</h2><button className="btn btn-icon btn-ghost" onClick={onClose}><X className="h-4 w-4" /></button></div>
        <p className="mt-2 text-[13.5px] leading-relaxed text-muted">Accepted items stay in reports, marked as accepted, but no longer lower your score or show up as things to fix.</p>
        <div className="mt-5 grid gap-2">
          {opt('finding', 'Just this one', f.title)}
          {opt('rule', 'Every finding of this type', canRule ? `All "${f.ruleId}" findings, now and in future checks.` : f.severity === 'Critical' ? 'Not available for critical findings: each one has to be accepted on its own.' : 'Not available for this finding.', !canRule)}
        </div>
        <label className="label mt-5 block">Why is it fine? (optional)</label>
        <input className="field mt-2 w-full" maxLength={200} placeholder="e.g. My own Defender exclusion for games" value={reason} onChange={(e) => setReason(e.target.value)} />
        <label className="label mt-4 block">For how long</label>
        <select className="field mt-2" value={days} onChange={(e) => setDays(+e.target.value)}><option value={0}>Until I undo it</option><option value={30}>30 days</option><option value={90}>90 days</option></select>
        <div className="mt-7 flex justify-end gap-2"><button className="btn btn-ghost" onClick={onClose}>Cancel</button><button className="btn btn-primary" onClick={save}><CheckCheck className="h-4 w-4" />Accept</button></div>
      </motion.div>
    </div>, document.body);
}
