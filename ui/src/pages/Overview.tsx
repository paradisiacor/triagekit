import { lazy, Suspense } from 'react';
import { motion } from 'motion/react';
import { ArrowRight, Zap, Play, ShieldCheck, ChevronRight, Sparkles } from 'lucide-react';
import { go, set, startScan, useStore } from '../lib/store';
import { AREAS, SEVERITIES, SEV_COLOR, VERDICT_COLOR, VERDICT_LINE, ago, areaRisk, fmtShort, plural, worst } from '../lib/format';
import { Glass, Sev, Dot, Counter } from '../components/ui';
import { RadarChart, TrendChart } from '../components/charts';

const ShieldScene = lazy(() => import('../three/ShieldScene'));

const fade = (i: number) => ({ initial: { opacity: 0, y: 14 }, animate: { opacity: 1, y: 0 }, transition: { delay: 0.05 * i, duration: 0.6, ease: [0.16, 1, 0.3, 1] as const } });

export function areaColor(findings: any[], cats: string[]) {
  const w = worst(findings.filter((f) => cats.includes(f.category) && f.severity !== 'Info'));
  return w ? SEV_COLOR[w] : '#34e0a1';
}

export default function Overview() {
  const d = useStore((s) => s.detail);
  const scans = useStore((s) => s.scans);
  const scan = useStore((s) => s.scan);
  const app = useStore((s) => s.app);
  const loaded = useStore((s) => s.loaded);
  const verdict = d?.summary.verdict;
  const tone = scan.running ? '#4c9dff' : verdict ? VERDICT_COLOR[verdict] : '#4c9dff';
  // An area is only green when the last check actually looked at it. A quick check doesn't open files or run the
  // malware rules, so "Files & malware" stays grey ("not in quick check") instead of claiming "All good".
  const notChecked = (key: string) => !d || (d.summary.quick && key === 'mal');
  const hotspots = AREAS.map((a) => (d && !notChecked(a.key) ? areaColor(d.findings, a.cats) : '#8b95a3'));
  const emblem = !d ? 'none' : verdict === 'Looks clean' ? 'check' : 'alert';
  const c = d?.summary.counts;

  return (
    <div className="mx-auto flex max-w-[1320px] flex-col gap-4">
      {/* HERO */}
      <motion.div {...fade(0)}>
        <Glass className="grid min-h-[440px] grid-cols-[minmax(400px,5fr)_7fr] overflow-hidden !rounded-[28px]">
          <div className="relative z-10 flex flex-col p-9 [@media(max-width:1280px)]:p-7">
            <div className="label">{d ? `${d.summary.quick ? 'Quick' : 'Full'} check · ${ago(d.summary.time)}` : loaded ? 'No checks yet' : ' '}</div>
            {d ? (
              <>
                <div className="mt-4 flex items-end gap-3">
                  <Counter value={d.summary.score} className="num text-[132px] leading-[0.82]" />
                  <span className="mb-2 font-mono text-[15px] text-dim">/100</span>
                </div>
                <div className="mt-6 flex items-center gap-3">
                  <span className="inline-flex items-center gap-2 rounded-full border px-3.5 py-1.5 text-[14px] font-medium" style={{ color: tone, borderColor: tone + '55', background: tone + '14' }}>
                    <Dot color={tone} size={7} />{verdict}
                  </span>
                </div>
                <p className="mt-4 max-w-[42ch] text-[15px] leading-relaxed text-muted">{VERDICT_LINE[verdict!]}</p>
                <div className="mt-7 grid grid-cols-4 gap-2">
                  {SEVERITIES.slice(0, 4).map((s) => (
                    <button key={s} onClick={() => go('findings')} className="rounded-2xl border border-white/[0.07] bg-white/[0.03] px-3.5 py-3 text-left transition hover:bg-white/[0.06]">
                      <div className="num text-[28px] leading-none" style={{ color: c![s] ? SEV_COLOR[s] : undefined }}>{c![s]}</div>
                      <div className="mt-1.5 text-[11.5px] text-muted">{s}</div>
                    </button>
                  ))}
                </div>
              </>
            ) : (
              <>
                <h1 className="mt-5 text-[52px] font-[300] leading-[1.02] tracking-[-0.035em]">How safe is<br /><span className="bg-gradient-to-r from-brand-2 to-brand bg-clip-text text-transparent">this PC</span>, really?</h1>
                <p className="mt-5 max-w-[44ch] text-[15px] leading-relaxed text-muted">Your antivirus looks for known bad files. A full check also looks at what it skips: settings, startup entries, exclusions, certificates, logs, browsers and documents. About 5 to 10 minutes, and nothing is changed.</p>
              </>
            )}
            <div className="mt-auto flex flex-wrap gap-2 pt-8 [@media(min-width:1000px)]:flex-nowrap">
              <button className="btn btn-primary btn-lg" onClick={() => startScan('full')} disabled={scan.running}><Play className="h-4 w-4" fill="currentColor" />{scan.running ? 'Scan running…' : d ? 'Run full check' : 'Run first check'}</button>
              <button className="btn btn-lg" onClick={() => startScan('quick')} disabled={scan.running}><Zap className="h-4 w-4" />Quick · 1 min</button>
            </div>
          </div>
          <div className="relative min-h-[440px]">
            <Suspense fallback={null}><ShieldScene tone={tone} hotspots={hotspots} scanning={scan.running} emblem={emblem as any} /></Suspense>
            {d && (
              <div className="pointer-events-none absolute inset-x-6 bottom-5 flex flex-wrap justify-center gap-1.5">
                {AREAS.map((a, i) => (
                  <motion.span key={a.key} {...fade(i + 3)} className="flex items-center gap-2 rounded-full border border-white/[0.07] bg-black/30 px-2.5 py-1 text-[11.5px] text-muted backdrop-blur-md">
                    {a.short}<Dot color={hotspots[i]} size={6} />
                  </motion.span>
                ))}
              </div>
            )}
          </div>
        </Glass>
      </motion.div>

      {d && (
        <div className="grid grid-cols-12 gap-4">
          {/* RADAR */}
          <motion.div {...fade(2)} className="col-span-6 xl:col-span-4">
            <Glass className="h-full p-6">
              <div className="flex items-center justify-between"><h3 className="text-[15px] font-medium">Threat surface</h3><span className="label">{AREAS.length} areas</span></div>
              <div className="mx-auto mt-2 aspect-square max-w-[320px]">
                <RadarChart axes={AREAS.map((a) => a.short)} values={AREAS.map((a) => areaRisk(d.findings, a))} color={tone} />
              </div>
              <p className="text-center text-[12px] text-dim">Further from the centre = more risk</p>
            </Glass>
          </motion.div>

          {/* WHAT TO DO FIRST */}
          <motion.div {...fade(3)} className="col-span-6 xl:col-span-5">
            <Glass className="h-full overflow-hidden">
              <div className="flex items-center justify-between px-6 pb-3 pt-6">
                <h3 className="flex items-center gap-2 text-[15px] font-medium"><Sparkles className="h-4 w-4 text-brand-2" />What to do first</h3>
                <span className="label">{d.highlights.length} of {d.findings.filter((f) => f.severity !== 'Info').length}</span>
              </div>
              {d.highlights.length === 0 ? (
                <div className="px-6 pb-8 pt-4 text-[14px] text-muted">Nothing important to fix. Keep Windows and your apps up to date.</div>
              ) : d.highlights.map((h, i) => (
                <button key={i} onClick={() => go('findings', { focusRule: h.ruleId ?? h.title })}
                  className="group flex w-full items-start gap-4 border-t border-white/[0.05] px-6 py-4 text-left transition hover:bg-white/[0.03]">
                  <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ background: SEV_COLOR[h.severity], boxShadow: `0 0 10px ${SEV_COLOR[h.severity]}` }} />
                  <div className="min-w-0 flex-1">
                    <div className="text-[14px] font-medium leading-snug">{h.title}</div>
                    <div className="mt-1 line-clamp-2 text-[12.5px] leading-snug text-muted">{h.recommendation}</div>
                  </div>
                  <ChevronRight className="mt-1 h-4 w-4 shrink-0 text-dim transition group-hover:translate-x-0.5 group-hover:text-ink" />
                </button>
              ))}
            </Glass>
          </motion.div>

          {/* SIDE */}
          <div className="col-span-12 flex flex-row gap-4 xl:col-span-3 xl:flex-col">
            <motion.div {...fade(4)}>
              <Glass className="p-6">
                <div className="flex items-center justify-between">
                  <h3 className="text-[15px] font-medium">Daily protection</h3>
                  <span className="chip sev" style={{ ['--c' as any]: app?.agent.installed ? '#34e0a1' : '#8b95a3' }}>{app?.agent.installed ? 'On' : 'Off'}</span>
                </div>
                <p className="mt-2 text-[13px] leading-relaxed text-muted">{app?.agent.installed ? (app.agent.nextScan ? `Next check ${fmtShort(app.agent.nextScan)}.` : 'Automatic checks are paused.') : 'Checks every day and alerts you only when something new appears.'}</p>
                <button className="btn mt-4 w-full justify-center" onClick={() => go('protection')}><ShieldCheck className="h-4 w-4" />{app?.agent.installed ? 'Manage' : 'Turn on'}</button>
              </Glass>
            </motion.div>
            <motion.div {...fade(5)} className="flex-1">
              <Glass className="flex h-full flex-col p-6">
                <div className="flex items-center justify-between"><h3 className="text-[15px] font-medium">Score trend</h3><button className="label hover:text-ink" onClick={() => go('history')}>History</button></div>
                <div className="mt-auto pt-4"><TrendChart scans={scans.slice(0, 12)} height={110} /></div>
                <div className="mt-2 text-[12px] text-dim">{plural(scans.length, 'check')} on this device</div>
              </Glass>
            </motion.div>
          </div>

          {/* AREAS */}
          <motion.div {...fade(6)} className="col-span-12 grid grid-cols-5 gap-3 2xl:grid-cols-10">
            {AREAS.map((a, i) => {
              const fs = d.findings.filter((f) => a.cats.includes(f.category) && f.severity !== 'Info');
              return (
                <button key={a.key} onClick={() => { set({ focusRule: null }); go('findings', { focusRule: `area:${a.key}` }); }} className="glass group !rounded-2xl p-4 text-left transition hover:-translate-y-0.5 hover:border-white/20">
                  <div className="flex items-center justify-between"><Dot color={hotspots[i]} size={7} /><ArrowRight className="h-3.5 w-3.5 text-dim opacity-0 transition group-hover:opacity-100" /></div>
                  <div className="mt-3 text-[13px] font-medium">{a.name}</div>
                  <div className="mt-0.5 text-[11.5px] text-muted">{notChecked(a.key) ? (d ? 'Not in quick check' : 'Not checked yet') : fs.length ? plural(fs.length, 'item') : 'All good'}</div>
                </button>
              );
            })}
          </motion.div>
        </div>
      )}
    </div>
  );
}
