import { useEffect, useState } from 'react';
import { motion } from 'motion/react';
import { Stethoscope, Play, Activity, ChevronDown, Lightbulb, Gauge, Monitor } from 'lucide-react';
import clsx from 'clsx';
import { call } from '../lib/api';
import { loadSettings, safe, startScan, toast, useStore } from '../lib/store';
import { SEV_COLOR, ago, fmtTime } from '../lib/format';
import type { Finding, Highlight } from '../lib/types';
import { Glass, PageHeader, Sev, Switch, Tip } from '../components/ui';

interface DoctorData { found: boolean; time?: string; findings?: Finding[]; highlights?: Highlight[]; stability?: any; health?: any; performance?: any; gaming?: any; live?: any; hardware?: any; sensors?: any }

function Stat({ label, value, tone, tip }: { label: string; value: string | number; tone?: string; tip?: string }) {
  return (
    <div className="rounded-2xl border border-white/[0.07] bg-white/[0.03] px-4 py-3.5">
      <div className="num text-[30px] leading-none" style={{ color: tone }}>{value}</div>
      <div className="mt-1.5 flex items-center text-[12px] text-muted">{label}{tip && <Tip text={tip} />}</div>
    </div>
  );
}

export default function Doctor() {
  const settings = useStore((s) => s.settings);
  const rev = useStore((s) => s.doctorRev);
  const running = useStore((s) => s.scan.running);
  const [d, setD] = useState<DoctorData | null>(null);
  const [all, setAll] = useState(false);
  useEffect(() => { safe(() => call<DoctorData>('doctor.latest')).then(setD); }, [rev]);
  useEffect(() => { if (!settings) loadSettings(); }, [settings]);


  const st = d?.stability ?? {}, he = d?.health ?? {}, pe = d?.performance ?? {}, ga = d?.gaming ?? {};
  const mods = settings?.modules ?? [];
  const toggle = (m: string, on: boolean) => safe(async () => {
    const next = on ? [...new Set([...mods, m])] : mods.filter((x) => x !== m);
    await call('settings.save', { values: settings!.values, secrets: {}, modules: next }); await loadSettings(); toast(on ? 'Will be included in every full check' : 'Removed from full checks');
  });
  const ram = (pe.Memory ?? [])[0];
  const disks: any[] = st.Disks ?? [];
  const worstDisk = disks.find((x) => x.Health !== 'Healthy') ?? disks[0];
  const discord: any[] = ga.Discord ?? [];
  const fs = d?.findings ?? [];
  const lv = d?.live, hw = d?.hardware, se = d?.sensors;
  const latency = lv ? (lv.DpcPercent?.Avg ?? 0) + (lv.InterruptPercent?.Avg ?? 0) : null;
  // Colours follow the findings: a value is amber or red only when PC Doctor also reported it, so the page and the
  // diagnosis never disagree. The limits themselves live in one place (DoctorLimits on the app side).
  const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const sevOf = (pred: (f: Finding) => boolean) => { const f = fs.filter((x) => !x.accepted && pred(x)).sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))[0]; return f ? SEV_COLOR[f.severity] : undefined; };
  const ev = (f: Finding, k: string) => { const e: any = f.evidence; return e?.[k] ?? e?.[k[0].toLowerCase() + k.slice(1)]; };
  const byRule = (id: string) => sevOf((f) => f.ruleId === id);
  const byLabel = (label: string) => sevOf((f) => ev(f, 'Label') === label);
  const sensorPeaks: { label: string; value: string; color?: string }[] = (() => {
    const r: any[] = se?.Readings ?? [];
    const pick = (re: RegExp, kind: string, not?: RegExp) => r.filter((x) => x.Kind === kind && re.test(x.Label) && !(not && not.test(x.Label))).sort((a, b) => (b.Max ?? b.Value) - (a.Max ?? a.Value))[0];
    const out: { label: string; value: string; color?: string }[] = [];
    const t = (re: RegExp, name: string, not?: RegExp) => { const x = pick(re, 'Temperature', not); if (x) out.push({ label: name, value: `${Math.round(x.Max ?? x.Value)} °C peak`, color: byLabel(x.Label) }); };
    t(/^(CPU Package|CPU \(Tctl\/Tdie\)|Tdie|Tctl|Core Max)/i, 'CPU'); t(/^GPU (Temperature|Core)|GPU Temp/i, 'GPU'); t(/Hot ?Spot/i, 'GPU hot spot', /Memory/i); t(/Memory Junction/i, 'Graphics memory');
    const standby = /SB|Standby|AUX|Dual|DDR|Memory/i;
    for (const [re, name] of [[/^\+?12(\.0)?\s?V\b/i, '+12 V rail'], [/^\+?5(\.0)?\s?V\b/i, '+5 V rail'], [/^\+?3\.3\s?V\b/i, '+3.3 V rail']] as const) {
      const x = r.find((y) => y.Kind === 'Voltage' && re.test(y.Label) && !standby.test(y.Label));
      if (x) out.push({ label: name, value: `${(x.Avg ?? x.Value).toFixed(2)} V avg (${(x.Min ?? x.Value).toFixed(2)}–${(x.Max ?? x.Value).toFixed(2)})`, color: byLabel(x.Label) });
    }
    const vc = pick(/^(Vcore|CPU Core( Voltage)?|Core Voltage|VDDCR_CPU)/i, 'Voltage', /VID|SoC/i); if (vc) out.push({ label: 'CPU core voltage', value: `${(vc.Max ?? vc.Value).toFixed(3)} V peak`, color: byLabel(vc.Label) });
    return out;
  })();
  const ok = '#34e0a1';

  return (
    <div className="mx-auto max-w-[1320px]">
      <PageHeader eyebrow="Health & performance" title="PC Doctor" sub={d?.found ? `Last examined ${ago(d.time)} · ${fmtTime(d.time)}` : 'Crashes, drivers, disks, RAM and gaming performance, explained.'}
        actions={<button className="btn btn-primary btn-lg" disabled={running} onClick={() => startScan('doctor')}><Play className="h-4 w-4" fill="currentColor" />{running ? 'Running…' : d?.found ? 'Examine again' : 'Run PC Doctor'}</button>} />

      {!d?.found ? (
        <Glass className="p-10 text-center"><Stethoscope className="mx-auto h-10 w-10 text-brand-2" /><div className="mt-4 text-[18px]">Run PC Doctor to see how healthy this PC is</div><div className="mt-1 text-[13.5px] text-muted">Takes about a minute. Read-only, like everything in TriageKit.</div></Glass>
      ) : (
        <>
          <div className="grid grid-cols-4 gap-3 xl:grid-cols-8">
            <Stat label="Blue screens" value={(st.BlueScreens ?? []).length} tone={(st.BlueScreens ?? []).length ? SEV_COLOR.High : undefined} tip="In the last 30+ days" />
            <Stat label="App & game crashes" value={(st.AppCrashes ?? []).reduce((a: number, x: any) => a + x.Count, 0)} tip="Last 30 days" />
            <Stat label="Hardware errors" value={st.HardwareErrors ?? 0} tone={st.HardwareErrors ? SEV_COLOR.Medium : undefined} tip="Corrected errors reported by CPU, RAM or PCIe" />
            <Stat label="GPU driver resets" value={st.GpuDriverResets ?? 0} tone={st.GpuDriverResets ? SEV_COLOR.Medium : undefined} />
            <Stat label="Device problems" value={(he.DeviceProblems ?? []).filter((x: any) => x.Code !== 45 && x.Code !== 22).length} />
            <Stat label="Reliability" value={he.ReliabilityIndex != null ? `${he.ReliabilityIndex}` : 'n/a'} tip="Windows' own stability score, 1–10" />
            <Stat label="RAM speed" value={ram ? `${ram.Running}` : 'n/a'} tone={ram && ram.Running < ram.Rated * 0.9 ? SEV_COLOR.Medium : undefined} tip={ram ? `Rated ${ram.Rated} MT/s` : undefined} />
            <Stat label="Disk health" value={worstDisk ? worstDisk.Health : 'n/a'} tone={worstDisk && worstDisk.Health !== 'Healthy' ? SEV_COLOR.High : '#34e0a1'} />
          </div>

          <div className="mt-4 grid grid-cols-[1.4fr_1fr] items-start gap-4">
            <Glass className="overflow-hidden">
              <div className="flex items-center gap-2 px-6 pb-3 pt-5"><Activity className="h-4 w-4 text-brand-2" /><h3 className="text-[15px] font-medium">Diagnosis</h3></div>
              {(d.highlights ?? []).length === 0 && <div className="px-6 pb-8 text-[14px] text-muted">No stability or performance problems found. 🎉</div>}
              {(d.highlights ?? []).map((h, i) => (
                <motion.div key={i} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }} className="border-t border-white/[0.05] px-6 py-4">
                  <div className="flex items-center gap-2"><Sev s={h.severity} /><span className="text-[14px] font-medium">{h.title}</span></div>
                  <div className="mt-2 flex gap-2.5 text-[13px] leading-relaxed text-muted"><Lightbulb className="mt-0.5 h-4 w-4 shrink-0 text-brand-2" />{h.recommendation}</div>
                </motion.div>
              ))}
            </Glass>
            <div className="flex flex-col gap-4">
              <Glass className="p-6">
                <h3 className="text-[15px] font-medium">Hardware</h3>
                <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-5 gap-y-2 text-[13px]">
                  <dt className="text-muted">Graphics</dt><dd className="text-right">{(pe.Gpus ?? []).map((g: any) => g.Name).join(', ') || 'n/a'}</dd>
                  <dt className="text-muted">GPU driver</dt><dd className="text-right font-mono text-[12px]">{(pe.Gpus ?? [])[0]?.Date ?? 'n/a'}</dd>
                  <dt className="text-muted">RAM</dt><dd className="text-right">{pe.TotalRamGB ? `${pe.TotalRamGB} GB` : 'n/a'}{ram ? ` · ${ram.Running}/${ram.Rated} MT/s` : ''}</dd>
                  <dt className="text-muted">Power plan</dt><dd className="text-right">{pe.PowerPlan ?? 'n/a'}</dd>
                  {disks.map((x, i) => <><dt key={'d' + i} className="text-muted">Disk</dt><dd key={'v' + i} className="text-right">{x.Name} · {x.Health}{x.WearPercent != null ? ` · ${x.WearPercent}% worn` : ''}{x.TemperatureC ? ` · ${x.TemperatureC}°C` : ''}</dd></>)}
                  <dt className="text-muted">Discord</dt><dd className="text-right">{discord.length ? discord.map((x) => x.Status).join(', ') : 'Not installed'}</dd>
                </dl>
              </Glass>
              <Glass className="p-6">
                <h3 className="text-[15px] font-medium">Include in full checks</h3>
                <div className="mt-3 flex items-center justify-between gap-4 text-[13.5px]"><span className="flex items-center">PC Doctor<Tip text="Adds crash, driver, disk and performance checks to every full check (about +30 seconds)." /></span><Switch checked={mods.includes('doctor')} onChange={(v) => toggle('doctor', v)} /></div>
                <div className="mt-3 flex items-center justify-between gap-4 text-[13.5px]"><span className="flex items-center">Gamer account protection<Tip text="Adds the Discord tamper check to every full check." /></span><Switch checked={mods.includes('gaming')} onChange={(v) => toggle('gaming', v)} /></div>
              </Glass>
            </div>
          </div>

          <div className="mt-4 grid grid-cols-2 items-start gap-4">
            <Glass className="p-6">
              <div className="flex items-center gap-2"><Activity className="h-4 w-4 text-brand-2" /><h3 className="text-[15px] font-medium">Live measurements</h3><Tip text="PC Doctor watches the PC for about 20 seconds. Close games and heavy apps first for a fair baseline, or run it while the stutter happens." /><span className="ml-auto text-[12px] text-dim">{lv?.Seconds ? `${lv.Seconds} s sample` : lv?.Ran === false ? 'Not available' : 'Not measured yet'}</span></div>
              {lv?.Ran === false ? <div className="mt-3 text-[13.5px] leading-relaxed text-muted">Windows' performance counters didn't answer, so nothing was measured (no numbers is better than wrong ones). Repairing them usually helps: run <span className="font-mono text-[12.5px] text-ink">lodctr /R</span> in an administrator command prompt, restart, and examine again.</div>
              : lv?.Seconds ? (<>
                <div className="mt-4 grid grid-cols-[repeat(auto-fit,minmax(118px,1fr))] gap-3">
                  <Stat label="Driver latency" value={`${latency!.toFixed(1)}%`} tone={byRule('perf.dpc-latency') ?? ok} tip="Share of CPU time spent in drivers (DPC + interrupts). Under 2% is healthy; high values cause micro-stutter and audio crackle." />
                  <Stat label="CPU use" value={`${Math.round(lv.CpuPercent?.Avg ?? 0)}%`} tip={`Peak ${Math.round(lv.CpuPercent?.Max ?? 0)}%`} />
                  <Stat label="Disk response" value={`${Math.round(lv.DiskMs?.Avg ?? 0)} ms`} tone={byRule('perf.disk-latency') ?? ok} tip={`Windows disk${lv.DiskMs?.Disk ? ` (${lv.DiskMs.Disk})` : ''}. Worst ${Math.round(lv.DiskMs?.Max ?? 0)} ms. A healthy SSD answers in under 5 ms.`} />
                  <Stat label="Free memory" value={`${((lv.AvailableMB?.Min ?? 0) / 1024).toFixed(1)} GB`} tone={byRule('perf.memory-pressure')} tip={`Lowest free RAM while watching${lv.AvailableMB?.Total ? `, of ${(lv.AvailableMB.Total / 1024).toFixed(0)} GB` : ''}`} />
                </div>
                {(lv.TopCpu ?? []).length > 0 && <div className="mt-4 text-[13px]"><div className="label mb-2">Busiest apps</div>
                  {(lv.TopCpu as any[]).slice(0, 5).map((p, i) => <div key={i} className="flex justify-between gap-3 border-t border-white/[0.05] py-1.5"><span className="truncate" title={p.Path ?? p.Name}>{p.Name}{p.Foreground ? <span className="ml-2 text-dim">in use</span> : p.Microsoft ? <span className="ml-2 text-dim">Windows</span> : !p.Signed && p.Path ? <span className="ml-2 text-dim">unsigned</span> : null}</span><span className="num text-muted">{p.Percent}%</span></div>)}
                </div>}
              </>) : <div className="mt-3 text-[13.5px] text-muted">Run PC Doctor again to measure driver latency, CPU, disk and memory live.</div>}
            </Glass>
            <Glass className="p-6">
              <div className="flex items-center gap-2"><Gauge className="h-4 w-4 text-brand-2" /><h3 className="text-[15px] font-medium">Voltages & temperatures</h3><Tip text="Windows doesn't share these without a hardware driver. TriageKit reads them from HWiNFO (with Shared Memory Support on) or LibreHardwareMonitor while it's running." /><span className="ml-auto text-[12px] text-dim">{se?.Source ? `from ${se.Source}` : 'No sensor tool running'}</span></div>
              {sensorPeaks.length > 0 ? <><dl className="mt-4 grid grid-cols-[1fr_auto] gap-y-2 text-[13px]">{sensorPeaks.map((p, i) => <><dt key={'l' + i} className="text-muted">{p.label}</dt><dd key={'v' + i} className="num text-right" style={{ color: p.color }}>{p.value}</dd></>)}</dl>
                <div className="mt-2 text-[11.5px] text-dim">Peaks are since {se?.Source ?? 'the sensor tool'} was started.</div></>
                : <div className="mt-3 text-[13.5px] leading-relaxed text-muted">{se?.Problem ? <>{se.Problem} </> : null}Start <b className="text-ink">HWiNFO</b> (Sensors only, "Shared Memory Support" on) or <b className="text-ink">LibreHardwareMonitor</b>, then examine again to check power supply rails, CPU voltage and hot spots.</div>}
              {(hw?.Displays ?? []).length > 0 && <div className="mt-5 text-[13px]"><div className="label mb-2 flex items-center gap-1.5"><Monitor className="h-3.5 w-3.5" />Monitors</div>
                {(hw.Displays as any[]).map((m, i) => <div key={i} className="flex justify-between border-t border-white/[0.05] py-1.5"><span className="truncate">{m.Monitor}{m.Primary ? <span className="ml-2 text-dim">main</span> : null}</span><span className="num" style={{ color: sevOf((f) => f.ruleId === 'perf.refresh-rate' && ev(f, 'Monitor') === m.Monitor) }}>{m.Resolution} · {m.RefreshHz}/{m.MaxRefreshHz} Hz</span></div>)}
              </div>}
            </Glass>
          </div>

          <button onClick={() => setAll(!all)} className="mt-8 flex w-full items-center gap-3 text-left"><h2 className="text-[17px] font-medium">All PC Doctor findings</h2><span className="chip">{fs.length}</span><span className="h-px flex-1 bg-white/[0.06]" /><ChevronDown className={clsx('h-4 w-4 text-muted transition', all && 'rotate-180')} /></button>
          {all && (
            <Glass className="mt-4 overflow-hidden">
              {fs.map((f, i) => (
                <details key={i} className="group border-t border-white/[0.05] px-6 py-4 first:border-0">
                  <summary className="flex cursor-pointer list-none items-center gap-3"><span className="h-2 w-2 shrink-0 rounded-full" style={{ background: SEV_COLOR[f.severity] }} /><span className="flex-1 text-[13.5px]">{f.title}</span><Sev s={f.severity} /></summary>
                  <pre className="select-text mt-3 whitespace-pre-wrap font-mono text-[12px] text-muted">{f.detail}</pre>
                  {f.recommendation && <div className="mt-3 rounded-xl border border-brand/25 bg-brand/[0.07] p-3 text-[13px]">{f.recommendation}</div>}
                </details>
              ))}
            </Glass>
          )}
        </>
      )}
    </div>
  );
}
