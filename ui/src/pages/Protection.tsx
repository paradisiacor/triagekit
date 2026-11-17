import { useState } from 'react';
import { motion } from 'motion/react';
import { ShieldCheck, Shield, Play, Radar, Wifi, LockKeyhole, Mail, Siren, Network } from 'lucide-react';
import { call } from '../lib/api';
import { refresh, safe, toast, useStore } from '../lib/store';
import { fmtTime } from '../lib/format';
import { Glass, PageHeader, Switch, confirmDialog, Tip } from '../components/ui';

export function Row({ title, help, tip, children }: { title: string; help?: string; tip?: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-6 border-t border-white/[0.05] px-6 py-4 first:border-0">
      <div><div className="flex items-center text-[14px]">{title}{tip && <Tip text={tip} />}</div>{help && !tip && <div className="mt-0.5 max-w-[62ch] text-[12.5px] text-muted">{help}</div>}</div>
      {children}
    </div>
  );
}

const SOON = [
  [Radar, 'Live monitoring', 'Instant alert when a new startup entry, service or suspicious process appears.'],
  [Wifi, 'Network safety', 'Warns about unsafe Wi-Fi, DNS hijacking, rogue proxies and open ports.'],
  [LockKeyhole, 'One-click hardening', 'Turns on safe protections. Every change logged and reversible.'],
  [Mail, 'Breach check', 'See if your email appears in known breaches, without revealing it.'],
  [Siren, 'Ransomware early warning', 'Decoy files that raise the alarm the moment encryption starts.'],
  [Network, 'Secure connection', 'Encrypted traffic on public Wi-Fi through a trusted VPN partner.'],
] as const;

export default function Protection() {
  const app = useStore((s) => s.app);
  const a = app?.agent;
  const [cfg, setCfg] = useState(a?.config);
  const on = !!a?.installed;
  const c = cfg ?? a?.config;

  return (
    <div className="mx-auto max-w-[1200px]">
      <PageHeader eyebrow="Protection" title="Know the day something changes" sub="A small background service checks once a day and only speaks up when something new appears." />
      <Glass className="relative flex items-center gap-7 overflow-hidden !rounded-[28px] p-8">
        <div className="absolute -left-20 -top-20 h-64 w-64 rounded-full blur-[90px]" style={{ background: on ? '#34e0a1' : '#4c9dff', opacity: 0.18 }} />
        <div className="relative grid h-20 w-20 shrink-0 place-items-center rounded-3xl border border-white/10 bg-white/[0.04]" style={{ color: on ? '#34e0a1' : '#8b95a3' }}>
          {on ? <ShieldCheck className="h-9 w-9" strokeWidth={1.5} /> : <Shield className="h-9 w-9" strokeWidth={1.5} />}
        </div>
        <div className="relative flex-1">
          <div className="label">Daily protection</div>
          <div className="mt-1.5 text-[28px] font-[350] tracking-[-0.02em]">{on ? (a!.running ? 'On · checked every day' : 'Installed, service stopped') : 'Off'}</div>
          <p className="mt-2 max-w-[70ch] text-[14px] text-muted">{on ? (a!.nextScan ? `Next check ${fmtTime(a!.nextScan)}. You'll be notified only when something new appears.` : 'The next automatic check is being scheduled.') : 'Adds a small background service and a tray icon. Checks daily, keeps a history and alerts you only about new issues.'}</p>
        </div>
        <div className="relative flex gap-2">
          {on ? <>
            <button className="btn" onClick={() => safe(async () => { const r: any = await call('agent.scanNow'); toast(r.message); })}><Play className="h-4 w-4" fill="currentColor" />Check now</button>
            <button className="btn border-crit/30 text-crit hover:bg-crit/10" onClick={async () => { if (await confirmDialog('Turn off daily protection?', 'The background service and tray icon are removed. Your history is kept.', 'Turn off', true)) safe(async () => { const r: any = await call('agent.uninstall', { purge: false }); toast(r.message); await refresh(); }); }}>Turn off</button>
          </> : (
            <button className="btn btn-primary btn-lg" disabled={!app?.elevated} title={app?.elevated ? '' : 'Restart TriageKit as administrator first'}
              onClick={async () => { if (await confirmDialog('Turn on daily protection?', 'TriageKit will be copied to Program Files and a background service added. Remove it any time here or in Settings › Apps.', 'Turn on')) safe(async () => { const r: any = await call('agent.install'); toast(r.message); await refresh(); }); }}>
              <ShieldCheck className="h-4 w-4" />Turn on</button>
          )}
        </div>
      </Glass>

      {on && c && (
        <Glass className="mt-4">
          <Row title="Daily check time" help="Missed checks run shortly after the PC starts." tip="Daily check time. If the PC was off, it runs shortly after start-up."><input type="time" className="field w-[120px]" value={c.dailyScanTime} onChange={(e) => setCfg({ ...c, dailyScanTime: e.target.value })} /></Row>
          <Row title="Use quick checks for the daily run" help="Lighter; full checks still run when you start them." tip="1-minute checks instead of full ones. Lighter on older PCs."><Switch checked={c.quickScheduledScans} onChange={(v) => setCfg({ ...c, quickScheduledScans: v })} /></Row>
          <Row title="Notify me about new issues" help="Only issues that weren't there in the previous check." tip="Alerts only for issues that weren't there last time."><Switch checked={c.notifyOnNewFindings} onChange={(v) => setCfg({ ...c, notifyOnNewFindings: v })} /></Row>
          <Row title="Keep history for" help="Number of checks to keep." tip="Older checks are deleted automatically after this many."><input type="number" min={5} max={365} className="field w-[90px] text-right" value={c.keepScans} onChange={(e) => setCfg({ ...c, keepScans: +e.target.value })} /></Row>
          <div className="flex justify-end border-t border-white/[0.05] px-6 py-4"><button className="btn btn-primary" onClick={() => safe(async () => { await call('agent.saveConfig', c as any); toast('Saved'); await refresh(); })}>Save</button></div>
        </Glass>
      )}

      <div className="mb-3 mt-10 flex items-baseline gap-3"><h2 className="text-[19px] font-[450]">Coming next</h2><span className="label">roadmap</span></div>
      <div className="grid grid-cols-3 gap-3">
        {SOON.map(([I, t, d], i) => (
          <motion.div key={t} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}>
            <Glass className="h-full p-6">
              <div className="flex items-center justify-between"><div className="grid h-10 w-10 place-items-center rounded-2xl bg-brand/12 text-brand-2"><I className="h-5 w-5" strokeWidth={1.7} /></div><span className="chip">Planned</span></div>
              <div className="mt-4 text-[15px] font-medium">{t}</div>
              <div className="mt-1.5 text-[13px] leading-relaxed text-muted">{d}</div>
            </Glass>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
