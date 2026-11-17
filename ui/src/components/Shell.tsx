import { motion } from 'motion/react';
import clsx from 'clsx';
import { LayoutGrid, Radar, ListChecks, History, ShieldCheck, Settings2, Info, Play, Lock, Stethoscope, PackageSearch, ArrowUpCircle } from 'lucide-react';
import type { ReactNode } from 'react';
import { go, startScan, useStore, type Route } from '../lib/store';
import { VERDICT_COLOR } from '../lib/format';
import { Dot } from './ui';

const NAV: ({ id: Route; label: string; icon: any } | null)[] = [
  { id: 'overview', label: 'Overview', icon: LayoutGrid },
  { id: 'scan', label: 'Scan', icon: Radar },
  { id: 'findings', label: 'Findings', icon: ListChecks },
  { id: 'history', label: 'History', icon: History },
  null,
  { id: 'safestart', label: 'Safe Start', icon: PackageSearch },
  { id: 'doctor', label: 'PC Doctor', icon: Stethoscope },
  { id: 'protection', label: 'Protection', icon: ShieldCheck },
  { id: 'settings', label: 'Settings', icon: Settings2 },
  { id: 'about', label: 'About', icon: Info },
];

export function Logo({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden>
      <defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#7fe0ff" /><stop offset="1" stopColor="#2e6bff" /></linearGradient></defs>
      <path d="M16 2.5c3.2 2.6 6.7 3.6 10.5 3.6v9.2c0 7-4.6 11.7-10.5 14.2C10.1 27 5.5 22.3 5.5 15.3V6.1C9.3 6.1 12.8 5.1 16 2.5z" fill="url(#lg)" />
      <path d="M11 15.8l3.4 3.4 6.8-7" fill="none" stroke="#ffffff" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Background() {
  const verdict = useStore((s) => s.detail?.summary.verdict);
  const running = useStore((s) => s.scan.running);
  const tone = running ? '#4c9dff' : verdict ? VERDICT_COLOR[verdict] : '#4c9dff';
  return (
    <div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
      <div className="absolute inset-0 grid-bg" />
      <div className="absolute -top-[45%] left-[30%] h-[80vh] w-[80vh] rounded-full blur-[150px] transition-[background-color] duration-1000" style={{ backgroundColor: tone, opacity: 0.09 }} />
      <div className="absolute -bottom-[40%] -right-[10%] h-[90vh] w-[90vh] rounded-full bg-[#3a5bff] opacity-[0.07] blur-[160px]" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,transparent_40%,#05070a_95%)]" />
    </div>
  );
}

function Sidebar() {
  const route = useStore((s) => s.route);
  const scan = useStore((s) => s.scan);
  const app = useStore((s) => s.app);
  const detail = useStore((s) => s.detail);
  const serious = detail ? detail.findings.filter((f) => f.severity === 'Critical' || f.severity === 'High').length : 0;
  return (
    <aside className="glass m-3 mr-0 flex min-h-0 w-[232px] shrink-0 flex-col overflow-y-auto !rounded-[26px] p-3">
      <div className="flex items-center gap-3 px-3 pb-6 pt-3 [@media(max-height:760px)]:pb-2 [@media(max-height:760px)]:pt-1">
        <Logo />
        <div>
          <div className="text-[17px] font-semibold tracking-[-0.01em]">TriageKit</div>
          <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-brand-2/80">{app ? `${app.edition} · ${app.version}` : ' '}</div>
        </div>
      </div>
      <nav className="flex flex-col gap-1">
        {NAV.map((n, i) => n === null ? <div key={i} className="mx-3 my-3 h-px bg-white/[0.06]" /> : (
          <button key={n.id} onClick={() => go(n.id)} aria-current={route === n.id ? 'page' : undefined}
            className={clsx('relative flex h-11 shrink-0 items-center [@media(max-height:760px)]:h-9 gap-3 rounded-2xl px-3.5 text-[14px] transition-colors', route === n.id ? 'text-ink' : 'text-muted hover:bg-white/[0.04] hover:text-ink')}>
            {route === n.id && <motion.span layoutId="navpill" className="absolute inset-0 rounded-2xl border border-white/10 bg-white/[0.07] shadow-[inset_0_1px_0_#ffffff14]" transition={{ type: 'spring', stiffness: 500, damping: 40 }} />}
            <n.icon className="relative h-[18px] w-[18px]" strokeWidth={1.7} />
            <span className="relative">{n.label}</span>
            {n.id === 'scan' && scan.running && <span className="relative ml-auto flex items-center gap-1.5 font-mono text-[11px] text-brand-2"><Dot color="#4c9dff" pulse size={6} />{scan.index}/{scan.total}</span>}
            {n.id === 'findings' && serious > 0 && <span className="relative ml-auto grid h-5 min-w-5 place-items-center rounded-full bg-high/20 px-1.5 font-mono text-[11px] text-high">{serious}</span>}
          </button>
        ))}
      </nav>
      <div className="mt-auto flex flex-col gap-3 pt-3">
        {app?.update && (
          <button onClick={() => go('about')} className="flex items-center gap-3 rounded-2xl border border-brand/30 bg-brand/10 px-4 py-3 text-left transition hover:border-brand/60">
            <ArrowUpCircle className="h-5 w-5 shrink-0 text-brand-2" />
            <div><div className="text-[13.5px] font-medium">Update available</div><div className="text-[12px] text-muted">Version {app.update.version}</div></div>
          </button>
        )}
        <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-gradient-to-br from-brand/20 via-brand/5 to-transparent p-4 [@media(max-height:600px)]:hidden">
          <div className="label !text-brand-2/80">Free for everyone</div>
          <div className="mt-1 text-[12.5px] leading-snug text-muted">Every check included. No account, no payments.</div>
        </div>
        <div className="flex items-center gap-2 px-3 pb-1 text-[11.5px] text-dim [@media(max-height:640px)]:hidden"><Lock className="h-3.5 w-3.5 shrink-0" />Read-only · nothing is changed</div>
      </div>
    </aside>
  );
}

function Topbar() {
  const app = useStore((s) => s.app);
  const running = useStore((s) => s.scan.running);
  return (
    <header className="flex h-[68px] shrink-0 items-center justify-between px-8">
      <div className="flex items-center gap-3 text-[13px] text-muted">
        <span className="chip"><Dot color={app?.elevated ? '#34e0a1' : '#f7b52c'} size={6} />{app?.machine ?? '…'}</span>
        {app?.os && <span className="hidden text-dim xl:inline">{app.os}</span>}
        {app && !app.elevated && <span className="chip sev" style={{ ['--c' as any]: '#f7b52c' }}>Limited – not admin</span>}
      </div>
      <div className="flex items-center gap-2">
        <span className="chip hidden md:inline-flex">Rules {app?.rules.version ?? ''}{app?.rules.trusted ? ' · signed' : ''}</span>
        <button className="btn btn-primary" onClick={() => startScan('full')} disabled={running}><Play className="h-4 w-4" fill="currentColor" />{running ? 'Scanning…' : 'Run check'}</button>
      </div>
    </header>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-full">
      <Background />
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <main className="min-h-0 flex-1 overflow-y-auto px-8 pb-10 [scrollbar-gutter:stable]">{children}</main>
      </div>
    </div>
  );
}
