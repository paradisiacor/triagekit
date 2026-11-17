import { AnimatePresence, motion } from 'motion/react';
import { CheckCircle2, AlertCircle, Info } from 'lucide-react';
import { createRoot } from 'react-dom/client';
import clsx from 'clsx';
import type { ReactNode } from 'react';
import { SEV_COLOR } from '../lib/format';
import type { Severity } from '../lib/types';
import { useStore } from '../lib/store';

export function Glass({ className, children, strong, ...rest }: { className?: string; children?: ReactNode; strong?: boolean } & React.HTMLAttributes<HTMLDivElement>) {
  return <div className={clsx('glass', strong && 'glass-strong', className)} {...rest}>{children}</div>;
}

export function Sev({ s, children }: { s: Severity; children?: ReactNode }) {
  return <span className="chip sev" style={{ ['--c' as any]: SEV_COLOR[s] }}>{children ?? s}</span>;
}

export function Dot({ color, pulse, size = 8 }: { color: string; pulse?: boolean; size?: number }) {
  return <span className={clsx('inline-block rounded-full shrink-0', pulse && 'pulse-dot')} style={{ width: size, height: size, background: color, color, boxShadow: `0 0 12px ${color}` }} />;
}

export function Switch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label?: string }) {
  return (
    <button role="switch" aria-checked={checked} aria-label={label} onClick={() => onChange(!checked)}
      className={clsx('relative h-6 w-11 shrink-0 rounded-full border transition-colors duration-300', checked ? 'bg-brand border-brand-2/60 shadow-[0_0_18px_-2px] shadow-brand/70' : 'bg-white/10 border-white/10')}>
      <motion.span layout transition={{ type: 'spring', stiffness: 600, damping: 35 }} className="absolute top-0.5 h-[18px] w-[18px] rounded-full bg-white shadow"
        style={{ left: checked ? 22 : 3 }} />
    </button>
  );
}

export function PageHeader({ eyebrow, title, sub, actions }: { eyebrow: string; title: ReactNode; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-7 flex items-end justify-between gap-6">
      <div>
        <div className="label mb-2">{eyebrow}</div>
        <h1 className="text-[34px] font-[350] leading-[1.05] tracking-[-0.03em]">{title}</h1>
        {sub && <p className="mt-2 max-w-[70ch] text-[14px] text-muted">{sub}</p>}
      </div>
      {actions && <div className="flex shrink-0 gap-2">{actions}</div>}
    </div>
  );
}

export function Empty({ icon, title, text, action }: { icon: ReactNode; title: string; text?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center px-6 py-16 text-center">
      <div className="mb-4 grid h-14 w-14 place-items-center rounded-2xl border border-white/10 bg-white/5 text-ok">{icon}</div>
      <h3 className="text-[17px] font-medium">{title}</h3>
      {text && <p className="mt-1.5 max-w-[48ch] text-[13.5px] text-muted">{text}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function Toasts() {
  const toasts = useStore((s) => s.toasts);
  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2" aria-live="polite">
      <AnimatePresence>
        {toasts.map((t) => (
          <motion.div key={t.id} initial={{ opacity: 0, y: 12, scale: 0.97 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 8 }}
            className="glass glass-strong flex max-w-[400px] items-start gap-3 !rounded-2xl px-4 py-3 text-[13.5px]">
            {t.kind === 'err' ? <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-crit" /> : <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-ok" />}
            <span>{t.text}</span>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}

/** Promise-based confirmation dialog. */
export function confirmDialog(title: string, text: string, ok = 'Continue', danger = false): Promise<boolean> {
  return new Promise((resolve) => {
    const host = document.createElement('div'); document.body.append(host);
    const root = createRoot(host);
    const close = (v: boolean) => { root.unmount(); host.remove(); resolve(v); };
    root.render(
      <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 backdrop-blur-sm" onMouseDown={(e) => { if (e.target === e.currentTarget) close(false); }}>
        <motion.div initial={{ opacity: 0, scale: 0.96, y: 8 }} animate={{ opacity: 1, scale: 1, y: 0 }} role="dialog" aria-modal="true" className="glass glass-strong w-[min(480px,92vw)] p-7">
          <h2 className="text-[22px] font-[400] tracking-[-0.02em]">{title}</h2>
          <p className="mt-3 text-[14px] leading-relaxed text-muted">{text}</p>
          <div className="mt-7 flex justify-end gap-2">
            <button className="btn btn-ghost" onClick={() => close(false)}>Cancel</button>
            <button autoFocus className={clsx('btn', danger ? 'border-crit/40 bg-crit/15 text-crit hover:bg-crit/25' : 'btn-primary')} onClick={() => close(true)}>{ok}</button>
          </div>
        </motion.div>
      </div>);
  });
}

/** Animated counter for big thin numbers. */
export function Counter({ value, className }: { value: number; className?: string }) {
  return (
    <motion.span key={value} className={className} initial={{ opacity: 0, y: 10, filter: 'blur(6px)' }} animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }} transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}>
      {value}
    </motion.span>
  );
}

/** Small (i) button with an explanation on hover or keyboard focus. */
export function Tip({ text }: { text: string }) {
  return (
    <span className="group relative inline-flex align-middle">
      <button type="button" aria-label="More information" className="ml-1.5 grid h-5 w-5 place-items-center rounded-full text-dim transition hover:text-ink focus:text-ink focus:outline-none">
        <Info className="h-3.5 w-3.5" />
      </button>
      <span role="tooltip" className="pointer-events-none absolute bottom-full left-1/2 z-40 mb-2 w-[260px] -translate-x-1/2 translate-y-1 rounded-2xl border border-white/10 bg-[#0d1218]/95 p-3.5 text-[12.5px] font-normal leading-relaxed text-muted opacity-0 shadow-2xl backdrop-blur-xl transition duration-200 group-hover:translate-y-0 group-hover:opacity-100 group-focus-within:translate-y-0 group-focus-within:opacity-100">
        {text}
      </span>
    </span>
  );
}
