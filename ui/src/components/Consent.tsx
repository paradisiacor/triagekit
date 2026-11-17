import { motion } from 'motion/react';
import { Globe, Lock } from 'lucide-react';
import { call } from '../lib/api';
import { loadSettings, safe, toast, useStore } from '../lib/store';

/** First-run question: may TriageKit look up file fingerprints online? Nothing is sent until the user says yes. */
export function ConsentDialog() {
  const st = useStore((s) => s.settings);
  if (!st || st.values.onlineLookupsAsked) return null;
  const answer = (on: boolean) => safe(async () => {
    await call('settings.save', { values: { ...st.values, onlineLookups: on, onlineLookupsAsked: true }, secrets: {} });
    await loadSettings();
    toast(on ? 'Online lookups are on. You can change this in Settings.' : 'Staying offline. You can change this in Settings.');
  });
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/65 backdrop-blur-sm">
      <motion.div initial={{ opacity: 0, scale: 0.96, y: 8 }} animate={{ opacity: 1, scale: 1, y: 0 }} role="dialog" aria-modal="true" className="glass glass-strong w-[min(560px,92vw)] p-8">
        <div className="grid h-12 w-12 place-items-center rounded-2xl bg-brand/15 text-brand-2"><Globe className="h-5 w-5" /></div>
        <h2 className="mt-5 text-[24px] font-[380] tracking-[-0.02em]">Check suspicious files online?</h2>
        <p className="mt-3 text-[14px] leading-relaxed text-muted">TriageKit can ask reputation services whether suspicious files are known to be safe or malicious. This makes results more accurate.</p>
        <ul className="mt-4 flex flex-col gap-2 text-[13.5px] text-muted">
          <li className="flex gap-2.5"><Lock className="mt-0.5 h-4 w-4 shrink-0 text-ok" />Only a file's fingerprint (SHA-256 hash) is sent. Never the file, its name or anything about you.</li>
          <li className="flex gap-2.5"><Lock className="mt-0.5 h-4 w-4 shrink-0 text-ok" />Sent to CIRCL (Luxembourg's CERT) and, only if you add your own key, VirusTotal or MalwareBazaar.</li>
          <li className="flex gap-2.5"><Lock className="mt-0.5 h-4 w-4 shrink-0 text-ok" />Everything else stays on this PC. You can change this any time in Settings.</li>
        </ul>
        <div className="mt-7 flex justify-end gap-2">
          <button className="btn btn-ghost" onClick={() => answer(false)}>Stay offline</button>
          <button className="btn btn-primary" autoFocus onClick={() => answer(true)}>Allow online lookups</button>
        </div>
      </motion.div>
    </div>
  );
}
