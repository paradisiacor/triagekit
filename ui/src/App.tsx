import { useEffect } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { Shell } from './components/Shell';
import { Toasts } from './components/ui';
import { ConsentDialog } from './components/Consent';
import { loadSettings, refresh, useStore, type Route } from './lib/store';
import Overview from './pages/Overview';
import ScanPage from './pages/Scan';
import Findings from './pages/Findings';
import HistoryPage from './pages/History';
import Protection from './pages/Protection';
import { AboutPage, SettingsPage } from './pages/Other';
import Doctor from './pages/Doctor';
import SafeStart from './pages/SafeStart';

const PAGES: Record<Route, () => JSX.Element> = {
  overview: Overview, scan: ScanPage, findings: Findings, history: HistoryPage, protection: Protection, settings: SettingsPage, about: AboutPage, doctor: Doctor, safestart: SafeStart,
};

export default function App() {
  const route = useStore((s) => s.route);
  useEffect(() => {
    refresh(); loadSettings();
    const key = (e: KeyboardEvent) => { if (e.key === 'F5') { e.preventDefault(); refresh(); } };
    window.addEventListener('keydown', key);
    window.addEventListener('contextmenu', (e) => { if (!(e.target as HTMLElement).closest('input,textarea,.select-text,pre')) e.preventDefault(); });
    return () => window.removeEventListener('keydown', key);
  }, []);
  const Page = PAGES[route];
  return (
    <Shell>
      <AnimatePresence mode="wait">
        <motion.div key={route} initial={{ opacity: 0, y: 10, filter: 'blur(4px)' }} animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }} exit={{ opacity: 0, y: -6, filter: 'blur(4px)' }} transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}>
          <Page />
        </motion.div>
      </AnimatePresence>
      <Toasts />
      <ConsentDialog />
    </Shell>
  );
}
