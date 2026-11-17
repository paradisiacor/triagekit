import FINDINGS from './mockdata';
import type { Finding, Highlight, Severity } from './types';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const SEV: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const counts = (fs: Finding[]) => Object.fromEntries(SEV.map((s) => [s, fs.filter((f) => f.severity === s).length])) as any;
function highlights(fs: Finding[]): Highlight[] {
  const m = new Map<string, Highlight>();
  for (const f of fs) { if (f.severity === 'Low' || f.severity === 'Info') continue; const k = f.ruleId || f.title; const h = m.get(k); if (h) h.count++; else m.set(k, { ...f, count: 1 }); }
  return [...m.values()].map((h) => h.count > 1 ? { ...h, title: `${h.title} (+${h.count - 1} similar)` } : h).slice(0, 5);
}
export function createMock(emit: (n: string, d: any) => void) {
  const now = Date.now();
  const p = new URLSearchParams(location.search);
  const fs = FINDINGS as Finding[];
  const scans = [
    { id: 6, time: new Date(now - 6 * 60e3).toISOString(), score: 58, verdict: 'At risk', counts: counts(fs), quick: false },
    { id: 5, time: new Date(now - 26 * 3600e3).toISOString(), score: 63, verdict: 'Needs attention', counts: { Critical: 0, High: 2, Medium: 3, Low: 6, Info: 2 }, quick: false },
    { id: 4, time: new Date(now - 50 * 3600e3).toISOString(), score: 61, verdict: 'Needs attention', counts: { Critical: 0, High: 2, Medium: 3, Low: 6, Info: 2 }, quick: true },
    { id: 3, time: new Date(now - 74 * 3600e3).toISOString(), score: 41, verdict: 'At risk', counts: { Critical: 0, High: 4, Medium: 6, Low: 7, Info: 2 }, quick: false },
    { id: 2, time: new Date(now - 98 * 3600e3).toISOString(), score: 47, verdict: 'At risk', counts: { Critical: 0, High: 4, Medium: 5, Low: 7, Info: 2 }, quick: false },
    { id: 1, time: new Date(now - 122 * 3600e3).toISOString(), score: 22, verdict: 'Likely compromised', counts: { Critical: 1, High: 4, Medium: 6, Low: 7, Info: 2 }, quick: false },
  ];
  if (p.has('empty')) scans.length = 0;
  if (p.has('clean')) { scans[0] = { ...scans[0], score: 94, verdict: 'Looks clean', counts: { Critical: 0, High: 0, Medium: 0, Low: 3, Info: 2 } }; }
  const state: any = {
    version: '0.14.0', edition: 'Portable', elevated: true, machine: 'DESKTOP-7Q2K', os: 'Windows 11 Pro 24H2', scanning: false,
    exePath: 'D:\\TriageKit\\TriageKit.exe', exeSha256: '3F1A…sample', webview: '131.0', rules: { version: '2026.11.14', trusted: true }, update: p.has('update') ? { version: '0.10.1', notes: 'Archive and Office macro scanning\nAccepted findings\nShareable reports', published: new Date().toISOString(), size: 54000000, status: null } : null,
    agent: { installed: p.has('agent'), running: true, nextScan: new Date(now + 15 * 3600e3).toISOString(), config: { dailyScanTime: '12:30', quickScheduledScans: false, notifyOnNewFindings: true, keepScans: 60 } },
  };
  const settings = { modules: [] as string[], path: 'D:\\TriageKit\\config.json', values: { runDefenderQuickScan: true, runYara: true, runAutoruns: true, eventLogDays: 30, recentFileDays: 14, onlineLookups: true, onlineLookupsAsked: !p.has('consent'), reputationCircl: true, reputationDefender: true, scanArchives: true, rememberFileChecks: true, checkForUpdates: true }, secrets: { virusTotal: { set: true, hint: '9f2c' }, malwareBazaar: { set: false } } };
  async function runScan(mode: string) {
    const checks = ['System posture', 'Antivirus & Defender', 'Running processes', 'Autostarts & persistence', 'Network', 'Event logs', 'Browser extensions', 'Installed software', 'Root certificates', 'Drivers', 'Camera, microphone & location', 'Windows hardening', 'Hidden persistence & accounts', 'Loaded modules', 'Recently created files', 'Defender quick scan', 'Sysinternals Autoruns', 'YARA scan', 'Reputation'].filter((_, i) => mode !== 'quick' || i < 13);
    state.scanning = true; emit('scan.started', { checks, quick: mode === 'quick' });
    for (let i = 0; i < checks.length; i++) {
      emit('scan.checkStart', { name: checks[i] });
      emit('scan.status', { text: `Reading ${checks[i].toLowerCase()}…` });
      const ms = p.has('slow') ? 4000 : 120 + (i % 4) * 90;
      await sleep(ms);
      if (p.has('hold') && i === 5) return;
      emit('scan.checkDone', { name: checks[i], ms });
      emit('scan.progress', { name: checks[i], index: i + 1, total: checks.length });
    }
    state.scanning = false; emit('scan.finished', { id: 6, score: 58, verdict: 'At risk', counts: counts(fs), newCount: 1, resolvedCount: 3 });
  }
  if (p.has('autoscan')) setTimeout(() => runScan('full'), 400);
  const accepted: any[] = [];
  return async (cmd: string, args: any) => {
    await sleep(30);
    switch (cmd) {
      case 'app.state': return state;
      case 'app.theme': return true;
      case 'scans.list': return scans;
      case 'scan.get': { const s = scans.find((x) => x.id === args.id) || scans[0]; return { summary: s, findings: fs, highlights: highlights(fs),
        diff: s.id === 1 ? { first: true, new: [], resolved: [] } : { first: false, new: [{ severity: 'High', title: fs[2].title }], resolved: [{ severity: 'High', title: 'Unsigned program running from a risky folder: setup_x64.exe' }, { severity: 'Medium', title: 'Extension not from the official store: Coupon Helper (Chrome)' }, { severity: 'Low', title: 'Remote-access tool installed: RustDesk' }] } }; }
      case 'scan.start': runScan(args.mode); return { ok: true };
      case 'scan.cancel': return { ok: true };
      case 'settings.get': return settings;
      case 'findings.accept': accepted.push({ id: String(accepted.length + 1), kind: args.kind, title: args.title || args.path, reason: args.reason, ruleId: args.ruleId, path: args.path, created: new Date().toISOString() });
        { const f = fs.find((x: any) => x.title === args.title); if (f) { f.accepted = true; f.acceptedReason = args.reason || 'Accepted by you'; } } return { ok: true };
      case 'suppressions.list': return accepted;
      case 'suppressions.remove': { const i = accepted.findIndex((x) => x.id === args.id); if (i >= 0) { const it = accepted.splice(i, 1)[0]; const f = fs.find((x: any) => x.title === it.title); if (f) f.accepted = false; } return true; }
      case 'update.check': return { available: false };
      case 'update.install': state.update.status = 'Version 0.10.1 is installed. Restart TriageKit to use it.'; return { ok: true };
      case 'report.share': return { path: 'D:\\TriageKit\\Reports\\scan\\report-shareable.html' };
      case 'settings.save': Object.assign(settings.values, args.values); return { ok: true };
      case 'doctor.latest': return { found: true, time: new Date(now - 3600e3).toISOString(),
        live: { Ran: true, Seconds: 20, CpuPercent: { Avg: 7.4, Max: 31 }, DpcPercent: { Avg: 4.1, Max: 9.8, WorstCore: 38 }, InterruptPercent: { Avg: 1.2, Max: 2.5 }, DiskMs: { Disk: '0 C:', Avg: 1.8, Max: 14 }, AvailableMB: { Min: 9120, Total: 32702 },
          TopCpu: [{ Name: 'Cyberpunk2077', Percent: 38.5, Foreground: true, Signed: true }, { Name: 'msedge', Percent: 4.2, Signed: true }, { Name: 'Discord', Percent: 2.1, Signed: true }, { Name: 'RazerAppEngine', Percent: 1.6, Signed: true }, { Name: 'svchost', Percent: 1.1, Signed: true, Microsoft: true }] },
        hardware: { Displays: [{ Monitor: 'LG ULTRAGEAR', Primary: true, Resolution: '2560x1440', RefreshHz: 60, MaxRefreshHz: 240 }, { Monitor: 'DELL P2422H', Primary: false, Resolution: '1920x1080', RefreshHz: 60, MaxRefreshHz: 60 }] },
        sensors: { Source: 'HWiNFO', Readings: [{ Kind: 'Temperature', Label: 'CPU Package', Value: 61, Max: 88 }, { Kind: 'Temperature', Label: 'GPU Temperature', Value: 48, Max: 71 }, { Kind: 'Temperature', Label: 'GPU Hot Spot', Value: 60, Max: 84 },
          { Kind: 'Voltage', Label: '+12V', Value: 12.1, Min: 11.98, Max: 12.14, Avg: 12.08 }, { Kind: 'Voltage', Label: '+5V', Value: 5.04, Min: 5.02, Max: 5.06 }, { Kind: 'Voltage', Label: '+3.3V', Value: 3.31, Min: 3.3, Max: 3.33 }, { Kind: 'Voltage', Label: 'Vcore', Value: 1.12, Max: 1.38 }] },
        highlights: [{ severity: 'High', category: 'Stability', title: '3 blue screens in the last 30 days', recommendation: 'The graphics driver stopped responding. Usually a GPU driver problem, an unstable GPU overclock or overheating.', count: 1 },
          { severity: 'Medium', category: 'Stability', title: 'Graphics driver stopped responding 4 times', recommendation: 'Do a clean reinstall of the graphics driver (DDU in Safe Mode, then the latest driver). Remove GPU overclocks and check GPU temperatures.', count: 1 },
          { severity: 'Low', category: 'Performance', title: 'RAM runs at 2133 MT/s but is rated for 3600 MT/s', recommendation: 'Enable XMP (Intel) or EXPO/DOCP (AMD) in the BIOS. Typical gain: 5–15% more FPS in CPU-heavy games.', count: 1 },
          { severity: 'Low', category: 'Stability', title: 'Wow.exe crashed 5 times in 30 days', recommendation: 'An overlay (RivaTuner, Steam, Discord, Nahimic…) – try disabling overlays for this game.', count: 1 }],
        findings: [{ severity: 'High', category: 'Stability', title: '3 blue screens in the last 30 days', detail: '2× 0x116 VIDEO_TDR_FAILURE\n1× 0x1A MEMORY_MANAGEMENT', recommendation: 'Update GPU driver.' },
          { severity: 'Low', category: 'Performance', title: 'Drivers keep the CPU busy (a common cause of micro-stutter)', ruleId: 'perf.dpc-latency', detail: 'For 20 seconds, 4.1% of CPU time went to deferred driver work (DPC) and 1.2% to hardware interrupts.', recommendation: 'Update chipset, network and GPU drivers first. LatencyMon (free) shows exactly which driver is responsible.' },
          { severity: 'Medium', category: 'Performance', title: 'LG ULTRAGEAR runs at 60 Hz but supports 240 Hz', ruleId: 'perf.refresh-rate', evidence: { Monitor: 'LG ULTRAGEAR', Primary: true, Current: 60, Max: 240 }, detail: 'At 2560x1440 this main screen can show 240 frames per second, but Windows is set to 60.', recommendation: 'Settings > System > Display > Advanced display > Choose a refresh rate.' }],
        stability: { BlueScreens: [1, 2, 3], AppCrashes: [{ App: 'Wow.exe', Count: 5 }, { App: 'Discord.exe', Count: 2 }], HardwareErrors: 2, GpuDriverResets: 4, Disks: [{ Name: 'Samsung SSD 980 PRO 1TB', Health: 'Healthy', WearPercent: 4, TemperatureC: 41 }, { Name: 'WDC WD20EZRZ', Health: 'Healthy', TemperatureC: 33 }] },
        health: { DeviceProblems: [{ Name: 'Unknown USB Device', Code: 43 }], ReliabilityIndex: 4.7 },
        performance: { Memory: [{ GB: 16, Rated: 3600, Running: 2133 }], TotalRamGB: 32, PowerPlan: 'Balanced', Gpus: [{ Name: 'NVIDIA GeForce RTX 3070', Date: '2026-02-10' }] },
        gaming: { Discord: [{ Status: 'Clean' }] } };

      case 'agent.install': state.agent.installed = true; return { message: 'Daily protection is on.' };
      case 'agent.uninstall': state.agent.installed = false; return { message: 'Daily protection was turned off.' };
      case 'agent.scanNow': return { message: 'Scan started.' };
      case 'agent.saveConfig': Object.assign(state.agent.config, args); return { ok: true };
      default: return null;
    }
  };
}
