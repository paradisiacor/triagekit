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
const sampleCheck = {
  target: 'C:\\Users\\alex\\Downloads\\Cool-Game-Repack.zip', name: 'Cool-Game-Repack.zip', started: new Date().toISOString(), seconds: 6.4, verdict: 'Dangerous',
  headline: 'Dangerous. Don\'t run it.', summary: 'TriageKit found signs that this download is built to infect the PC. Get the program from its official website or store instead.',
  downloadedFrom: 'mega.nz', files: 214, programs: 9, archives: 2, onlineLookups: true,
  notChecked: ['Cool-Game-Repack.zip » Cool Game/data2.bin: expands to more than 1,000 times its packed size, only the start was checked'],
  findings: [
    { severity: 'High', title: 'Instructions to switch off your antivirus: README.txt', detail: 'Cool-Game-Repack.zip » Cool Game/README.txt\nIt says: "IMPORTANT before installing please disable Windows Defender real-time protection, the crack is a false positive". Real software never needs your protection switched off. This is the most common way malware gets past antivirus.', recommendation: 'Don\'t follow these instructions and don\'t run the download. Delete it.', ruleId: 'safestart.disable-av-instructions' },
    { severity: 'High', title: 'Program padded to an unusual size: setup.exe', detail: 'Cool-Game-Repack.zip » Cool Game/setup.exe\nThe program is 742 MB, but 739 MB of that is filler added after the real program. Malware does this so it\'s too big for antivirus cloud scans and upload sites.', recommendation: 'Don\'t run it. Real games and installers keep their data in separate files, not as filler inside the .exe.', ruleId: 'safestart.padded' },
    { severity: 'Medium', title: 'Script packed into an unsigned program: crack/launcher.exe', detail: 'Cool-Game-Repack.zip » Cool Game/crack/launcher.exe\nThis program is a Python (PyInstaller) script wrapped into an .exe and isn\'t signed. Most info stealers that target gamers are built exactly like this.', recommendation: 'Only run it if you trust its author and expected a tool like this.', ruleId: 'safestart.packed-script' },
  ],
  items: [
    { path: 'Cool-Game-Repack.zip » Cool Game/setup.exe', kind: 'Program', size: 778043392, signature: 'not checked (too large)', risk: 'High', reasons: ['Program padded to an unusual size: setup.exe'] },
    { path: 'Cool-Game-Repack.zip » Cool Game/README.txt', kind: 'Text', size: 1840, signature: 'n/a', risk: 'High', reasons: ['Instructions to switch off your antivirus: README.txt'] },
    { path: 'Cool-Game-Repack.zip » Cool Game/crack/launcher.exe', kind: 'Program', size: 9431040, signature: 'not signed', risk: 'Medium', reasons: ['Script packed into an unsigned program: crack/launcher.exe'] },
    { path: 'Cool-Game-Repack.zip » Cool Game/redist/vc_redist.x64.exe', kind: 'Program', size: 25165824, signature: 'valid', signer: 'Microsoft Corporation', risk: 'Info', reasons: [] },
    { path: 'Cool-Game-Repack.zip » Cool Game/data2.bin', kind: 'Other', size: 4294967296, signature: 'n/a', risk: 'Info', reasons: [], note: 'only the start was checked' },
  ],
  stopped: false,
};
const sampleWatch = {
  before: new Date(Date.now() - 9 * 60e3).toISOString(), after: new Date().toISOString(), verdict: 'Dangerous', headline: 'Dangerous changes found.',
  summary: 'What was installed changed things that malware changes. Look at the red items below. If you don\'t recognise them, uninstall the program, run a full check and change important passwords from another device.',
  newFindings: [{ severity: 'High', title: 'Defender exclusion: Path C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Network', detail: 'Defender does not scan anything matching this exclusion. Malware often adds exclusions for itself.', recommendation: 'Remove the exclusion in Windows Security > Virus & threat protection > Exclusions, unless you know exactly why it is there.', ruleId: 'defender.exclusion' }],
  goneFindings: [],
  added: [
    { category: 'Defender exclusion', kind: 'Added', text: 'Path: C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Network', severity: 'High', why: 'Microsoft Defender now skips this location. Installers almost never need this; malware always wants it.' },
    { category: 'Startup entry, task or service', kind: 'Added', text: 'Scheduled task \\MicrosoftEdgeUpdateTaskMachineCore2: C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Network\\svchost.exe', severity: 'High', why: 'This now starts automatically.' },
    { category: 'hosts file entry', kind: 'Added', text: '127.0.0.1 activation.coolgame-studio.com', severity: 'Medium', why: 'The hosts file now sends a website name somewhere else. Cracks use this to block activation; malware to redirect logins.' },
    { category: 'Installed program', kind: 'Added', text: 'Cool Game: 1.0.4 (Cool Game Studio)', severity: 'Info', why: 'Installed.' },
  ],
  removed: [], unchanged: 806, notes: [],
};
const watchState: any = { before: null, last: 'watch_20261117-102000' };

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
      const skip = /Autoruns|quick scan/i.test(checks[i]);
      emit('scan.checkDone', { name: checks[i], ms, state: skip ? 'skipped' : 'ok', note: skip ? (/Autoruns/.test(checks[i]) ? 'tools\\Sysinternals\\autorunsc64.exe not found' : 'Off (Defender may remove what it finds)') : null });
      emit('scan.progress', { name: checks[i], index: i + 1, total: checks.length });
    }
    state.scanning = false; emit('scan.finished', { id: 6, score: 58, verdict: 'At risk', counts: counts(fs), newCount: 1, resolvedCount: 3 });
  }
  if (p.has('autoscan')) setTimeout(() => runScan('full'), 400);
  const accepted: any[] = [];
  return async (cmd: string, args: any) => {
    await sleep(30);
    switch (cmd) {
      case 'safestart.pick': return { token: 't1', name: args.folder ? 'Cool Game Repack' : 'Cool-Game-Repack.zip', path: 'C:\\Users\\alex\\Downloads\\' + (args.folder ? 'Cool Game Repack' : 'Cool-Game-Repack.zip'), folder: !!args.folder, size: 734003200 };
      case 'safestart.check': {
        emit('safestart.started', { name: 'Cool-Game-Repack.zip' });
        let n = 0; const files = ['Cool Game/setup.exe', 'Cool Game/data1.bin', 'Cool Game/README.txt', 'Cool Game/crack/steam_api64.dll', 'Cool Game/redist/vc_redist.x64.exe'];
        const t = setInterval(() => { emit('safestart.progress', { text: 'Cool-Game-Repack.zip » ' + files[n % files.length], files: ++n * 37 }); if (n >= 6) { clearInterval(t); emit('safestart.done', { id: 'check_20261117-101500', result: sampleCheck }); } }, 450);
        return { ok: true };
      }
      case 'safestart.cancel': return true;
      case 'safestart.history': return [{ id: 'check_20261117-101500', name: 'Cool-Game-Repack.zip', verdict: 'Dangerous', started: new Date(now - 3600e3).toISOString(), files: 214 }, { id: 'check_20261116-200000', name: 'OBS-Studio-31.0-Windows-x64-Installer.exe', verdict: 'NoThreatsFound', started: new Date(now - 26 * 3600e3).toISOString(), files: 1 }];
      case 'safestart.get': return String(args.id).startsWith('watch') ? sampleWatch : sampleCheck;
      case 'watch.state': return watchState;
      case 'watch.before': case 'watch.after': {
        const after = cmd === 'watch.after'; const names = ['System posture', 'Antivirus & Defender', 'Autostarts & persistence', 'Hidden persistence & accounts', 'Root certificates', 'Drivers', 'Browser extensions', 'Installed software', 'Network', 'Windows hardening'];
        emit('watch.started', { after, total: names.length }); let i = 0;
        const t = setInterval(() => { i++; emit('watch.progress', { name: names[i - 1], index: i, total: names.length }); if (i >= names.length) { clearInterval(t); if (!after) watchState.before = { taken: new Date().toISOString(), machine: 'DESKTOP-7Q2K', items: 812, findings: 9 }; emit('watch.done', after ? { after, id: 'watch_20261117-102000', result: sampleWatch } : { after }); } }, 300);
        return { ok: true };
      }
      case 'watch.discard': watchState.before = null; return { ok: true };
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
