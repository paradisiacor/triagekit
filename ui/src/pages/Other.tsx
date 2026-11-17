import { Fragment, useEffect, useState } from 'react';
import { Check, Trash2, Plus } from 'lucide-react';
import { call } from '../lib/api';
import { loadSettings, refresh, safe, toast, useStore } from '../lib/store';
import type { Settings, SuppressionItem } from '../lib/types';
import { Glass, PageHeader, Switch } from '../components/ui';
import { Logo } from '../components/Shell';
import { Row } from './Protection';

export function SettingsPage() {
  const st = useStore((s) => s.settings);
  const [v, setV] = useState<Settings['values'] | null>(null);
  const [sec, setSec] = useState<Record<string, string>>({});
  useEffect(() => { if (!st) loadSettings(); else setV(st.values); }, [st]);
  if (!st || !v) return <div className="text-muted">Loading…</div>;
  const sw = (k: keyof Settings['values']) => <Switch checked={!!v[k]} onChange={(x) => setV({ ...v, [k]: x })} />;
  const num = (k: keyof Settings['values'], min: number, max: number) => <input type="number" min={min} max={max} className="field w-[90px] text-right" value={v[k] as number} onChange={(e) => setV({ ...v, [k]: Math.max(min, Math.min(max, +e.target.value || min)) })} />;
  const secret = (k: 'virusTotal' | 'malwareBazaar') => {
    const info = st.secrets[k];
    return (
      <div className="flex gap-2">
        <input type="password" autoComplete="off" spellCheck={false} className="field w-[260px]" placeholder={sec[k] === '' && info.set ? 'Will be removed on save' : info.set ? `Saved · ends in ${info.hint}` : 'Paste key'} value={sec[k] ?? ''} onChange={(e) => setSec({ ...sec, [k]: e.target.value })} />
        {info.set && <button className="btn btn-icon btn-ghost" title="Remove key" onClick={() => setSec({ ...sec, [k]: '' })}><Trash2 className="h-4 w-4" /></button>}
      </div>
    );
  };
  return (
    <div className="mx-auto max-w-[1000px]">
      <PageHeader eyebrow="Settings" title="Settings" sub={st.path ? `Saved in ${st.path}` : undefined} />
      <h3 className="label mb-3 mt-2">Scanning</h3>
      <Glass>
        <Row title="Also run Microsoft Defender's quick scan" help="Off by default. Defender removes threats it finds under its own settings, so this is the only step that can change files." tip="Asks Defender to run its quick scan during a full check. Defender, not TriageKit, may quarantine what it finds.">{sw('runDefenderQuickScan')}</Row>
        <Row title="Built-in malware rules" help="Scans unsigned programs and scripts with TriageKit's signed rules." tip="Checks unsigned programs and scripts for known malware patterns. Runs locally.">{sw('runYara')}</Row>
        <Row title="Sysinternals Autoruns" help="Deeper startup list, if autorunsc64.exe is in tools\Sysinternals." tip="Extra-thorough startup list from Microsoft. Used only if autorunsc64.exe is in tools\Sysinternals.">{sw('runAutoruns')}</Row>
        <Row title="Event log look-back (days)" help="How far back to look for things like Defender being switched off." tip="How far back to look for warning signs, like Defender being switched off.">{num('eventLogDays', 1, 180)}</Row>
        <Row title="Recent files look-back (days)" help="How far back the file sweep looks." tip="How far back to look for newly created programs in risky folders.">{num('recentFileDays', 1, 90)}</Row>
        <Row title="Look inside archives and documents" help="Checks ZIP files, Office macros and shortcuts in Downloads, Desktop and Temp. In memory only." tip="Opens ZIPs and Office files in memory to find hidden scripts and macros. Nothing is extracted.">{sw('scanArchives')}</Row>
        <Row title="Remember checked system files" help="Faster repeat checks: Windows and Program Files results are reused for 7 days." tip="Skips re-checking unchanged Windows and Program Files files for 7 days. Your own folders are always re-checked.">{sw('rememberFileChecks')}</Row>
      </Glass>
      <AcceptedList />
      <h3 className="label mb-3 mt-8">Updates</h3>
      <Glass>
        <Row title="Check for updates" help="Once a day. Only asks the TriageKit server for the newest version; nothing about this PC is sent." tip="Looks for a newer TriageKit once a day. Updates are signed and checked before they're installed.">{sw('checkForUpdates')}</Row>
      </Glass>
      <h3 className="label mb-3 mt-8">Online intelligence</h3>
      <Glass>
        <Row title="Online lookups" help="Look up file fingerprints (SHA-256) with reputation services. Files are never uploaded." tip="Checks file fingerprints online. Only the fingerprint is sent, never the file.">{sw('onlineLookups')}</Row>
        <Row title="CIRCL known-file database" help="Recognises legitimate files to cut false alarms. Free, no key." tip="Free list of known legitimate files. Cuts false alarms. No key needed.">{sw('reputationCircl')}</Row>
        <Row title="Microsoft Defender re-check" help="Asks Defender to re-check suspicious files locally. No key." tip="Asks Defender, on this PC, to re-check suspicious files. Nothing is sent online.">{sw('reputationDefender')}</Row>
        <Row title="VirusTotal API key" help="Optional. Your own free key for personal use, stored only on this PC." tip="Your free VirusTotal key adds ~70 antivirus opinions. Stored only on this PC.">{secret('virusTotal')}</Row>
        <Row title="MalwareBazaar Auth-Key" help="Optional. Your own free key from abuse.ch, stored only on this PC." tip="Your free key to check files against known malware samples. Stored only on this PC.">{secret('malwareBazaar')}</Row>
      </Glass>
      <div className="sticky bottom-0 mt-6 flex justify-end py-4">
        <button className="btn btn-primary btn-lg" onClick={() => safe(async () => { await call('settings.save', { values: v, secrets: sec }); setSec({}); await loadSettings(); toast('Settings saved'); })}><Check className="h-4 w-4" />Save settings</button>
      </div>
    </div>
  );
}

function AcceptedList() {
  const [items, setItems] = useState<SuppressionItem[] | null>(null);
  const [path, setPath] = useState('');
  const load = () => safe(async () => setItems(await call<SuppressionItem[]>('suppressions.list')));
  useEffect(() => { load(); }, []);
  const kindLabel = { finding: 'Finding', rule: 'All of a type', path: 'Excluded folder', file: 'File' } as const;
  return (<>
    <h3 className="label mb-3 mt-8">Accepted &amp; excluded</h3>
    <Glass>
      <div className="flex items-center gap-3 border-b border-white/[0.05] px-6 py-4">
        <div className="min-w-0 flex-1"><div className="text-[14px]">Exclude a folder</div><div className="mt-0.5 text-[12.5px] text-muted">Files in it are skipped by malware rules, and findings that mention it are accepted. Critical findings always still show.</div></div>
        <input className="field w-[280px]" placeholder={'D:\\Games\\Tools'} value={path} onChange={(e) => setPath(e.target.value)} />
        <button className="btn" disabled={!path.trim()} onClick={() => safe(async () => { await call('findings.accept', { kind: 'path', path, reason: 'Excluded folder' }); setPath(''); toast('Folder excluded'); await load(); await refresh(true); })}><Plus className="h-4 w-4" />Exclude</button>
      </div>
      {items === null ? <div className="px-6 py-5 text-[13px] text-muted">Loading…</div>
        : items.length === 0 ? <div className="px-6 py-5 text-[13px] text-muted">Nothing accepted yet. Use "This is fine…" on a finding to stop it coming back.</div>
        : items.map((i) => (
          <div key={i.id} className="flex items-center gap-3 border-b border-white/[0.05] px-6 py-3 last:border-0">
            <span className="chip shrink-0">{kindLabel[i.kind] ?? i.kind}</span>
            <div className="min-w-0 flex-1"><div className="truncate text-[13.5px]">{i.kind === 'rule' ? i.ruleId : i.title}</div><div className="mt-0.5 text-[12px] text-dim">{i.reason || 'No reason given'} · {new Date(i.created).toLocaleDateString()}{i.until ? ` · until ${new Date(i.until).toLocaleDateString()}` : ''}</div></div>
            <button className="btn btn-icon btn-ghost" title="Undo" onClick={() => safe(async () => { await call('suppressions.remove', { id: i.id }); await load(); await refresh(true); })}><Trash2 className="h-4 w-4" /></button>
          </div>))}
    </Glass>
  </>);
}

function UpdateCard() {
  const a = useStore((s) => s.app);
  const [busy, setBusy] = useState(false);
  const u = a?.update;
  const done = !!u?.status?.startsWith('Version');
  if (!u) return (
    <div className="mb-6 flex items-center gap-3 rounded-2xl border border-white/[0.06] bg-white/[0.02] p-4">
      <div className="min-w-0 flex-1 text-[13px] text-muted">You have the latest version we know of.</div>
      <button className="btn btn-ghost" disabled={busy} onClick={() => safe(async () => { setBusy(true); try { const r: any = await call('update.check'); toast(r?.available ? `Version ${r.version} is available` : 'TriageKit is up to date'); await refresh(); } finally { setBusy(false); } })}>{busy ? 'Checking…' : 'Check now'}</button>
    </div>);
  return (
    <div className="mb-6 rounded-2xl border border-brand/30 bg-brand/[0.08] p-5">
      <div className="label !text-brand-2">Update available</div>
      <div className="mt-1 text-[18px] font-medium">Version {u.version}</div>
      {u.notes && <p className="mt-2 whitespace-pre-line text-[13px] leading-relaxed text-muted">{u.notes}</p>}
      <p className="mt-2 text-[12px] text-dim">Signed by the TriageKit release key. The download is checked against its published fingerprint before anything is replaced; the previous version is kept until the next start.</p>
      <div className="mt-4 flex items-center gap-3">
        {done ? <button className="btn btn-primary" onClick={() => call('app.restart')}>Restart now</button>
          : <button className="btn btn-primary" disabled={busy || !!u.status} onClick={() => safe(async () => { setBusy(true); try { await call('update.install'); } finally { setBusy(false); } })}>{u.status ?? 'Download and install'}</button>}
        {done && <span className="text-[13px] text-muted">{u.status}</span>}
      </div>
    </div>);
}

export function AboutPage() {
  const a = useStore((s) => s.app);
  return (
    <div className="mx-auto max-w-[1000px]">
      <PageHeader eyebrow="About" title="TriageKit" sub="Read-only Windows security check. Free for everyone." />
      <div className="grid grid-cols-[1.1fr_1fr] gap-4">
        <Glass strong className="relative overflow-hidden p-8">
          <div className="absolute -right-16 -top-16 h-56 w-56 rounded-full bg-brand opacity-20 blur-[80px]" />
          <Logo size={44} />
          <div className="label mt-6">Our promise</div>
          <h2 className="mt-2 text-[30px] font-[320] leading-tight tracking-[-0.03em]">It looks.<br />It never touches.</h2>
          <p className="mt-4 text-[14px] leading-relaxed text-muted">TriageKit does not delete, quarantine, change or upload anything. Online lookups send only file fingerprints, and only to the services you enable. Reports stay on this PC unless you share them.</p>
        </Glass>
        <Glass className="p-7">
          <UpdateCard />
          <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-3 text-[13px]">
            {[['Version', a?.version], ['Edition', a?.edition], ['Rule pack', `${a?.rules.version ?? ''}${a?.rules.trusted ? ' · signed ✓' : ''}`], ['Web engine', a?.webview], ['Program', a?.exePath], ['SHA-256', a?.exeSha256]].map(([k, v]) => (
              <Fragment key={k}><dt className="text-muted">{k}</dt><dd className="select-text break-all font-mono text-[12px]">{v ?? 'n/a'}</dd></Fragment>
            ))}
          </dl>
        </Glass>
      </div>
      <p className="mt-6 text-[12px] leading-relaxed text-dim">Built with React, Three.js, Motion and Tailwind CSS. Fonts: Geist (SIL OFL). Icons: Lucide (ISC). MITRE ATT&CK® is a registered trademark of The MITRE Corporation.</p>
    </div>
  );
}
