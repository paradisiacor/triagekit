// Bridge to the TriageKit host (WebView2). Request {id, cmd, args} -> {id, ok, result | error}; events {event, data}.
declare const __PREVIEW__: boolean;
type Listener = (data: any) => void;
const host: any = (window as any).chrome?.webview;
let seq = 0;
const pending = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void }>();
const listeners = new Map<string, Set<Listener>>();
let mock: ((cmd: string, args: any) => Promise<any>) | null = null;

function emit(name: string, data: any) { listeners.get(name)?.forEach((fn) => { try { fn(data); } catch (e) { console.error(e); } }); }

if (host) {
  host.addEventListener('message', (e: MessageEvent) => {
    const m: any = e.data;
    if (!m || typeof m !== 'object') return;
    if (m.id && pending.has(m.id)) { const p = pending.get(m.id)!; pending.delete(m.id); m.ok ? p.resolve(m.result) : p.reject(new Error(m.error || 'Request failed')); }
    else if (m.event) emit(m.event, m.data);
  });
}

export function on(name: string, fn: Listener) {
  if (!listeners.has(name)) listeners.set(name, new Set());
  listeners.get(name)!.add(fn);
  return () => { listeners.get(name)!.delete(fn); };
}

export async function call<T = any>(cmd: string, args: Record<string, unknown> = {}): Promise<T> {
  if (!host) {
    if (__PREVIEW__) {
      mock ??= (await import('./mock')).createMock(emit);
      return mock(cmd, args);
    }
    throw new Error('TriageKit host not available');
  }
  const id = ++seq;
  return new Promise<T>((resolve, reject) => {
    pending.set(id, { resolve, reject });
    host.postMessage({ id, cmd, args });
    const long = cmd === 'agent.install' || cmd === 'agent.uninstall';
    setTimeout(() => { if (pending.has(id)) { pending.delete(id); reject(new Error('The app did not respond.')); } }, long ? 300000 : 60000);
  });
}
