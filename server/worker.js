// TriageKit update service (Cloudflare Worker + D1 + one Durable Object).
//
// TriageKit is free and open source; there are no licences. This service only publishes signed update announcements.
// - The release signing key is generated INSIDE the "Vault" Durable Object and never leaves it. Nobody - not the
//   publisher, not the Cloudflare dashboard, not D1 - can read the private key.
// - The publisher signs in to /admin with a passkey (Windows Hello, phone, security key). No passwords.
//   The very first passkey needs a one-time setup code (secret BOOTSTRAP_CODE); after that, only a signed-in
//   publisher can add more passkeys, and every publish needs a fresh passkey touch bound to the exact announcement.
// - Apps fetch /v1/update and check the signature with the public key compiled into them. They send nothing about the PC.

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' };
const SEC_HEADERS = {
  'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY',
  'strict-transport-security': 'max-age=31536000',
  'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};
const MAX_BODY = 32 * 1024;
const SESSION_HOURS = 12;

const json = (data, status = 200, extra = {}) => new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...extra } });
const err = (message, status = 400) => json({ ok: false, error: message }, status);
const now = () => new Date().toISOString();
const enc = new TextEncoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (buf) => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64url = (s) => unb64(String(s).replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((String(s).length + 3) % 4));
const sha256 = async (data) => new Uint8Array(await crypto.subtle.digest('SHA-256', typeof data === 'string' ? enc.encode(data) : data));
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const randomHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));

async function readBody(request) {
  const len = +(request.headers.get('content-length') || 0);
  if (len > MAX_BODY) throw new Error('Request too large');
  const text = await request.text();
  if (text.length > MAX_BODY) throw new Error('Request too large');
  return text;
}
async function readJson(request) { try { return JSON.parse(await readBody(request)); } catch { return null; } }
const timingSafeEqual = async (a, b) => { const [x, y] = await Promise.all([sha256(String(a)), sha256(String(b))]); let d = 0; for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i]; return d === 0; };

function derToPem(der, label) {
  const s = b64(der).match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${s}\n-----END ${label}-----\n`;
}

// ECDSA DER signature (what authenticators produce) -> raw r||s (what WebCrypto verifies).
function derSigToRaw(der) {
  let i = 2; if (der[1] & 0x80) i += der[1] & 0x7f;
  const read = () => { if (der[i++] !== 0x02) throw new Error('bad sig'); const len = der[i++]; let v = der.slice(i, i + len); i += len; while (v.length > 32 && v[0] === 0) v = v.slice(1); const out = new Uint8Array(32); out.set(v, 32 - v.length); return out; };
  const r = read(), s = read(); const raw = new Uint8Array(64); raw.set(r); raw.set(s, 32); return raw;
}

async function log(env, kind, detail) {
  try { await env.DB.prepare('INSERT INTO events(kind, detail) VALUES (?1, ?2)').bind(kind, detail ?? null).run(); } catch {}
}

const vault = (env) => env.VAULT.get(env.VAULT.idFromName('vault'));
async function callVault(env, op, args = {}) {
  const r = await vault(env).fetch('https://vault/' + op, { method: 'POST', body: JSON.stringify(args) });
  const data = await r.json();
  if (!r.ok) throw Object.assign(new Error(data.error || 'Vault error'), { status: r.status });
  return data;
}

// ======================================================================= Durable Object: keys, passkeys, sessions
export class Vault {
  constructor(state, env) { this.state = state; this.storage = state.storage; this.env = env; this.keys = null; }

  async loadKeys() {
    if (this.keys) return this.keys;
    let stored = (await this.storage.get('keys')) || { created: now() };
    if (!stored.release) {   // signs update announcements (older stored licence keys are no longer used)
      const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      stored.release = { priv: await crypto.subtle.exportKey('jwk', kp.privateKey), spki: b64(await crypto.subtle.exportKey('spki', kp.publicKey)) };
      await this.storage.put('keys', stored);
    }
    const imp = (jwk) => crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    this.keys = { release: await imp(stored.release.priv), releasePub: stored.release.spki, created: stored.created };
    return this.keys;
  }

  async sign(which, text) {
    const k = await this.loadKeys();
    return b64(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k[which], enc.encode(text)));   // IEEE P1363 r||s
  }

  async fetch(request) {
    const op = new URL(request.url).pathname.slice(1);
    const a = await request.json().catch(() => ({}));
    try {
      switch (op) {
        case 'keys': { const k = await this.loadKeys(); return json({ release: derToPem(unb64(k.releasePub), 'PUBLIC KEY'), created: k.created }); }
        case 'signRelease': {
          // Signing needs a live session AND a fresh passkey touch made for exactly this payload (step-up), so a
          // stolen session cookie alone can't publish an update.
          if (!(await this.sessionValid(a.session))) return err('Signed out', 401);
          if (!a.assertion) return err('Confirm this action with your passkey.', 401);
          const purpose = 'release';
          await this.verifyAssertion({ rpId: a.rpId, origin: a.origin, credential: a.assertion, kind: 'stepup:' + purpose + ':' + a.digest });
          return json({ signature: await this.sign('release', a.text) });
        }
        case 'stepupOptions': {
          if (!(await this.sessionValid(a.session))) return err('Signed out', 401);
          if (!['release', 'passkey-add', 'passkey-remove'].includes(a.purpose) || !/^[0-9a-f]{64}$/.test(a.digest || '')) return err('Bad request');
          const creds = await this.creds();
          return json({ challenge: await this.newChallenge('stepup:' + a.purpose + ':' + a.digest), rpId: a.rpId, userVerification: 'required', allowCredentials: creds.map((c) => ({ type: 'public-key', id: c.id })), timeout: 120000 });
        }
        case 'logoutAll': {
          if (!(await this.sessionValid(a.session))) return err('Signed out', 401);
          const all = await this.storage.list({ prefix: 'session:' });
          await this.storage.delete([...all.keys()]);
          return json({ ok: true, ended: all.size });
        }
        case 'removePasskey': {
          if (!(await this.sessionValid(a.session))) return err('Signed out', 401);
          // A session alone can't change who may sign in: removing a passkey needs a touch of an existing one.
          if (!a.assertion) return err('Confirm this action with your passkey.', 401);
          await this.verifyAssertion({ rpId: a.rpId, origin: a.origin, credential: a.assertion, kind: 'stepup:passkey-remove:' + hex(await sha256(String(a.id || ''))) });
          const creds = await this.creds();
          if (creds.length <= 1) return err('Add another passkey before removing this one, or you would be locked out.');
          const left = creds.filter((c) => c.id.slice(0, 12) !== a.id);
          if (left.length === creds.length) return err('Passkey not found', 404);
          await this.storage.put('creds', left);
          return json({ ok: true });
        }
        case 'session': return json({ valid: await this.sessionValid(a.session) });
        case 'logout': { if (a.session) await this.storage.delete('session:' + hex(await sha256(a.session))); return json({ ok: true }); }
        case 'status': { const creds = await this.creds(); return json({ hasPasskeys: creds.length > 0, passkeys: creds.length }); }
        case 'passkeys': {
          if (!(await this.sessionValid(a.session))) return err('Signed out', 401);
          return json({ passkeys: (await this.creds()).map((c) => ({ id: c.id.slice(0, 12), name: c.name, created: c.created, lastUsed: c.lastUsed || null })) });
        }
        case 'registerOptions': return await this.registerOptions(a);
        case 'registerVerify': return await this.registerVerify(a);
        case 'loginOptions': return await this.loginOptions(a);
        case 'loginVerify': return await this.loginVerify(a);
        default: return err('Unknown op', 404);
      }
    } catch (e) { return err(e.message || 'Vault error', e.status || 400); }
  }

  async creds() { return (await this.storage.get('creds')) || []; }

  async sessionValid(token) {
    if (!token || typeof token !== 'string' || token.length > 100) return false;
    const key = 'session:' + hex(await sha256(token));
    const s = await this.storage.get(key);
    if (!s) return false;
    if (Date.parse(s.expires) < Date.now()) { await this.storage.delete(key); return false; }
    return true;
  }

  async newChallenge(kind) {
    await this.purgeExpired();
    const c = b64url(crypto.getRandomValues(new Uint8Array(32)));
    await this.storage.put('challenge:' + c, { kind, expires: Date.now() + 5 * 60e3 });
    return c;
  }

  // Old challenges and sessions would otherwise pile up forever.
  async purgeExpired() {
    const last = (await this.storage.get('lastPurge')) || 0;
    if (Date.now() - last < 3600e3) return;
    await this.storage.put('lastPurge', Date.now());
    for (const prefix of ['challenge:', 'session:']) {
      const items = await this.storage.list({ prefix, limit: 500 });
      const dead = [...items].filter(([, v]) => (typeof v.expires === 'number' ? v.expires : Date.parse(v.expires)) < Date.now()).map(([k]) => k);
      if (dead.length) await this.storage.delete(dead);
    }
  }
  async takeChallenge(c, kind) {
    if (typeof c !== 'string' || c.length > 100) return false;
    const key = 'challenge:' + c; const v = await this.storage.get(key);
    if (!v) return false;
    await this.storage.delete(key);
    return v.kind === kind && v.expires > Date.now();
  }

  async registerOptions({ rpId, session, code, name }) {
    const creds = await this.creds();
    const signedIn = await this.sessionValid(session);
    if (creds.length > 0 && !signedIn) throw Object.assign(new Error('Sign in first to add another passkey.'), { status: 401 });
    if (creds.length === 0) {
      if (!this.env.BOOTSTRAP_CODE) throw Object.assign(new Error('Setup is not enabled on the server.'), { status: 403 });
      if (!(await timingSafeEqual(String(code || '').trim(), this.env.BOOTSTRAP_CODE))) {
        await this.slowDown();
        throw Object.assign(new Error('That setup code is not right.'), { status: 401 });
      }
    }
    return json({
      challenge: await this.newChallenge('create'),
      rp: { id: rpId, name: 'TriageKit Admin' },
      user: { id: b64url(enc.encode('triagekit-admin')), name: 'admin', displayName: String(name || 'TriageKit admin').slice(0, 60) },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
      excludeCredentials: creds.map((c) => ({ type: 'public-key', id: c.id })),
      attestation: 'none', timeout: 120000,
    });
  }

  async slowDown() {
    const n = ((await this.storage.get('failures')) || 0) + 1;
    await this.storage.put('failures', n);
    await new Promise((r) => setTimeout(r, Math.min(5000, 250 * n)));
  }

  parseAuthData(ad, rpIdHash) {
    if (ad.length < 37) throw new Error('Bad authenticator data');
    for (let i = 0; i < 32; i++) if (ad[i] !== rpIdHash[i]) throw new Error('Passkey is for a different site');
    const flags = ad[32];
    if (!(flags & 0x01)) throw new Error('User presence missing');
    if (!(flags & 0x04)) throw new Error('User verification (PIN / Windows Hello) is required');
    const counter = new DataView(ad.buffer, ad.byteOffset + 33, 4).getUint32(0);
    return { flags, counter };
  }

  checkClientData(raw, type, origin) {
    const cd = JSON.parse(new TextDecoder().decode(raw));
    if (cd.type !== type) throw new Error('Wrong WebAuthn type');
    if (cd.origin !== origin) throw new Error('Wrong origin');
    if (cd.crossOrigin) throw new Error('Cross-origin passkey use is not allowed');
    return cd;
  }

  async registerVerify({ rpId, origin, session, code, name, credential, assertion }) {
    const creds = await this.creds();
    const signedIn = await this.sessionValid(session);
    if (creds.length > 0 && !signedIn) throw Object.assign(new Error('Sign in first.'), { status: 401 });
    // Adding a passkey needs a touch of an existing passkey, made for exactly this registration (bound to its
    // challenge). Otherwise a stolen session could register its own passkey and then pass every step-up.
    if (creds.length > 0) {
      if (!assertion) throw Object.assign(new Error('Confirm this action with your passkey.'), { status: 401 });
      const pending = JSON.parse(new TextDecoder().decode(unb64url((credential || {}).clientDataJSON || ''))).challenge;
      await this.verifyAssertion({ rpId, origin, credential: assertion, kind: 'stepup:passkey-add:' + hex(await sha256(String(pending || ''))) });
    }
    // Re-read: verifyAssertion updated the stored counters.
    const fresh = await this.creds(); creds.length = 0; creds.push(...fresh);
    if (creds.length === 0 && !(this.env.BOOTSTRAP_CODE && (await timingSafeEqual(String(code || '').trim(), this.env.BOOTSTRAP_CODE)))) { await this.slowDown(); throw Object.assign(new Error('That setup code is not right.'), { status: 401 }); }
    const c = credential || {};
    const clientData = unb64url(c.clientDataJSON);
    const cd = this.checkClientData(clientData, 'webauthn.create', origin);
    if (!(await this.takeChallenge(cd.challenge, 'create'))) throw new Error('This request expired - try again.');
    const ad = unb64url(c.authenticatorData);
    const { counter } = this.parseAuthData(ad, await sha256(rpId));
    if (!(ad[32] & 0x40)) throw new Error('No credential in response');
    // Attested credential data: aaguid(16) | idLen(2) | id
    const idLen = (ad[53] << 8) | ad[54];
    const credId = b64url(ad.slice(55, 55 + idLen));
    if (credId !== c.id) throw new Error('Credential id mismatch');
    const alg = c.publicKeyAlgorithm;
    if (alg !== -7 && alg !== -257) throw new Error('Unsupported passkey type');
    const spki = unb64url(c.publicKey);
    await crypto.subtle.importKey('spki', spki, alg === -7 ? { name: 'ECDSA', namedCurve: 'P-256' } : { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    creds.push({ id: credId, alg, spki: b64url(spki), counter, name: String(name || 'Passkey').slice(0, 60), created: now() });
    await this.storage.put('creds', creds);
    return json({ ok: true, session: signedIn ? null : await this.newSession() });
  }

  async loginOptions({ rpId }) {
    const creds = await this.creds();
    if (creds.length === 0) throw Object.assign(new Error('No passkeys yet - use the setup code first.'), { status: 409 });
    return json({ challenge: await this.newChallenge('get'), rpId, userVerification: 'required', allowCredentials: creds.map((c) => ({ type: 'public-key', id: c.id })), timeout: 120000 });
  }

  async loginVerify({ rpId, origin, credential }) {
    await this.verifyAssertion({ rpId, origin, credential, kind: 'get' });
    return json({ ok: true, session: await this.newSession() });
  }

  async verifyAssertion({ rpId, origin, credential, kind }) {
    const c = credential || {};
    const creds = await this.creds();
    const cred = creds.find((x) => x.id === c.id);
    if (!cred) { await this.slowDown(); throw Object.assign(new Error('Unknown passkey'), { status: 401 }); }
    const clientData = unb64url(c.clientDataJSON);
    const cd = this.checkClientData(clientData, 'webauthn.get', origin);
    if (!(await this.takeChallenge(cd.challenge, kind))) throw Object.assign(new Error('This confirmation expired or doesn\'t match - try again.'), { status: 401 });
    const ad = unb64url(c.authenticatorData);
    const { counter } = this.parseAuthData(ad, await sha256(rpId));
    const signed = new Uint8Array(ad.length + 32); signed.set(ad); signed.set(await sha256(clientData), ad.length);
    const spki = unb64url(cred.spki);
    let sig = unb64url(c.signature), ok;
    if (cred.alg === -7) {
      const key = await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, derSigToRaw(sig), signed);
    } else {
      const key = await crypto.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
      ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, signed);
    }
    if (!ok) { await this.slowDown(); throw Object.assign(new Error('Passkey signature is invalid'), { status: 401 }); }
    if (counter !== 0 && cred.counter !== 0 && counter <= cred.counter) throw Object.assign(new Error('Passkey counter went backwards - possible cloned key.'), { status: 401 });
    cred.counter = counter; cred.lastUsed = now();
    await this.storage.put('creds', creds);
    await this.storage.put('failures', 0);
  }

  async newSession() {
    const token = b64url(crypto.getRandomValues(new Uint8Array(32)));
    await this.storage.put('session:' + hex(await sha256(token)), { expires: new Date(Date.now() + SESSION_HOURS * 3600e3).toISOString() });
    return token;
  }
}

// ======================================================================= public endpoints
// Rate limits. Cloudflare's Rate Limiting binding counts across all isolates in a location (free plan, periods of
// 10 or 60 s); the small per-isolate limiter below works if a binding is missing.
async function over(env, binding, key, max, windowMs) {
  const rl = env[binding];
  if (rl) { try { const { success } = await rl.limit({ key }); if (!success) return true; } catch { /* fail open to the local limiter */ } }
  return limited(key, max, windowMs);
}
const hits = new Map();
function limited(key, max, windowMs) {
  const t = Date.now(); const e = hits.get(key);
  if (!e || t - e.start > windowMs) { hits.set(key, { start: t, n: 1 }); if (hits.size > 5000) hits.clear(); return false; }
  return ++e.n > max;
}

async function update(url, env) {
  const channel = url.searchParams.get('channel') === 'stable' ? 'stable' : 'beta';
  const r = await env.DB.prepare("SELECT manifest, signature FROM releases WHERE manifest IS NOT NULL AND (channel = ?1 OR (?1 = 'beta' AND channel = 'stable')) ORDER BY published DESC LIMIT 1").bind(channel).first();
  // The manifest is signed with the release key when it is published; the app checks it before using anything in it.
  return json({ ok: true, manifest: r?.manifest ?? null, signature: r?.signature ?? null }, 200, { 'cache-control': 'public, max-age=300' });
}

// ======================================================================= admin console
function cookie(request, name) {
  const m = (request.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? m[1] : null;
}
const sessionCookie = (token, maxAge) => `tk_admin=${token}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

async function adminApi(request, env, url) {
  // CSRF: same-origin fetches only (SameSite=Strict cookie + custom header + Origin check).
  if (request.method !== 'POST' || request.headers.get('x-tk-admin') !== '1' || request.headers.get('origin') !== url.origin) return err('Forbidden', 403);
  if (await over(env, 'RL_ADMIN', 'admin:' + (request.headers.get('cf-connecting-ip') || '?'), 120, 60e3)) return err('Too many requests', 429);
  const rpId = url.hostname, origin = url.origin;
  const session = cookie(request, 'tk_admin');
  const op = url.pathname.slice('/admin/api/'.length);
  const a = (await readJson(request)) || {};

  // --- sign-in flow (no session needed)
  if (op === 'status') { const s = await callVault(env, 'status'); const { valid } = await callVault(env, 'session', { session }); return json({ ok: true, ...s, signedIn: valid }); }
  if (op === 'register/options') return json(await callVault(env, 'registerOptions', { rpId, session, code: a.code, name: a.name }));
  if (op === 'register/verify') {
    const r = await callVault(env, 'registerVerify', { rpId, origin, session, code: a.code, name: a.name, credential: a.credential, assertion: a.assertion });
    await log(env, 'admin-passkey-added', String(a.name || '').slice(0, 60));
    return json({ ok: true }, 200, r.session ? { 'set-cookie': sessionCookie(r.session, SESSION_HOURS * 3600) } : {});
  }
  if (op === 'login/options') return json(await callVault(env, 'loginOptions', { rpId }));
  if (op === 'login/verify') {
    const r = await callVault(env, 'loginVerify', { rpId, origin, credential: a.credential });
    await log(env, 'admin-login', null);
    return json({ ok: true }, 200, { 'set-cookie': sessionCookie(r.session, SESSION_HOURS * 3600) });
  }
  if (op === 'logout') { await callVault(env, 'logout', { session }); return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0) }); }

  // --- everything below needs a signed-in publisher
  const { valid } = await callVault(env, 'session', { session });
  if (!valid) return err('Signed out', 401);

  switch (op) {

    case 'events': {
      const { results } = await env.DB.prepare('SELECT at, kind, detail FROM events ORDER BY id DESC LIMIT 200').all();
      return json({ ok: true, events: results });
    }
    case 'stepup/options': {
      const p = a.payload || {};
      const purpose = ['release', 'passkey-add', 'passkey-remove'].includes(a.purpose) ? a.purpose : null;
      if (!purpose) return err('Unknown action');
      const digest = await digestOf(purpose === 'release' ? releaseSource(p) : purpose === 'passkey-add' ? String(p.challenge || '') : String(p.id || ''));
      return json(await callVault(env, 'stepupOptions', { session, rpId, purpose, digest }));
    }
    case 'logout-all': { const r = await callVault(env, 'logoutAll', { session }); await log(env, 'admin-logout-all', String(r.ended)); return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0) }); }
    case 'passkeys/remove': { await callVault(env, 'removePasskey', { session, id: String(a.id || ''), assertion: a.assertion, rpId, origin }); await log(env, 'admin-passkey-removed', null); return json({ ok: true }); }
    case 'passkeys': return json({ ok: true, ...(await callVault(env, 'passkeys', { session })) });
    case 'keys': return json({ ok: true, ...(await callVault(env, 'keys')) });
    case 'release': {
      const r = a.release || {};
      if (!/^\d+\.\d+\.\d+$/.test(r.version || '') || !/^https:\/\/[^\s]+$/.test(r.url || '') || !/^[0-9A-Fa-f]{64}$/.test(r.sha256 || '')) return err('Version must be like 1.2.3, the URL must start with https:// and SHA-256 must be 64 hex characters');
      const manifest = JSON.stringify({ product: 'TriageKit', version: r.version, channel: r.channel === 'stable' ? 'stable' : 'beta', url: r.url, sha256: r.sha256.toUpperCase(),
        size: Math.max(0, r.size | 0), notes: String(r.notes || '').slice(0, 4000), published: now() });
      const { signature } = await callVault(env, 'signRelease', { session, text: manifest, assertion: a.assertion, digest: await digestOf(releaseSource(r)), rpId, origin });
      await env.DB.prepare('INSERT OR REPLACE INTO releases(version, channel, url, sha256, size, notes, manifest, signature) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)')
        .bind(r.version, r.channel === 'stable' ? 'stable' : 'beta', r.url, r.sha256.toUpperCase(), r.size | 0, String(r.notes || '').slice(0, 4000), manifest, signature).run();
      await log(env, 'release', r.version);
      return json({ ok: true });
    }
    case 'releases': {
      const { results } = await env.DB.prepare('SELECT version, channel, url, sha256, size, published FROM releases ORDER BY published DESC LIMIT 50').all();
      return json({ ok: true, releases: results });
    }
    default: return err('Not found', 404);
  }
}

// What the publisher confirms with a passkey touch: the exact fields that will be signed.
const releaseSource = (r) => JSON.stringify({ version: String(r.version || ''), channel: r.channel === 'stable' ? 'stable' : 'beta', url: String(r.url || ''),
  sha256: String(r.sha256 || '').toUpperCase(), size: r.size | 0, notes: String(r.notes || '') });
const digestOf = async (text) => hex(await sha256(text));

function asset(body, type) { return new Response(body, { headers: { 'content-type': type, 'cache-control': 'no-cache', ...SEC_HEADERS } }); }

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      const p = url.pathname;
      if (p === '/' && request.method === 'GET') return asset(ROOT_HTML, 'text/html; charset=utf-8');
      if (p === '/v1/health') return json({ ok: true, service: 'triagekit-api', time: now() });
      if (p === '/v1/keys' && request.method === 'GET') { const k = await callVault(env, 'keys'); return json({ ok: true, release: k.release }); }
      // TriageKit is free since 0.14: there are no licences any more. Older apps get a clear answer.
      if (p === '/v1/licence/check') return err('TriageKit is free for everyone now. Please update to the latest version.', 410);
      if (p === '/v1/update' && request.method === 'GET') return await update(url, env);
      if (p === '/admin' || p === '/admin/') return asset(ADMIN_HTML, 'text/html; charset=utf-8');
      if (p === '/admin/app.js') return asset(ADMIN_JS, 'text/javascript; charset=utf-8');
      if (p === '/admin/app.css') return asset(ADMIN_CSS, 'text/css; charset=utf-8');
      if (p.startsWith('/admin/api/')) return await adminApi(request, env, url);
      return err('Not found', 404);
    } catch (e) {
      if (e.status && e.status < 500) return err(e.message, e.status);
      return err('Server error', 500);
    }
  },
};

// ======================================================================= static pages
const ROOT_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TriageKit API</title><link rel="stylesheet" href="/admin/app.css"></head>
<body><main class="center"><div class="card narrow"><div class="brand"><span class="dot"></span>TriageKit</div><h1>Update service</h1><p class="muted">This service publishes signed update announcements for the TriageKit app. There is nothing to see here.</p><p class="muted small">Status: online</p></div></main></body></html>`;

const ADMIN_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>TriageKit Admin</title><link rel="stylesheet" href="/admin/app.css"></head>
<body><div id="app"><main class="center"><div class="card narrow"><p class="muted">Loading…</p></div></main></div><script src="/admin/app.js"></script></body></html>`;

const ADMIN_CSS = `:root{--bg:#070b12;--panel:#0d1420;--line:#1c2635;--text:#e6edf6;--muted:#8796aa;--accent:#2dd4bf;--accent2:#38bdf8;--danger:#f87171;--warn:#fbbf24;color-scheme:dark}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(1200px 600px at 80% -10%,#0f2a33 0,transparent 60%),var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh}
.center{min-height:100vh;display:grid;place-items:center;padding:24px}.card{background:linear-gradient(180deg,#0f1724,#0b111b);border:1px solid var(--line);border-radius:16px;padding:24px}.narrow{width:100%;max-width:420px}
h1{font-size:20px;margin:8px 0 4px}h2{font-size:15px;margin:0 0 12px}.muted{color:var(--muted)}.small{font-size:12px}.brand{display:flex;gap:8px;align-items:center;font-weight:600;letter-spacing:.02em}.dot{width:10px;height:10px;border-radius:50%;background:var(--accent);box-shadow:0 0 12px var(--accent)}
input,select,textarea{width:100%;background:#0a1019;border:1px solid var(--line);color:var(--text);border-radius:10px;padding:9px 11px;font:inherit}textarea{font-family:ui-monospace,Consolas,monospace;font-size:12px}label{display:block;font-size:12px;color:var(--muted);margin:10px 0 4px}
button{background:var(--accent);color:#04201c;border:0;border-radius:10px;padding:9px 14px;font-weight:600;cursor:pointer;font:inherit;font-weight:600}button.ghost{background:transparent;color:var(--text);border:1px solid var(--line)}button.danger{background:transparent;color:var(--danger);border:1px solid #4a2020}button:disabled{opacity:.5;cursor:default}button.sm{padding:5px 9px;font-size:12px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.grow{flex:1}.top{display:flex;justify-content:space-between;align-items:center;padding:16px 24px;border-bottom:1px solid var(--line)}.wrap{max-width:1200px;margin:0 auto;padding:24px;display:grid;gap:16px}
.grid2{display:grid;grid-template-columns:360px 1fr;gap:16px}@media(max-width:900px){.grid2{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:600}td.mono,.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;border:1px solid var(--line)}.ok{color:var(--accent);border-color:#134e48}.bad{color:var(--danger);border-color:#4a2020}.warn{color:var(--warn);border-color:#4a3a10}
.msg{margin-top:12px;padding:10px 12px;border-radius:10px;font-size:13px}.msg.err{background:#2a1212;color:#fecaca}.msg.okm{background:#0d2a26;color:#a7f3d0}.tabs{display:flex;gap:6px}.tabs button{background:transparent;color:var(--muted);border:1px solid transparent}.tabs button.on{color:var(--text);border-color:var(--line);background:#0f1724}`;

const ADMIN_JS = String.raw`(() => {
  const $ = (h) => { const t = document.createElement('template'); t.innerHTML = h.trim(); return t.content.firstElementChild; };
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const app = document.getElementById('app');
  const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
  async function api(op, body) {
    const r = await fetch('/admin/api/' + op, { method: 'POST', headers: { 'content-type': 'application/json', 'x-tk-admin': '1' }, body: JSON.stringify(body || {}), credentials: 'same-origin' });
    const d = await r.json().catch(() => ({ ok: false, error: 'Bad response' }));
    if (r.status === 401 && op !== 'status' && !op.startsWith('login') && !op.startsWith('register')) { render(); throw new Error('Signed out'); }
    if (!r.ok || d.ok === false) throw new Error(d.error || ('Error ' + r.status));
    return d;
  }
  const fmt = (s) => s ? new Date(s).toLocaleString() : 'n/a';
  const day = (s) => s ? new Date(s).toLocaleDateString() : 'n/a';
  function msg(el, text, ok) { el.innerHTML = text ? '<div class="msg ' + (ok ? 'okm' : 'err') + '">' + esc(text) + '</div>' : ''; }

  async function createPasskey(code, name, signedIn) {
    const o = await api('register/options', { code, name });
    // Adding a second passkey: first confirm with an existing one (bound to this registration).
    const assertion = signedIn ? await stepUp('passkey-add', { challenge: o.challenge }) : undefined;
    const cred = await navigator.credentials.create({ publicKey: { ...o, challenge: unb64u(o.challenge), user: { ...o.user, id: unb64u(o.user.id) }, excludeCredentials: o.excludeCredentials.map((c) => ({ ...c, id: unb64u(c.id) })) } });
    const r = cred.response;
    await api('register/verify', { code, name, assertion, credential: { id: cred.id, clientDataJSON: b64u(r.clientDataJSON), authenticatorData: b64u(r.getAuthenticatorData()), publicKey: b64u(r.getPublicKey()), publicKeyAlgorithm: r.getPublicKeyAlgorithm() } });
  }
  // A fresh passkey touch for one specific action (publish an update, change passkeys).
  async function stepUp(purpose, payload) {
    const o = await api('stepup/options', { purpose, payload });
    const cred = await navigator.credentials.get({ publicKey: { ...o, challenge: unb64u(o.challenge), allowCredentials: o.allowCredentials.map((c) => ({ ...c, id: unb64u(c.id) })) } });
    const r = cred.response;
    return { id: cred.id, clientDataJSON: b64u(r.clientDataJSON), authenticatorData: b64u(r.authenticatorData), signature: b64u(r.signature) };
  }
  async function signIn() {
    const o = await api('login/options');
    const cred = await navigator.credentials.get({ publicKey: { ...o, challenge: unb64u(o.challenge), allowCredentials: o.allowCredentials.map((c) => ({ ...c, id: unb64u(c.id) })) } });
    const r = cred.response;
    await api('login/verify', { credential: { id: cred.id, clientDataJSON: b64u(r.clientDataJSON), authenticatorData: b64u(r.authenticatorData), signature: b64u(r.signature) } });
  }

  async function render() {
    let s; try { s = await api('status'); } catch (e) { app.replaceChildren($('<main class="center"><div class="card narrow"><p class="muted">Service unavailable: ' + esc(e.message) + '</p></div></main>')); return; }
    if (s.signedIn) return console_();
    if (!s.hasPasskeys) {
      const el = $('<main class="center"><div class="card narrow"><div class="brand"><span class="dot"></span>TriageKit Admin</div><h1>First-time setup</h1><p class="muted">Enter the one-time setup code, then create a passkey with Windows Hello, your phone or a security key. After this, the code stops working.</p><label>Setup code</label><input id="code" autocomplete="off" spellcheck="false"><label>Name for this passkey</label><input id="name" value="My PC"><div class="row" style="margin-top:16px"><button id="go">Create passkey</button></div><div id="m"></div></div></main>');
      el.querySelector('#go').onclick = async (ev) => { ev.target.disabled = true; try { await createPasskey(el.querySelector('#code').value, el.querySelector('#name').value); render(); } catch (e) { msg(el.querySelector('#m'), e.message); ev.target.disabled = false; } };
      return app.replaceChildren(el);
    }
    const el = $('<main class="center"><div class="card narrow"><div class="brand"><span class="dot"></span>TriageKit Admin</div><h1>Sign in</h1><p class="muted">Use your passkey (Windows Hello, phone or security key).</p><div class="row" style="margin-top:16px"><button id="go">Sign in with passkey</button></div><div id="m"></div></div></main>');
    el.querySelector('#go').onclick = async (ev) => { ev.target.disabled = true; try { await signIn(); render(); } catch (e) { msg(el.querySelector('#m'), e.name === 'NotAllowedError' ? 'Cancelled.' : e.message); ev.target.disabled = false; } };
    app.replaceChildren(el);
  }

  let tab = 'releases';
  async function console_() {
    const el = $('<div><div class="top"><div class="brand"><span class="dot"></span>TriageKit Admin</div><div class="row"><div class="tabs"><button data-t="events">Activity</button><button data-t="releases">Releases</button><button data-t="security">Security</button></div><button class="ghost sm" id="out">Sign out</button></div></div><div class="wrap" id="body"></div></div>');
    el.querySelectorAll('[data-t]').forEach((b) => { b.classList.toggle('on', b.dataset.t === tab); b.onclick = () => { tab = b.dataset.t; console_(); }; });
    el.querySelector('#out').onclick = async () => { await api('logout').catch(() => {}); render(); };
    app.replaceChildren(el);
    const body = el.querySelector('#body');
    if (tab === 'events') return events(body);
    if (tab === 'releases') return releases(body);
    return security(body);
  }

  async function events(body) {
    const el = $('<div class="card"><h2>Recent activity</h2><div id="l" class="muted">Loading…</div></div>');
    body.replaceChildren(el);
    const { events } = await api('events');
    const t = $('<table><thead><tr><th>When</th><th>Event</th><th>Detail</th></tr></thead><tbody></tbody></table>');
    for (const e of events) t.tBodies[0].append($('<tr><td>' + fmt(e.at.endsWith('Z') ? e.at : e.at + 'Z') + '</td><td>' + esc(e.kind) + '</td><td>' + esc(e.detail || '') + '</td></tr>'));
    el.querySelector('#l').replaceChildren(events.length ? t : document.createTextNode('Nothing yet.'));
  }

  async function releases(body) {
    const el = $('<div class="grid2"><div class="card"><h2>Publish an update</h2><p class="muted small">Apps download it from the URL, check the SHA-256 and only install it if this signed announcement matches.</p>'
      + '<div class="row"><div class="grow"><label>Version</label><input id="version" placeholder="0.10.0"></div><div style="width:120px"><label>Channel</label><select id="channel"><option>beta</option><option>stable</option></select></div></div>'
      + '<label>Download URL (https, .zip with TriageKit.exe or the .exe)</label><input id="url" placeholder="https://github.com/…/TriageKit-0.10.0-exe.zip">'
      + '<label>SHA-256 of that file</label><input id="sha" class="mono" placeholder="64 hex characters">'
      + '<label>Size in bytes</label><input id="size" type="number" min="0">'
      + '<label>Release notes</label><textarea id="notes" rows="4"></textarea>'
      + '<div class="row" style="margin-top:14px"><button id="pub">Sign and publish</button></div><div id="m"></div></div>'
      + '<div class="card"><h2>Published</h2><div id="list" class="muted">Loading…</div></div></div>');
    body.replaceChildren(el);
    const v = (id) => el.querySelector('#' + id).value.trim();
    el.querySelector('#pub').onclick = async (ev) => {
      if (!confirm('Publish ' + v('version') + ' to every ' + v('channel') + ' user?')) return;
      ev.target.disabled = true;
      try { const release = { version: v('version'), channel: v('channel'), url: v('url'), sha256: v('sha'), size: +v('size') || 0, notes: v('notes') }; await api('release', { release, assertion: await stepUp('release', release) }); msg(el.querySelector('#m'), 'Published.', true); load(); }
      catch (e) { msg(el.querySelector('#m'), e.message); }
      ev.target.disabled = false;
    };
    async function load() {
      const { releases } = await api('releases');
      const t = $('<table><thead><tr><th>Version</th><th>Channel</th><th>Published</th><th>SHA-256</th></tr></thead><tbody></tbody></table>');
      for (const r of releases) t.tBodies[0].append($('<tr><td>' + esc(r.version) + '</td><td>' + esc(r.channel) + '</td><td>' + fmt(r.published.endsWith('Z') ? r.published : r.published + 'Z') + '</td><td class="mono">' + esc(r.sha256.slice(0, 16)) + '…</td></tr>'));
      el.querySelector('#list').replaceChildren(releases.length ? t : document.createTextNode('Nothing published yet.'));
    }
    load();
  }

  async function security(body) {
    const el = $('<div class="grid2"><div class="card"><h2>Passkeys</h2><div id="pk" class="muted">Loading…</div><label>Add another passkey (e.g. your phone as a backup)</label><input id="name" placeholder="Phone"><div class="row" style="margin-top:10px"><button id="add">Add passkey</button></div><div id="m"></div></div>'
      + '<div class="card"><h2>Signing keys</h2><p class="muted small">Generated inside Cloudflare and never exported. The app has these public keys built in.</p><textarea id="keys" rows="12" readonly></textarea></div></div>');
    body.replaceChildren(el);
    const { passkeys } = await api('passkeys');
    const pk = el.querySelector('#pk'); pk.replaceChildren();
    for (const p of passkeys) {
      const row = $('<div class="row" style="justify-content:space-between;margin:4px 0"><div>' + esc(p.name) + ' <span class="small muted">added ' + day(p.created) + (p.lastUsed ? ', last used ' + fmt(p.lastUsed) : '') + '</span></div><button class="sm danger">Remove</button></div>');
      row.querySelector('button').onclick = async () => { if (!confirm('Remove passkey "' + p.name + '"?')) return; try { const assertion = await stepUp('passkey-remove', { id: p.id }); await api('passkeys/remove', { id: p.id, assertion }); security(body); } catch (e) { msg(el.querySelector('#m'), e.message); } };
      pk.append(row);
    }
    const out = $('<div class="row" style="margin-top:18px"><button class="ghost sm">Sign out everywhere</button><span class="small muted">Ends every admin session, including this one.</span></div>');
    out.querySelector('button').onclick = async () => { await api('logout-all').catch(() => {}); render(); };
    el.querySelector('#pk').after(out);
    el.querySelector('#add').onclick = async () => { try { await createPasskey(null, el.querySelector('#name').value || 'Passkey', true); security(body); } catch (e) { msg(el.querySelector('#m'), e.message); } };
    const k = await api('keys');
    el.querySelector('#keys').value = 'Release key:\n' + k.release;
  }

  render();
})();`;
