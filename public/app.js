'use strict';
/*
 * Kavach client — all cryptography happens here, in the browser (Web Crypto API).
 *
 *  Identity      : none. Each contact gets fresh P-256 keys + a fresh random mailbox.
 *  Pairing       : (a) one-time rotating QR/link, (b) shared room code (PBKDF2-hardened),
 *                  both followed by a 6-emoji safety code check.
 *  Messages      : AES-256-GCM, new key per message (HMAC hash-chain ratchet => forward secrecy),
 *                  header bound as AAD, plaintext padded to fixed buckets (hides length).
 *  Re-keying     : fresh ECDH every 40 messages (post-compromise recovery).
 *  Files / voice : chunked through the same ratchet; images re-encoded (EXIF/GPS stripped);
 *                  stored on-device in IndexedDB encrypted with the vault key.
 *  At rest       : state encrypted with a random data key, wrapped by PIN, recovery key,
 *                  and (optionally) a duress PIN that opens a decoy vault.
 *  Calls         : WebRTC (DTLS-SRTP); signalling travels inside the E2EE channel.
 */
(() => {
const $ = (id) => document.getElementById(id);
const te = new TextEncoder(), td = new TextDecoder();
const S = crypto.subtle;
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
const b64 = (buf) => { const a = new Uint8Array(buf); let s = ''; for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const unb64 = (s) => { s = String(s).replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let k = 0; for (const x of a) { o.set(x, k); k += x.length; } return o; };
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const now = () => Date.now();
const hhmm = (t) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const isId = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= (max || 32) && /^[A-Za-z0-9_-]+$/.test(s);
const fmtSize = (n) => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(0) + ' KB' : (n / 1048576).toFixed(1) + ' MB';

if (!window.isSecureContext || !S) {
  document.body.innerHTML = '<p class="screen">Kavach needs HTTPS (secure context) for encryption. Open it via https:// or http://localhost.</p>';
  return;
}

/* =================== crypto primitives =================== */
const EC = { name: 'ECDH', namedCurve: 'P-256' };
const genKP = () => S.generateKey(EC, true, ['deriveBits']);
const pubRaw = async (k) => b64(await S.exportKey('raw', k));
const privJwk = (k) => S.exportKey('jwk', k);
const impPriv = (j) => S.importKey('jwk', j, EC, false, ['deriveBits']);
const impPub = (s) => S.importKey('raw', unb64(s), EC, false, []);
async function dh(priv, pub) { return new Uint8Array(await S.deriveBits({ name: 'ECDH', public: await impPub(pub) }, priv, 256)); }
async function hkdf(ikm, salt, info, len) {
  const k = await S.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await S.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(info) }, k, len * 8));
}
async function hmac1(key, byte) {
  const k = await S.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await S.sign('HMAC', k, new Uint8Array([byte])));
}
const sha = async (d) => new Uint8Array(await S.digest('SHA-256', d));
async function session(shared, myPub, theirPub, prevRoot) {
  const lo = myPub < theirPub;
  const salt = await sha(cat(prevRoot || te.encode('kavach-root-v1'), te.encode(lo ? myPub + '|' + theirPub : theirPub + '|' + myPub)));
  const o = await hkdf(shared, salt, 'kavach-session-v1', 96);
  shared.fill(0);
  return { root: o.slice(0, 32), send: lo ? o.slice(32, 64) : o.slice(64, 96), recv: lo ? o.slice(64, 96) : o.slice(32, 64) };
}
const EMO = '🐶🐱🦊🐼🐨🐯🦁🐮🐷🐸🐵🐔🐧🐦🦉🦄🐝🦋🐢🐙🐬🐳🦈🐊🦒🐘🦔🌵🌲🌻🌙⭐🔥🌈❄️🍎🍉🍇🍓🍒🥭🍍🥥🌽🍕🍩🎂☕🎸🎺🚲🚀⚓⏰🔑💡🎈🎁📚✏️🧲🧭🎯🪁'.match(/(\p{Extended_Pictographic}️?)/gu);
async function sasOf(root) {
  const h = await sha(cat(te.encode('kavach-sas-v1'), root));
  let e = '', d = '';
  for (let i = 0; i < 6; i++) e += EMO[h[i] % EMO.length];
  for (let i = 6; i < 16; i++) d += (h[i] % 10);
  return { emoji: e, digits: d.slice(0, 5) + ' ' + d.slice(5) };
}
const BUCKETS = [256, 1024, 4096, 16384, 40960];
function pad(str) {
  const b = te.encode(str);
  const L = BUCKETS.find((x) => x > b.length);
  if (!L) throw new Error('too-big');
  const o = new Uint8Array(L); o.set(b); o[b.length] = 0x80; return o;
}
function unpad(u) { let i = u.length - 1; while (i >= 0 && u[i] === 0) i--; if (u[i] !== 0x80) throw new Error('pad'); return td.decode(u.slice(0, i)); }

/* ---------- ratchet ---------- */
function newContact(sess) {
  return {
    id: b64(rnd(9)), name: '', ep: 0, root: b64(sess.root), sentInEp: 0,
    ch: { 0: { s: b64(sess.send), sn: 0, r: b64(sess.recv), rn: 0, sk: {} } },
    msgs: [], timer: 0, verified: false, unread: 0, created: now(), state: 'pending',
    rid: '', sid: '', theirSid: '', sas: null, rk: null,
  };
}
function installEpoch(c, e, sess) {
  c.ch[e] = { s: b64(sess.send), sn: 0, r: b64(sess.recv), rn: 0, sk: {} };
  c.ep = e; c.root = b64(sess.root); c.sentInEp = 0;
  for (const k of Object.keys(c.ch)) if (+k < e - 1) delete c.ch[k];
}
async function seal(c, obj) {
  const ch = c.ch[c.ep];
  const ck = unb64(ch.s);
  const mk = await hmac1(ck, 1);
  ch.s = b64(await hmac1(ck, 2));
  const h = { e: c.ep, n: ch.sn++ };
  const iv = rnd(12);
  const key = await S.importKey('raw', mk, 'AES-GCM', false, ['encrypt']);
  const ct = await S.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(JSON.stringify(h)) }, key, pad(JSON.stringify(obj)));
  mk.fill(0);
  c.sentInEp++;
  return { h, iv: b64(iv), c: b64(ct) };
}
async function open(c, env) {
  const h = env && env.h;
  if (!h || !Number.isInteger(h.e) || !Number.isInteger(h.n) || h.n < 0) throw new Error('hdr');
  const ch = c.ch[h.e];
  if (!ch) throw new Error('epoch');
  let mk, rk = ch.r, rn = ch.rn;
  const sk = Object.assign({}, ch.sk);
  if (h.n < rn) {
    if (!sk[h.n]) throw new Error('replay');
    mk = unb64(sk[h.n]); delete sk[h.n];
  } else {
    if (h.n - rn > 1000) throw new Error('gap');
    let ck = unb64(rk);
    while (rn < h.n) { sk[rn] = b64(await hmac1(ck, 1)); ck = await hmac1(ck, 2); rn++; }
    mk = await hmac1(ck, 1); ck = await hmac1(ck, 2); rn++; rk = b64(ck);
    const keys = Object.keys(sk); if (keys.length > 300) for (const k of keys.slice(0, keys.length - 300)) delete sk[k];
  }
  const key = await S.importKey('raw', mk, 'AES-GCM', false, ['decrypt']);
  const pt = new Uint8Array(await S.decrypt({ name: 'AES-GCM', iv: unb64(env.iv), additionalData: te.encode(JSON.stringify({ e: h.e, n: h.n })) }, key, unb64(env.c)));
  ch.r = rk; ch.rn = rn; ch.sk = sk;
  return JSON.parse(unpad(pt));
}

/* =================== themes (32) =================== */
// name, bg, panel, panel2, text, muted, border, accent, bubbleIn, bubbleOut, bubbleOutText, dark
const THEMES = [
['Midnight','#0e1320','#151b2b','#1c2438','#e8ecf5','#8a93a8','#243049','#5b8cff','#1c2438','#3d6cf2','#ffffff',1],
['Daylight','#f4f6fb','#ffffff','#eef1f7','#151a24','#6b7385','#e2e6ee','#3a6df0','#ffffff','#3a6df0','#ffffff',0],
['AMOLED Black','#000000','#0a0a0a','#141414','#f2f2f2','#8a8a8a','#1f1f1f','#00d0a0','#161616','#00a37e','#ffffff',1],
['Ocean','#e6f3f7','#ffffff','#d9eef4','#0d2a33','#5a7a85','#cbe3ea','#0f8fb3','#ffffff','#0f8fb3','#ffffff',0],
['Forest','#10180f','#162214','#1e2d1b','#e3eedc','#8fa489','#263a22','#5fbf4a','#1e2d1b','#3f8f30','#ffffff',1],
['Sunset','#fff3ec','#ffffff','#ffe7da','#2b1710','#8a6a5d','#f5d9cb','#f0643c','#ffffff','#f0643c','#ffffff',0],
['Rose','#fff0f4','#ffffff','#ffe3eb','#2d0f19','#8c6070','#f6d1dd','#e0457b','#ffffff','#e0457b','#ffffff',0],
['Lavender','#f3f0ff','#ffffff','#e9e4ff','#1d1736','#706a8c','#ddd6f7','#7b5cf0','#ffffff','#7b5cf0','#ffffff',0],
['Mint','#eefaf5','#ffffff','#dff5ec','#0f2a20','#5d7f72','#cdeadf','#12a873','#ffffff','#12a873','#ffffff',0],
['Sepia','#f4ecdf','#fbf6ee','#efe4d2','#3b2f22','#86745f','#e3d5bf','#a0682c','#fbf6ee','#a0682c','#ffffff',0],
['Nord','#2e3440','#3b4252','#434c5e','#eceff4','#a3abba','#4c566a','#88c0d0','#434c5e','#5e81ac','#ffffff',1],
['Dracula','#1e1f29','#282a36','#323444','#f8f8f2','#9ea3c0','#3a3d50','#bd93f9','#323444','#7c5cc4','#ffffff',1],
['Solarized Light','#fdf6e3','#fffbee','#eee8d5','#073642','#657b83','#e4dcc4','#268bd2','#fffbee','#268bd2','#ffffff',0],
['Solarized Dark','#002b36','#073642','#0d404d','#eee8d5','#93a1a1','#12505f','#2aa198','#0d404d','#1f7f78','#ffffff',1],
['Monokai','#1f201b','#272822','#32332b','#f8f8f2','#a6a68f','#3c3d33','#a6e22e','#32332b','#6f9a1f','#ffffff',1],
['Cyberpunk','#0b0614','#140a24','#1d1033','#f5e9ff','#a08cc0','#2c1a4a','#ff2bd6','#1d1033','#b3129a','#ffffff',1],
['Coffee','#1b1410','#241b16','#2e231c','#efe2d6','#a8927f','#3a2d24','#c98a55','#2e231c','#8c5a33','#ffffff',1],
['Sakura','#fff5f8','#ffffff','#fde8ef','#2e1a22','#8f6f7b','#f5d8e2','#e8679a','#ffffff','#f8c4d6','#3a1a26',0],
['High Contrast','#000000','#000000','#111111','#ffffff','#e0e0e0','#ffffff','#ffd400','#111111','#ffd400','#000000',1],
['Terminal','#020a02','#051205','#0a1c0a','#7dff7d','#3fae3f','#0f2a0f','#33ff66','#0a1c0a','#0f3d14','#7dff7d',1],
['Desert','#f6efe3','#fffaf2','#efe3cf','#3a2b17','#8a775b','#e6d6bb','#d98e2b','#fffaf2','#d98e2b','#ffffff',0],
['Arctic','#eef4fa','#ffffff','#e3ecf6','#122233','#6b7d90','#d3e0ee','#2f80ed','#ffffff','#dbe9fb','#122233',0],
['Royal','#120b24','#1a1033','#24173f','#efe8ff','#9d8fc2','#2f2152','#f5c542','#24173f','#6c3fd1','#ffffff',1],
['Tiranga','#fff8ee','#ffffff','#ffefd9','#2a1b05','#8a7350','#f6e0bd','#ff8c1a','#ffffff','#138808','#ffffff',0],
['Slate','#1a1d23','#22262e','#2b3039','#e6e9ef','#959cab','#353b46','#7aa2f7','#2b3039','#3e5fa8','#ffffff',1],
['Paper Ink','#fafafa','#ffffff','#f0f0f0','#111111','#666666','#e5e5e5','#111111','#ffffff','#111111','#ffffff',0],
['Neon Ocean','#031626','#06223a','#0b2f4e','#e0f4ff','#7fa6c2','#123a5e','#00e5ff','#0b2f4e','#0077a8','#ffffff',1],
['Autumn','#fbf1e6','#ffffff','#f6e2cc','#311b0b','#8b6c50','#efd4b6','#c2410c','#ffffff','#c2410c','#ffffff',0],
['Matcha','#1a1f14','#222a1a','#2b3521','#eef3e2','#a0ab8c','#34402a','#b5d46a','#2b3521','#6f8f2d','#ffffff',1],
['Peach','#fff6f0','#ffffff','#ffece0','#33190d','#8f705f','#f6dccb','#ff8a65','#ffffff','#ffd2bf','#33190d',0],
['Galaxy','#090a1a','#11132b','#191c3d','#e9e9ff','#9496c4','#24275a','#8f7bff','#191c3d','#5b46e0','#ffffff',1],
['Ruby Night','#160a0d','#1f0f13','#2b151b','#fbe9ec','#b48b93','#3a1d24','#ff4d6d','#2b151b','#b8213f','#ffffff',1]];
const ACCENTS = ['#5b8cff','#3a6df0','#7b5cf0','#bd93f9','#e0457b','#ff2bd6','#ef4f5f','#f0643c','#ff8c1a','#f5c542','#a6e22e','#22b57a','#12a873','#00d0a0','#0f8fb3','#00e5ff','#8c5a33','#111111'];
const BRIGHT = ['#ffd400','#f5c542','#a6e22e','#00e5ff','#33ff66','#00d0a0','#88c0d0','#b5d46a'];
const hexRgba = (h, a) => { const n = parseInt(h.slice(1), 16); return `rgba(${n >> 16 & 255},${n >> 8 & 255},${n & 255},${a})`; };
function applyTheme() {
  const set = ST ? ST.set : {};
  const t = THEMES[+set.theme] || THEMES[0], st = document.documentElement.style;
  const acc = set.accent || t[7], on = BRIGHT.includes(acc) ? '#111111' : '#ffffff';
  const v = { '--bg': t[1], '--panel': t[2], '--panel2': t[3], '--text': t[4], '--muted': t[5], '--border': t[6], '--accent': acc, '--soft': hexRgba(acc, t[11] ? 0.18 : 0.12), '--on': on, '--bin': t[8], '--bout': set.accent ? acc : t[9], '--bouttx': set.accent ? on : t[10] };
  for (const k in v) st.setProperty(k, v[k]);
  document.documentElement.style.colorScheme = t[11] ? 'dark' : 'light';
  document.documentElement.classList.toggle('notoemoji', !!set.notoEmoji);
}

/* =================== encrypted vault (v3) =================== */
/*  meta = { v:3, salt, wp (PIN-wrapped DEK), rsalt, wr (recovery-wrapped DEK),
 *           dsalt, wd (duress-PIN-wrapped decoy DEK), iv, ct (real state), div, dct (decoy state) }
 *  wd/dct are random junk when no duress PIN is set => a forensic look cannot tell. */
const VKEY = 'kavach_vault_v1', FKEY = 'kavach_fails';
let vaultKey = null, ST = null, slot = 'real';
const defState = () => ({ v: 1, contacts: {}, set: { theme: 0, accent: '', receipts: true, typing: true, relayOnly: true, wipe10: true, autoLock: 1, relayKey: '', rotate: true, ssAlert: true, stripMeta: true, disguise: false, emojiVer: 15.1, notoEmoji: false, adult: false, gender: '', blurStrangers: false } });
async function pinKey(pin, salt) {
  const base = await S.importKey('raw', te.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return S.deriveKey({ name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
const readV = () => JSON.parse(localStorage.getItem(VKEY) || 'null');
const writeV = (v) => localStorage.setItem(VKEY, JSON.stringify(v));
const impDek = (raw) => S.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
async function wrapKey(k, dek) { const iv = rnd(12); return { iv: b64(iv), ct: b64(await S.encrypt({ name: 'AES-GCM', iv }, k, dek)) }; }
async function unwrapKey(k, w) { return new Uint8Array(await S.decrypt({ name: 'AES-GCM', iv: unb64(w.iv) }, k, unb64(w.ct))); }
const junkWrap = () => ({ iv: b64(rnd(12)), ct: b64(rnd(48)) });
const RA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function newRecoveryCode() { const r = rnd(24); let s = ''; for (let i = 0; i < 24; i++) { s += RA[r[i] % 32]; if (i % 4 === 3 && i < 23) s += '-'; } return s; }
const normRec = (s) => String(s).toUpperCase().replace(/[^A-Z0-9]/g, '').replace(/(.{4})(?=.)/g, '$1-');
const fixSet = () => {
  ST.set = Object.assign(defState().set, ST.set || {}); if (typeof ST.set.theme !== 'number') ST.set.theme = 0;
  ST.stk = ST.stk || { packs: [{ id: 'saved', name: '⭐ Saved', items: [] }], recent: [] };
  ST.emo = ST.emo || { recent: [], tone: '' };
};
async function encState(key, st) { const iv = rnd(12); return { iv: b64(iv), ct: b64(await S.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(st)))) }; }
async function decState(key, iv, ct) { return JSON.parse(td.decode(await S.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, key, unb64(ct)))); }
function addJunkDecoy(v) { v.dsalt = b64(rnd(16)); v.wd = junkWrap(); v.div = b64(rnd(12)); v.dct = b64(rnd(600 + (rnd(1)[0] * 4))); }

async function vaultCreate(pin, keepState) {
  const dek = rnd(32), salt = rnd(16), rsalt = rnd(16), code = newRecoveryCode();
  const v = { v: 3, salt: b64(salt), rsalt: b64(rsalt), wp: await wrapKey(await pinKey(pin, salt), dek), wr: await wrapKey(await pinKey(normRec(code), rsalt), dek) };
  addJunkDecoy(v); writeV(v);
  vaultKey = await impDek(dek); dek.fill(0); slot = 'real';
  ST = keepState || defState(); fixSet();
  await persist();
  return code;
}
async function vaultOpen(pin) {
  const v = readV();
  if (!v.wp) {                                              // legacy v1 -> upgrade
    const st = await decState(await pinKey(pin, unb64(v.salt)), v.iv, v.ct);
    return vaultCreate(pin, st);
  }
  if (!v.wd) { addJunkDecoy(v); writeV(v); }
  // derive both keys every time => same timing whether real or duress PIN
  const [kReal, kDuress] = await Promise.all([pinKey(pin, unb64(v.salt)), pinKey(pin, unb64(v.dsalt))]);
  try {
    const dek = await unwrapKey(kReal, v.wp);
    vaultKey = await impDek(dek); dek.fill(0); slot = 'real';
    ST = await decState(vaultKey, v.iv, v.ct); fixSet();
    return null;
  } catch (e) { /* not the real PIN */ }
  const dek = await unwrapKey(kDuress, v.wd);                // throws => wrong PIN
  vaultKey = await impDek(dek); dek.fill(0); slot = 'decoy';
  ST = await decState(vaultKey, v.div, v.dct); fixSet();
  if (ST.set.wipeReal) destroyReal();
  return null;
}
function destroyReal() {
  const v = readV();
  v.wp = junkWrap(); v.wr = junkWrap(); v.iv = b64(rnd(12)); v.ct = b64(rnd(unb64(v.ct).length));
  writeV(v);
  delete ST.set.wipeReal;
  idbClear().catch(() => {});
  persist();
}
async function changePin(oldPin, newPin) {
  const v = readV(), [sf, wf] = slot === 'real' ? ['salt', 'wp'] : ['dsalt', 'wd'];
  const dek = await unwrapKey(await pinKey(oldPin, unb64(v[sf])), v[wf]);
  const salt = rnd(16);
  v[sf] = b64(salt); v[wf] = await wrapKey(await pinKey(newPin, salt), dek); dek.fill(0);
  writeV(v);
}
async function recoverWith(code, newPin) {
  const v = readV();
  if (!v || !v.wr) throw new Error('no-recovery');
  const dek = await unwrapKey(await pinKey(normRec(code), unb64(v.rsalt)), v.wr);
  const salt = rnd(16);
  v.salt = b64(salt); v.wp = await wrapKey(await pinKey(newPin, salt), dek);
  writeV(v);
  vaultKey = await impDek(dek); dek.fill(0); slot = 'real';
  ST = await decState(vaultKey, v.iv, v.ct); fixSet();
}
async function rotateRecovery(pin) {
  const v = readV();
  if (slot !== 'real') { await pinKey(pin, unb64(v.dsalt)); return newRecoveryCode(); }   // decoy: looks identical, changes nothing
  const dek = await unwrapKey(await pinKey(pin, unb64(v.salt)), v.wp);
  const rsalt = rnd(16), code = newRecoveryCode();
  v.rsalt = b64(rsalt); v.wr = await wrapKey(await pinKey(normRec(code), rsalt), dek); dek.fill(0);
  writeV(v);
  return code;
}
async function setDuress(dpin, wipeReal) {
  if (slot !== 'real') return;                        // inside decoy: pretend success
  const v = readV();
  try { await unwrapKey(await pinKey(dpin, unb64(v.salt)), v.wp); throw new Error('same'); } catch (e) { if (e.message === 'same') throw e; }
  const ddek = rnd(32), dsalt = rnd(16);
  const decoy = defState(); decoy.set.theme = ST.set.theme; decoy.set.accent = ST.set.accent; decoy.set.disguise = ST.set.disguise; decoy.set.relayKey = ST.set.relayKey;
  if (wipeReal) decoy.set.wipeReal = true;
  const dk = await impDek(ddek);
  const enc = await encState(dk, decoy);
  v.dsalt = b64(dsalt); v.wd = await wrapKey(await pinKey(dpin, dsalt), ddek); v.div = enc.iv; v.dct = enc.ct; ddek.fill(0);
  writeV(v);
}
function clearDuress() { if (slot !== 'real') return; const v = readV(); addJunkDecoy(v); writeV(v); }
let saveT = null;
function save() { clearTimeout(saveT); saveT = setTimeout(persist, 200); }
async function persist() {
  if (!vaultKey || !ST) return;
  const v = readV() || {};
  const e = await encState(vaultKey, ST);
  if (slot === 'real') { v.iv = e.iv; v.ct = e.ct; } else { v.div = e.iv; v.dct = e.ct; }
  writeV(v);
}
function showRecovery(code, title) {
  modal(title || 'Your recovery key', `
    <p class="muted small">If you forget your PIN, this key resets it without losing chats. It is shown <b>only once</b>. Write it on paper and keep it offline — anyone with this key can open your vault.</p>
    <div class="reccode">${esc(code)}</div>
    <div class="row2"><button class="btn ghost" id="recCopy">Copy</button><button class="btn" id="recOk">I've saved it</button></div>`);
  $('recCopy').onclick = () => copy(code, 'Copied · clipboard clears in 60s');
  $('recOk').onclick = closeModal;
}
async function wipeAll() {
  try { localStorage.removeItem(VKEY); localStorage.removeItem(FKEY); localStorage.removeItem('kavach_w10'); localStorage.removeItem('kavach_dg'); } catch (e) {}
  try { await idbClear(); } catch (e) {}
  vaultKey = null; ST = null; location.replace(location.pathname);
}

/* =================== encrypted file store (IndexedDB) =================== */
let idbP = null;
function idb() {
  if (!idbP) idbP = new Promise((res, rej) => { const r = indexedDB.open('kavach_files', 1); r.onupgradeneeded = () => r.result.createObjectStore('f'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
  return idbP;
}
async function idbDo(mode, fn) { const db = await idb(); return new Promise((res, rej) => { const tx = db.transaction('f', mode); const r = fn(tx.objectStore('f')); tx.oncomplete = () => res(r && r.result); tx.onerror = () => rej(tx.error); }); }
async function filePut(fid, bytes) { const iv = rnd(12); const ct = await S.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(fid) }, vaultKey, bytes); await idbDo('readwrite', (s) => s.put({ iv, ct }, slot + ':' + fid)); }
async function fileGet(fid) { const r = await idbDo('readonly', (s) => s.get(slot + ':' + fid)); if (!r) return null; return new Uint8Array(await S.decrypt({ name: 'AES-GCM', iv: r.iv, additionalData: te.encode(fid) }, vaultKey, r.ct)); }
function fileDel(fid) { idbDo('readwrite', (s) => s.delete(slot + ':' + fid)).catch(() => {}); const u = blobUrls.get(fid); if (u) { URL.revokeObjectURL(u); blobUrls.delete(fid); } }
async function idbClear() { if (idbP) { const db = await idbP; db.close(); idbP = null; } await new Promise((res) => { const r = indexedDB.deleteDatabase('kavach_files'); r.onsuccess = r.onerror = r.onblocked = () => res(); }); }
const blobUrls = new Map(), blobLoading = new Set();
async function loadBlob(f) {
  if (blobLoading.has(f.fid)) return;
  blobLoading.add(f.fid);
  try { const d = await fileGet(f.fid); if (d) { blobUrls.set(f.fid, URL.createObjectURL(new Blob([d], { type: f.mime }))); } else f.st = 'gone'; }
  catch (e) { f.st = 'gone'; }
  blobLoading.delete(f.fid); renderChat();
}
function revokeAll() { for (const u of blobUrls.values()) URL.revokeObjectURL(u); blobUrls.clear(); }

/* =================== relay connection =================== */
let ws = null, wsUp = false, reqId = 0, backoff = 800, failStreak = 0;
const pending = new Map();
let outbox = [];
function setNet(on) { $('net').className = 'net' + (on ? ' on' : ''); $('net').title = on ? 'Connected to relay' : 'Offline — messages will queue'; }
function connect() {
  if (!vaultKey) return;
  const key = ST && ST.set.relayKey ? '?k=' + encodeURIComponent(ST.set.relayKey) : '';
  ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws' + key);
  ws._opened = false;
  ws.onopen = () => {
    wsUp = true; backoff = 800; setNet(true); ws._opened = true; failStreak = 0;
    for (const c of Object.values(ST.contacts)) if (c.rid) req({ op: 'sub', rid: c.rid }).catch((e) => { if (e === 'nobox' && c.state === 'ok') { c.state = 'gone'; render(); } });
    for (const inv of invites.values()) req({ op: 'sub', rid: inv.rid }).catch(() => {});
    for (const r of rooms.values()) req({ op: 'sub', rid: r.rid }).catch(() => {});
    const ob = outbox; outbox = [];
    for (const o of ob) put(o.sid, o.d).catch(() => {});
  };
  ws.onmessage = (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
    if (m.op === 'ok' || m.op === 'err') { const p = pending.get(m.r); if (p) { pending.delete(m.r); m.op === 'ok' ? p.res(m) : p.rej(m.e); } return; }
    if (m.op === 'msg') serial(() => onEnvelope(m));
    if (m.op === 'match') serial(() => onMatch(m));
  };
  ws.onclose = () => {
    wsUp = false; setNet(false);
    if (!ws._opened && ++failStreak === 3) { $('net').title = 'Relay refused — wrong or missing access key? (Settings → Security)'; toast('🔑 Relay refused connection — check the access key in Settings → Security'); }
    if (RS) { RS = null; if (!$('modal').classList.contains('hidden') && $('rsX')) { modalClose = null; closeModal(); } toast('Connection lost — search stopped'); }
    for (const p of pending.values()) p.rej('net');
    pending.clear();
    if (vaultKey) setTimeout(connect, backoff = Math.min(backoff * 2, 15000));
  };
  ws.onerror = () => {};
}
function req(m) {
  return new Promise((res, rej) => {
    if (!wsUp) return rej('net');
    m.r = ++reqId; pending.set(m.r, { res, rej });
    ws.send(JSON.stringify(m));
    setTimeout(() => { if (pending.has(m.r)) { pending.delete(m.r); rej('timeout'); } }, 15000);
  });
}
async function put(sid, d) {
  for (let attempt = 1; ; attempt++) {
    if (!wsUp) { outbox.push({ sid, d }); return; }
    try { await req({ op: 'put', sid, d }); return; }
    catch (e) {
      if (e === 'net' || e === 'timeout') { outbox.push({ sid, d }); return; }
      if ((e === 'rate' || e === 'qfull') && attempt < 12) { await sleep(Math.min(4000, 150 * attempt * attempt)); continue; }   // never drop on back-pressure
      throw e;
    }
  }
}
function ack(rid, id) { if (wsUp) ws.send(JSON.stringify({ op: 'ack', rid, id })); }
const sidOf = async (rid) => b64(await sha(te.encode('kavach-sid|' + rid)));

let chain = Promise.resolve();
function serial(fn) { const p = chain.then(fn, fn); chain = p.catch(() => {}); return p; }

/* =================== sending =================== */
async function sendNow(c, obj) {
  if (!c.theirSid) throw new Error('not-connected');
  const env = await seal(c, obj);
  save();
  await put(c.theirSid, JSON.stringify(env));
  if (c.sentInEp >= 40 && !c.rk) await startRekeyNow(c);
}
const sendInner = (c, obj) => serial(() => sendNow(c, obj));
async function startRekeyNow(c) {
  const kp = await genKP();
  c.rk = { priv: await privJwk(kp.privateKey), pub: await pubRaw(kp.publicKey) };
  await sendNow(c, { t: 'rk1', pub: c.rk.pub });
}

/* =================== QR invites (one-time, rotating, expiring) =================== */
const invites = new Map();
const INVITE_TTL = 10 * 60e3, ROTATE = 30e3;
let invTimer = null, invCur = null;
async function createInvite() {
  const kp = await genKP();
  const rid = b64(rnd(32));
  const ttl = ST.set.rotate ? ROTATE * 2 + 5e3 : INVITE_TTL;
  const r = await req({ op: 'new', rid, once: true, ttl });
  await req({ op: 'sub', rid });
  const inv = { rid, sid: r.sid, pub: await pubRaw(kp.publicKey), priv: kp.privateKey, exp: now() + ttl };
  invites.set(inv.sid, inv);
  return inv;
}
function inviteLink(inv) { return location.origin + location.pathname + '#i=' + inv.pub + '.' + inv.sid + '.' + Math.floor(inv.exp / 1000); }
function killInvite(inv) { invites.delete(inv.sid); inv.priv = null; req({ op: 'del', rid: inv.rid }).catch(() => {}); }
function killAllInvites() { clearInterval(invTimer); invTimer = null; invCur = null; for (const inv of [...invites.values()]) killInvite(inv); }
function parseInvite(s) {
  const m = String(s).match(/#i=([A-Za-z0-9_-]{80,100})\.([A-Za-z0-9_-]{43})\.(\d{9,11})/);
  return m ? { pub: m[1], sid: m[2], exp: +m[3] * 1000 } : null;
}
async function showInvite() {
  if (!wsUp) return toast('Relay offline — check connection');
  modal('Invite with one-time QR', `
    <p class="muted small center">Show this to the other person. No ID, number or name is inside — just a fresh key and a random mailbox. Single-use.</p>
    <div class="qrbox" id="qrBox"></div>
    <div class="bar"><i id="qrBar"></i></div>
    <p class="center small" id="qrInfo"></p>
    <div class="row2"><button class="btn ghost" id="qrCopy">Copy link</button><button class="btn ghost" id="qrNew">New QR now</button></div>
    <div class="opt"><div class="tx"><b>Auto-rotate every 30s</b><small>Old QR dies on the server. Off = one QR valid 10 min.</small></div><button class="sw ${ST.set.rotate ? 'on' : ''}" id="qrRot"></button></div>`, killAllInvites);
  let drawing = false;
  const draw = async () => {
    if (drawing) return; drawing = true;
    try {
      const prev = invCur;
      invCur = await createInvite();
      for (const inv of [...invites.values()]) if (inv !== invCur && inv !== prev) killInvite(inv);
      if (!ST.set.rotate && prev) killInvite(prev);
      const q = qrcode(0, 'M'); q.addData(inviteLink(invCur)); q.make();
      if ($('qrBox')) $('qrBox').innerHTML = q.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
      invCur.shownAt = now();
    } catch (e) { toast('Could not create invite'); }
    drawing = false;
  };
  const tick = () => {
    if (!invCur || !$('qrBar')) return;
    const life = ST.set.rotate ? ROTATE : INVITE_TTL;
    const left = Math.max(0, life - (now() - invCur.shownAt));
    $('qrBar').style.width = (100 * left / life) + '%';
    const s = Math.ceil(left / 1000);
    $('qrInfo').textContent = ST.set.rotate ? `New QR in ${s}s · each QR is unique & single-use` : `Expires in ${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')} · single-use`;
    if (left <= 0) { if (ST.set.rotate) draw(); else { $('qrBox').innerHTML = '<p class="expired">Expired — tap “New QR now”</p>'; killAllInvites(); } }
  };
  await draw();
  invTimer = setInterval(tick, 1000); tick();
  $('qrCopy').onclick = () => { if (invCur) copy(inviteLink(invCur), 'Link copied · clipboard clears in 60s'); };
  $('qrNew').onclick = async () => { if (!invTimer) invTimer = setInterval(tick, 1000); await draw(); tick(); };
  $('qrRot').onclick = function () { ST.set.rotate = !ST.set.rotate; save(); this.className = 'sw' + (ST.set.rotate ? ' on' : ''); draw().then(tick); };
}
async function onHello(inv, d) {
  if (!inv.priv) return;
  const env = JSON.parse(d);
  const sess = await session(await dh(inv.priv, env.p), inv.pub, env.p, null);
  const c = newContact(sess);
  const hello = await open(c, env);
  if (hello.t !== 'hello' || !isId(hello.sid, 64)) throw new Error('bad-hello');
  c.theirSid = hello.sid;
  c.sas = await sasOf(sess.root);
  killAllInvites();
  showRequest(c);
}
function showRequest(c) {
  modal('New contact request', `
    <div class="req"><p class="muted small center">Someone wants to connect. Ask them to read the emoji on <b>their</b> screen. Accept only if it matches exactly.</p>
    <div class="sas">${c.sas.emoji}</div><div class="digits">${c.sas.digits}</div>
    <input id="reqName" placeholder="Nickname (only stored on this device)" maxlength="40"></div>
    <div class="row2"><button class="btn danger" id="reqNo">Reject</button><button class="btn" id="reqYes">Match · Accept</button></div>`);
  $('reqNo').onclick = () => { closeModal(); toast('Rejected · keys discarded'); };
  $('reqYes').onclick = () => serial(async () => {
    const rid = b64(rnd(32));
    const r = await req({ op: 'new', rid });
    await req({ op: 'sub', rid });
    c.rid = rid; c.sid = r.sid; c.state = 'ok'; c.verified = true;
    c.name = ($('reqName').value || '').trim() || defaultName(c);
    ST.contacts[c.id] = c;
    await sendNow(c, { t: 'ok', sid: c.sid });
    sys(c, '🔐 Connected · end-to-end encrypted · verified');
    save(); closeModal(); openChat(c.id);
  }).catch(() => toast('Accept failed — try again'));
}
function defaultName(c) { return 'Contact ' + (c.sas ? c.sas.emoji.match(/\p{Extended_Pictographic}/gu).slice(0, 2).join('') : c.id.slice(0, 4)); }
let waitingFor = null;
function showWaiting(c) {
  modal('Waiting for approval', `<div class="req"><p class="muted small center">Read these emoji to the other person. They must see the <b>same</b> on their screen before accepting.</p>
    <div class="sas">${c.sas.emoji}</div><div class="digits">${c.sas.digits}</div><p class="small muted center">You can close this — chat opens automatically when accepted.</p></div>`);
  waitingFor = c.id;
}
async function join(link) {
  const p = parseInvite(link);
  if (!p) throw new Error('This is not a Kavach invite');
  if (p.exp < now()) throw new Error('Invite expired');
  const kp = await genKP();
  const myPub = await pubRaw(kp.publicKey);
  const sess = await session(await dh(kp.privateKey, p.pub), myPub, p.pub, null);
  const c = newContact(sess);
  c.sas = await sasOf(sess.root);
  const rid = b64(rnd(32));
  const r = await req({ op: 'new', rid });
  await req({ op: 'sub', rid });
  c.rid = rid; c.sid = r.sid; c.state = 'waiting'; c.name = defaultName(c);
  const env = await seal(c, { t: 'hello', sid: c.sid });
  env.p = myPub;
  try { await req({ op: 'put', sid: p.sid, d: JSON.stringify(env) }); }
  catch (e) { req({ op: 'del', rid }).catch(() => {}); throw new Error(e === 'used' ? 'Invite already used by someone' : e === 'nobox' ? 'Invite expired or deleted' : 'Network error'); }
  ST.contacts[c.id] = c; save();
  return c;
}
function showJoin(prefill) {
  modal('Join with QR / link', `
    <p class="muted small">Scan the other person's QR, or paste their one-time link.</p>
    <video id="scanV" class="hidden" playsinline muted></video>
    <div class="row2"><button class="btn ghost" id="scanBtn">📷 Scan QR</button></div>
    <p></p><input id="joinIn" placeholder="Paste invite link" value="${esc(prefill || '')}">
    <div class="row2"><button class="btn" id="joinGo">Connect</button></div>`, stopScan);
  $('scanBtn').onclick = startScan;
  $('joinGo').onclick = () => doJoin($('joinIn').value);
  if (prefill) doJoin(prefill);
}
async function doJoin(link) {
  stopScan();
  if (!wsUp) return toast('Relay offline');
  try {
    if ($('joinGo')) $('joinGo').disabled = true;
    const c = await serial(() => join(link));
    render(); showWaiting(c);
  } catch (e) { toast(e.message || 'Join failed'); if ($('joinGo')) $('joinGo').disabled = false; }
}
let scanStream = null, scanTimer = null;
async function startScan() {
  try {
    scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
    const v = $('scanV'); v.srcObject = scanStream; v.classList.remove('hidden'); await v.play();
    const cv = document.createElement('canvas'), cx = cv.getContext('2d', { willReadFrequently: true });
    scanTimer = setInterval(() => {
      if (!v.videoWidth) return;
      cv.width = v.videoWidth; cv.height = v.videoHeight; cx.drawImage(v, 0, 0);
      const r = jsQR(cx.getImageData(0, 0, cv.width, cv.height).data, cv.width, cv.height, { inversionAttempts: 'dontInvert' });
      if (r && parseInvite(r.data)) { $('joinIn').value = r.data; doJoin(r.data); }
    }, 250);
  } catch (e) { toast('Camera not available'); }
}
function stopScan() { clearInterval(scanTimer); scanTimer = null; if (scanStream) scanStream.getTracks().forEach((t) => t.stop()); scanStream = null; }

/* =================== room code pairing =================== */
/* Both people type the same secret words. Code -> PBKDF2 (300k) -> {mailbox id, AES key}.
 * Whoever arrives first hosts; the second joins. Then the normal emoji check protects
 * against anyone who guessed or overheard the code. */
const rooms = new Map();   // sid -> room
const ROOM_TTL = 10 * 60e3;
const SYL_C = 'bdfghjklmnprstvz', SYL_V = 'aeiou';
function newRoomCode() {
  const words = [];
  for (let w = 0; w < 3; w++) { let s = ''; for (let k = 0; k < 2; k++) { let x; do { x = rnd(1)[0]; } while (x >= 240); s += SYL_C[x % 16] + SYL_V[Math.floor(x / 16) % 5]; } words.push(s); }
  return words.join('-');
}
const normCode = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
async function roomKeys(code) {
  const base = await S.importKey('raw', te.encode('kavach-room-v1|' + normCode(code)), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await S.deriveBits({ name: 'PBKDF2', salt: te.encode('kavach-room-salt-v1'), iterations: 300000, hash: 'SHA-256' }, base, 512));
  return { rid: b64(bits.slice(0, 32)), key: await S.importKey('raw', bits.slice(32), 'AES-GCM', false, ['encrypt', 'decrypt']) };
}
async function kEnc(key, obj) { const iv = rnd(12); return JSON.stringify({ rm: 1, iv: b64(iv), c: b64(await S.encrypt({ name: 'AES-GCM', iv }, key, pad(JSON.stringify(obj)))) }); }
async function kDec(key, d) { const o = JSON.parse(d); return JSON.parse(unpad(new Uint8Array(await S.decrypt({ name: 'AES-GCM', iv: unb64(o.iv) }, key, unb64(o.c))))); }
async function enterRoom(code) {
  if (normCode(code).length < 8) throw new Error('Code too short');
  const { rid, key } = await roomKeys(code);
  const kp = await genKP(), myPub = await pubRaw(kp.publicKey);
  try {
    const r = await req({ op: 'new', rid, once: true, ttl: ROOM_TTL });
    await req({ op: 'sub', rid });
    rooms.set(r.sid, { role: 'host', rid, sid: r.sid, key, kp, myPub, exp: now() + ROOM_TTL });
    return 'host';
  } catch (e) { if (e !== 'exists') throw new Error('Network error'); }
  const sidX = await sidOf(rid);
  const myRid = b64(rnd(32));
  const r = await req({ op: 'new', rid: myRid });
  await req({ op: 'sub', rid: myRid });
  rooms.set(r.sid, { role: 'guest', rid: myRid, sid: r.sid, key, kp, myPub, exp: now() + ROOM_TTL });
  try { await req({ op: 'put', sid: sidX, d: await kEnc(key, { pub: myPub, sid: r.sid }) }); }
  catch (e) { killRoom(rooms.get(r.sid)); throw new Error(e === 'used' ? 'This code is already in use' : 'Code expired'); }
  return 'guest';
}
function killRoom(room, keepBox) { if (!room) return; rooms.delete(room.sid); room.kp = null; if (!keepBox) req({ op: 'del', rid: room.rid }).catch(() => {}); }
function killAllRooms() { for (const r of [...rooms.values()]) killRoom(r); }
async function onRoomMsg(room, d) {
  const o = await kDec(room.key, d);      // fails unless sender knows the code
  if (typeof o.pub !== 'string') return;
  const sess = await session(await dh(room.kp.privateKey, o.pub), room.myPub, o.pub, null);
  const c = newContact(sess);
  c.sas = await sasOf(sess.root);
  if (room.role === 'host') {
    if (!isId(o.sid, 64)) return;
    c.theirSid = o.sid;
    await put(o.sid, await kEnc(room.key, { pub: room.myPub }));
    killRoom(room);
    showRequest(c);
  } else {
    c.rid = room.rid; c.sid = room.sid; c.state = 'waiting'; c.name = defaultName(c);
    ST.contacts[c.id] = c; killRoom(room, true); save(); render();
    showWaiting(c);
  }
}
function showRoom() {
  if (!wsUp) return toast('Relay offline');
  modal('Connect with a secret code', `
    <p class="muted small">Both people enter the <b>same</b> code (say it in person or on a call). No QR, no link, no ID. Code works for 10 minutes, once.</p>
    <div class="row2"><button class="btn" id="rmNew">🎲 Create a code</button></div>
    <p></p><input id="rmIn" placeholder="or type the code, e.g. kari-mope-sutu" autocomplete="off" autocapitalize="none" spellcheck="false">
    <div class="row2"><button class="btn ghost" id="rmGo">Use this code</button></div>
    <div id="rmState" class="center"></div>`, killAllRooms);
  const go = async (code) => {
    $('rmGo').disabled = true; $('rmNew').disabled = true;
    $('rmState').innerHTML = '<p class="muted small">Securing code… (slow on purpose)</p>';
    try {
      const role = await enterRoom(code);
      if (!$('rmState')) return;
      $('rmState').innerHTML = role === 'host'
        ? `<div class="reccode">${esc(normCode(code))}</div><p class="muted small">Waiting for the other person to type this code… <span id="rmLeft"></span></p>`
        : '<p class="muted small">Found! Exchanging keys…</p>';
      if (role === 'host') { const t = setInterval(() => { const r = [...rooms.values()].find((x) => x.role === 'host'); if (!r || !$('rmLeft')) return clearInterval(t); const s = Math.max(0, Math.round((r.exp - now()) / 1000)); $('rmLeft').textContent = `(${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')})`; if (!s) { clearInterval(t); killRoom(r); $('rmState').innerHTML = '<p class="muted">Code expired.</p>'; } }, 1000); }
    } catch (e) { if ($('rmState')) $('rmState').innerHTML = `<p class="muted">${esc(e.message)}</p>`; $('rmGo').disabled = false; $('rmNew').disabled = false; }
  };
  $('rmNew').onclick = () => { const code = newRoomCode(); $('rmIn').value = code; go(code); };
  $('rmGo').onclick = () => go($('rmIn').value);
}

/* =================== Random Connect (18+, boy <-> girl) =================== */
/* Fresh keys + fresh mailbox for every stranger. The relay only pairs a boy with a girl
 * (self-declared) and swaps their one-time public keys. Chats are ephemeral: "Next" destroys
 * keys, mailbox and media. Reports put the reported network on a cooldown at the relay. */
let RS = null;
function randomEntry() {
  if (!wsUp) return toast('Relay offline');
  if (!ST.set.adult || !ST.set.gender) return randomGate();
  startSearch();
}
function randomGate() {
  modal('Random Connect · 18+ only', `
    <p class="muted small">Chat anonymously with a random person. No name, number or ID is shared — just fresh encryption keys.</p>
    <ul class="rules"><li>🔞 You must be <b>18 or older</b>.</li><li>🤝 Be respectful. No harassment, threats or sexual content without consent.</li><li>🚩 Use Report if someone misbehaves — repeated reports block their network.</li><li>🕵️ Never share your address, school/office, bank or OTP details with strangers.</li><li>⏭ “Next” erases the whole chat from your device.</li></ul>
    <div class="grp">I am</div>
    <div class="gpick"><button data-g="m" class="${ST.set.gender === 'm' ? 'act' : ''}">👦 Boy</button><button data-g="f" class="${ST.set.gender === 'f' ? 'act' : ''}">👧 Girl</button></div>
    <label class="chk"><input type="checkbox" id="adult18"> I confirm I am 18 years or older and agree to these rules</label>
    <div class="row2"><button class="btn" id="rgGo">Start</button></div>`);
  let g = ST.set.gender;
  $('mBody').querySelectorAll('[data-g]').forEach((b) => { b.onclick = () => { g = b.dataset.g; $('mBody').querySelectorAll('[data-g]').forEach((x) => x.classList.toggle('act', x === b)); }; });
  $('rgGo').onclick = () => {
    if (!g) return toast('Choose Boy or Girl');
    if (!$('adult18').checked) return toast('Random Connect is only for 18+');
    ST.set.gender = g; ST.set.adult = true; save(); closeModal(); startSearch();
  };
}
async function startSearch() {
  if (RS) return;
  const kp = await genKP(), myPub = await pubRaw(kp.publicKey), rid = b64(rnd(32));
  RS = { rid, kp, myPub, sid: '' };
  const me = RS;
  modal('Finding someone…', `<div class="req"><div class="spin"></div><p>Looking for a <b>${ST.set.gender === 'm' ? 'girl' : 'boy'}</b> to chat with…</p><p class="muted small">Anonymous · end-to-end encrypted · 18+</p></div><div class="row2"><button class="btn ghost" id="rsX">Cancel</button></div>`, cancelSearch);
  $('rsX').onclick = closeModal;
  try {
    const r = await req({ op: 'new', rid }); me.sid = r.sid;
    await req({ op: 'sub', rid });
    if (RS !== me) { req({ op: 'del', rid }).catch(() => {}); return; }
    await req({ op: 'rq', g: ST.set.gender, pub: myPub, sid: r.sid });
  } catch (e) {
    if (RS === me) { modalClose = null; closeModal(); cancelSearch(me); }
    toast(e === 'cooldown' ? '⛔ Random Connect is paused for your network (reports). Try again later.' : e === 'rate' ? 'Too many searches — wait a minute' : 'Could not start search');
  }
}
function cancelSearch(which) {
  const r = which && which.rid ? which : RS; if (!r) return;
  if (r === RS) RS = null;
  if (r.matched) return;
  req({ op: 'rqx' }).catch(() => {}); req({ op: 'del', rid: r.rid }).catch(() => {});
}
async function onMatch(m) {
  if (!RS || !RS.sid || typeof m.pub !== 'string' || !isId(m.sid, 64)) return;
  const r = RS; r.matched = true; RS = null;
  const sess = await session(await dh(r.kp.privateKey, m.pub), r.myPub, m.pub, null);
  const c = newContact(sess);
  c.rid = r.rid; c.sid = r.sid; c.theirSid = m.sid; c.state = 'ok'; c.rand = true; c.mid = String(m.mid || '');
  c.sas = await sasOf(sess.root);
  c.name = 'Stranger ' + c.sas.emoji.match(/\p{Extended_Pictographic}/gu)[0];
  ST.contacts[c.id] = c;
  sys(c, '💞 Connected with a random ' + (ST.set.gender === 'm' ? 'girl' : 'boy') + ' · 18+ only · be kind · end-to-end encrypted. ⏭ = next, 🚩 = report.');
  save(); modalClose = null; closeModal(); openChat(c.id);
}
function purgeContact(c) {
  for (const m of c.msgs) if (m.f) fileDel(m.f.fid);
  req({ op: 'del', rid: c.rid }).catch(() => {});
  delete ST.contacts[c.id]; if (cur === c.id) cur = null;
  save(); render();
}
function leaveRandom(c, again) {
  if (CALL && CALL.c === c) endCall(true);
  if (c.state === 'ok') sendInner(c, { t: 'bye' }).catch(() => {});
  setTimeout(() => { purgeContact(c); if (again) startSearch(); }, 300);
}
$('randBtn').onclick = randomEntry;
$('rNext').onclick = () => { const c = ST.contacts[cur]; if (c && c.rand) leaveRandom(c, true); };
$('rRep').onclick = () => {
  const c = ST.contacts[cur]; if (!c || !c.rand) return;
  modal('Report this stranger?', `<p class="muted small">The chat ends and is erased. Your report is anonymous. If several people report the same network, it is blocked from Random Connect for a while. (Messages are end-to-end encrypted, so nobody can read them — not even the server.)</p>
    <div class="row2"><button class="btn ghost" id="rpX">Cancel</button><button class="btn danger" id="rpGo">🚩 Report & leave</button><button class="btn danger" id="rpNext">🚩 Report & next</button></div>`);
  $('rpX').onclick = closeModal;
  const go = (again) => { req({ op: 'rep', mid: c.mid }).catch(() => {}); closeModal(); toast('Reported. Thanks for keeping it safe.'); leaveRandom(c, again); };
  $('rpGo').onclick = () => go(false); $('rpNext').onclick = () => go(true);
};

/* =================== incoming =================== */
async function onEnvelope(m) {
  const c = Object.values(ST ? ST.contacts : {}).find((x) => x.sid === m.sid);
  if (c) {
    try { const inner = await open(c, JSON.parse(m.d)); await onInner(c, inner); save(); }
    catch (e) { /* tampered / replayed / unknown => dropped */ }
    ack(c.rid, m.id);
    return;
  }
  const room = rooms.get(m.sid);
  if (room) { ack(room.rid, m.id); try { await onRoomMsg(room, m.d); } catch (e) {} return; }
  const inv = invites.get(m.sid);
  if (inv) { ack(inv.rid, m.id); try { await onHello(inv, m.d); } catch (e) {} }
}
const typingUntil = {}, recvBuf = {};
const MAX_FILE = 8 * 1024 * 1024, CHUNK = 24000;
const safeMime = (s) => (typeof s === 'string' && /^[\w.+-]+\/[\w.+-]+$/.test(s) && !/svg|html|xml|javascript/i.test(s)) ? s : 'application/octet-stream';
function newIncoming(c, m) {
  if (cur !== c.id || document.hidden) c.unread = (c.unread || 0) + 1;
  typingUntil[c.id] = 0;
  if (ST.set.receipts) sendNow(c, { t: 'r', ids: [m.id], s: 'd' }).catch(() => {});
  if (cur === c.id && !document.hidden) setTimeout(() => markRead(c), 50);
}
async function onInner(c, m) {
  switch (m.t) {
    case 'ok':
      if (c.state !== 'waiting' || !isId(m.sid, 64)) return;
      c.theirSid = m.sid; c.state = 'ok'; c.verified = true;
      sys(c, '🔐 Connected · end-to-end encrypted');
      if (waitingFor === c.id) { closeModal(); waitingFor = null; openChat(c.id); }
      break;
    case 'm': {
      if (typeof m.x !== 'string' || !isId(m.id) || c.msgs.some((x) => x.id === m.id)) return;
      const ttl = Math.min(Math.max(+m.ttl || 0, 0), 31536000);
      c.msgs.push({ id: m.id, me: false, x: m.x.slice(0, 20000), ts: now(), exp: ttl ? now() + ttl * 1000 : 0, rp: isId(m.rp) ? m.rp : undefined });
      newIncoming(c, m);
      break;
    }
    case 'f': {
      if (!isId(m.id) || !isId(m.fid) || c.msgs.some((x) => x.id === m.id)) return;
      const n = +m.n, size = +m.size;
      if (!(n > 0 && n <= Math.ceil(MAX_FILE / CHUNK) + 1 && size >= 0 && size <= MAX_FILE)) return;
      const ttl = Math.min(Math.max(+m.ttl || 0, 0), 31536000);
      const f = { fid: m.fid, name: String(m.name || 'file').replace(/[\\/\u0000-\u001f]/g, '_').slice(0, 120), mime: safeMime(m.mime), size, st: 'down', p: 0, voice: Math.min(+m.voice || 0, 3600), vo: m.vo ? 1 : 0, stk: m.stk ? 1 : 0 };
      if (f.stk && (size > STK_MAX || f.vo)) return;
      c.msgs.push({ id: m.id, me: false, x: typeof m.cap === 'string' ? m.cap.slice(0, 2000) : '', ts: now(), exp: ttl ? now() + ttl * 1000 : 0, rp: isId(m.rp) ? m.rp : undefined, f });
      recvBuf[m.fid] = { n, size, parts: new Array(n), got: 0, cid: c.id, mid: m.id };
      newIncoming(c, m);
      break;
    }
    case 'fc': {
      const b = recvBuf[m.fid];
      if (!b || b.cid !== c.id || !Number.isInteger(m.i) || m.i < 0 || m.i >= b.n || b.parts[m.i]) return;
      b.parts[m.i] = unb64(m.d); b.got++;
      const msg = c.msgs.find((x) => x.id === b.mid);
      if (!msg) { delete recvBuf[m.fid]; return; }
      msg.f.p = Math.round(b.got * 100 / b.n);
      if (b.got === b.n) {
        const all = cat(...b.parts); delete recvBuf[m.fid];
        if (all.length !== b.size) { msg.f.st = 'err'; break; }
        await filePut(m.fid, all); msg.f.st = 'ok';
      }
      if (cur === c.id && (b.got % 5 === 0 || msg.f.st !== 'down')) renderChat();
      return;
    }
    case 'r':
      if (!Array.isArray(m.ids)) return;
      for (const x of c.msgs) if (x.me && m.ids.includes(x.id) && x.st !== 'r') x.st = m.s === 'r' ? 'r' : 'd';
      break;
    case 'rx': {
      const x = c.msgs.find((y) => y.id === m.id);
      if (!x || typeof m.e !== 'string' || m.e.length > 16) return;
      x.re = x.re || {}; x.re[m.e] = x.re[m.e] || {}; x.re[m.e].them = !!m.on;
      if (!x.re[m.e].me && !x.re[m.e].them) delete x.re[m.e];
      break;
    }
    case 'typ': typingUntil[c.id] = now() + 4000; setTimeout(renderTyping, 4100); renderTyping(); return;
    case 'del': { const x = c.msgs.find((y) => y.id === m.id && !y.me); if (x) { if (x.f) fileDel(x.f.fid); c.msgs = c.msgs.filter((y) => y !== x); } break; }
    case 'tmr': c.timer = Math.min(Math.max(0, +m.s || 0), 31536000); sys(c, '⏱ Disappearing messages: ' + tname(c.timer)); break;
    case 'prot':
      c.prot = !!m.on;
      sys(c, c.prot ? '🔒 ' + c.name + ' turned on Protected chat — no saving, sharing or copying; media is hold-to-view' : '🔓 ' + c.name + ' turned off Protected chat');
      break;
    case 'vo': { const x = c.msgs.find((y) => y.id === m.id && y.me && y.f && y.f.vo); if (x) x.f.st = 'opened'; break; }
    case 'ss': if (ST.set.ssAlert) sys(c, '⚠️ ' + c.name + ' may have tried to take a screenshot'); break;
    case 'bye': c.state = 'gone'; sys(c, c.rand ? '👋 Stranger left the chat. Tap ⏭ for someone new.' : 'Contact deleted this chat. Keys destroyed.'); if (CALL && CALL.c === c) endCall(false, 'Call ended'); break;
    case 'rk1': {
      if (c.rk) { if (c.rk.pub < m.pub) return; c.rk = null; }
      const kp = await genKP(), myPub = await pubRaw(kp.publicKey);
      const sess = await session(await dh(kp.privateKey, m.pub), myPub, m.pub, unb64(c.root));
      const e = c.ep + 1;
      await sendNow(c, { t: 'rk2', pub: myPub, e });
      installEpoch(c, e, sess);
      break;
    }
    case 'rk2': {
      if (!c.rk || !Number.isInteger(m.e)) return;
      const sess = await session(await dh(await impPriv(c.rk.priv), m.pub), c.rk.pub, m.pub, unb64(c.root));
      c.rk = null; installEpoch(c, m.e, sess);
      break;
    }
    case 'call': await onCallSignal(c, m); break;
  }
  render();
}

/* =================== UI =================== */
let cur = null;
const tname = (s) => !s ? 'Off' : s < 60 ? s + ' sec' : s < 3600 ? s / 60 + ' min' : s < 86400 ? s / 3600 + ' hour' : s < 604800 ? s / 86400 + ' day' : s / 604800 + ' week';
const avc = (c) => 'c' + (parseInt(c.id.replace(/[^0-9a-f]/gi, '').slice(0, 4) || '0', 16) % 8);
const ini = (n) => (n || '?').replace(/[^\p{L}\p{N} ]/gu, '').trim().split(/\s+/).map((w) => w[0]).join('').slice(0, 2).toUpperCase() || '🔐';
function sys(c, text) { c.msgs.push({ id: b64(rnd(6)), sys: true, x: text, ts: now() }); }
function toast(t) { const el = $('toast'); el.textContent = t; el.className = 'show'; clearTimeout(el._t); el._t = setTimeout(() => { el.className = ''; }, 2600); }
function copy(t, msg) { navigator.clipboard.writeText(t).then(() => { toast(msg || 'Copied'); setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 60000); }).catch(() => toast('Copy failed')); }
const preview = (m) => m.x || (m.f ? (m.f.stk ? '🧩 Sticker' : m.f.voice ? '🎤 Voice note' : m.f.mime.startsWith('image/') ? '🖼 Photo' : '📎 ' + m.f.name) : '');

let modalClose = null;
function modal(title, html, onClose) {
  if (modalClose) { const f = modalClose; modalClose = null; f(); }
  $('mTitle').textContent = title; $('mBody').innerHTML = html; $('modal').classList.remove('hidden');
  modalClose = onClose || null;
}
function closeModal() { $('modal').classList.add('hidden'); $('mBody').innerHTML = ''; if (modalClose) { const f = modalClose; modalClose = null; f(); } }
$('mClose').onclick = closeModal;
$('modal').onclick = (e) => { if (e.target.id === 'modal') closeModal(); };

function renderList() {
  const arr = Object.values(ST.contacts).sort((a, b) => ((b.msgs[b.msgs.length - 1] || {}).ts || b.created) - ((a.msgs[a.msgs.length - 1] || {}).ts || a.created));
  $('list').innerHTML = arr.length ? arr.map((c) => {
    const tag = c.rand ? '<span class="tag rnd">🎲 stranger</span>' : c.state === 'waiting' ? '<span class="tag warn">waiting</span>' : c.state === 'gone' ? '<span class="tag warn">ended</span>' : c.timer ? '<span class="tag">⏱ ' + tname(c.timer) + '</span>' : '';
    const last = [...c.msgs].reverse().find((x) => !x.sys) || c.msgs[c.msgs.length - 1];
    return `<button class="row${cur === c.id ? ' act' : ''}" data-c="${c.id}" role="listitem"><div class="av ${avc(c)}">${esc(ini(c.name))}</div>
      <div class="mid"><div class="t"><b>${esc(c.name)}</b>${c.verified ? '<span class="tag ok">✓</span>' : ''}${tag}<small>${last ? hhmm(last.ts) : ''}</small></div>
      <div class="t"><span class="p">${last ? esc((last.me ? 'You: ' : '') + preview(last)) : '<i>No messages</i>'}</span>${c.unread ? `<span class="cnt">${c.unread}</span>` : ''}</div></div></button>`;
  }).join('') : '<div class="emptyl">No chats yet.<br>Tap <b>QR</b>, <b>Join</b> or <b>Code</b> to start a private conversation.</div>';
  const tot = arr.reduce((n, c) => n + (c.unread || 0), 0);
  if (!document.body.classList.contains('dg')) document.title = (tot ? `(${tot}) ` : '') + 'Kavach';
}
const kindOf = (f) => f.voice || f.mime.startsWith('audio/') ? 'voice note' : f.mime.startsWith('video/') ? 'video' : f.mime.startsWith('image/') ? 'photo' : 'file';
function fileHTML(m, c) {
  const f = m.f;
  if (f.vo && f.st !== 'up' && f.st !== 'down' && f.st !== 'err') {
    if (m.me) return `<div class="vochip">👁 View-once ${kindOf(f)} · ${f.st === 'opened' ? 'opened ✓' : 'sent'}</div>`;
    if (f.st === 'viewed' || f.st === 'gone') return `<div class="vochip">👁 View-once ${kindOf(f)} · opened</div>`;
    return `<button class="vochip vobtn" data-vo="${esc(m.id)}">👁 View-once ${kindOf(f)} · tap to open</button>`;
  }
  if (f.st === 'up' || f.st === 'down') return `<div class="fph">${f.st === 'up' ? '⬆️' : '⬇️'} ${esc(f.voice ? 'Voice note' : f.name)} · ${f.p}%</div>`;
  if (f.st === 'err') return `<div class="fph">⚠️ ${esc(f.name)} · failed</div>`;
  if (f.st === 'gone') return `<div class="fph">🗑 ${esc(f.name)} · no longer on device</div>`;
  const url = blobUrls.get(f.fid);
  if (!url) { loadBlob(f); return `<div class="fph">🔓 Decrypting…</div>`; }
  if (f.stk) {
    if (/^video\//.test(f.mime)) return `<video class="stk" src="${url}" autoplay loop muted playsinline disablepictureinpicture></video>`;
    if (/tgsticker|lottie/.test(f.mime)) return `<div class="stk lottie" data-lottie="${esc(f.fid)}" data-mime="${esc(f.mime)}"></div>`;
    return `<img class="stk" src="${url}" alt="sticker" draggable="false">`;
  }
  const prot = c && c.prot;
  const nodl = prot ? ' controlslist="nodownload noplaybackrate noremoteplayback" disablepictureinpicture' : '';
  if (f.voice || f.mime.startsWith('audio/')) return `<div class="voice">🎤 <audio controls preload="metadata"${nodl} src="${url}"></audio><small>${f.voice ? f.voice + 's' : ''}</small></div>`;
  if (prot && /^image\//.test(f.mime)) return `<div class="holdview" data-hold="1"><img class="fimg blurred" src="${url}" alt="photo" draggable="false"><span>👆 Press &amp; hold to view</span></div>`;
  if (prot && /^video\//.test(f.mime)) return `<video class="fimg" controls preload="metadata"${nodl} src="${url}"></video>`;
  if (prot) return `<div class="fdl">📎 <span><b>${esc(f.name)}</b><small>${fmtSize(f.size)} · 🔒 Protected chat — saving disabled</small></span></div>`;
  if (/^image\/(jpeg|png|webp|gif|avif)$/.test(f.mime)) {
    const blur = c && c.rand && !m.me && ST.set.blurStrangers && !m.unblur;
    return blur ? `<div class="blurwrap" data-unblur="${esc(m.id)}"><img class="fimg blurred" src="${url}" alt="photo"><span>👁 Tap to view</span></div>` : `<img class="fimg" src="${url}" alt="photo" data-view="${esc(f.fid)}">`;
  }
  if (/^video\/(mp4|webm)$/.test(f.mime)) return `<video class="fimg" controls preload="metadata" src="${url}"></video>`;
  return `<a class="fdl" href="${url}" download="${esc(f.name)}">📎 <span><b>${esc(f.name)}</b><small>${fmtSize(f.size)} · encrypted · tap to save</small></span></a>`;
}
function msgHTML(c, m) {
  if (m.sys) return `<div class="sys">${esc(m.x)}</div>`;
  let q = '';
  if (m.rp) { const r = c.msgs.find((x) => x.id === m.rp); q = `<div class="quote" data-jump="${esc(m.rp)}"><b>${r ? (r.me ? 'You' : esc(c.name)) : ''}</b><span>${r ? esc(preview(r)) : 'Message no longer available'}</span></div>`; }
  const body = (m.f ? fileHTML(m, c) : '') + (m.x ? `<div class="tx">${esc(m.x)}</div>` : '');
  const re = m.re ? Object.keys(m.re).map((e) => { const v = m.re[e]; const n = (v.me ? 1 : 0) + (v.them ? 1 : 0); return n ? `<button class="rc${v.me ? ' me' : ''}" data-rx="${esc(e)}">${esc(e)}${n > 1 ? ' 2' : ''}</button>` : ''; }).join('') : '';
  return `<div class="m ${m.me ? 'out' : 'in'}${m.f && m.f.stk ? ' stkm' : m.f && /image|video/.test(m.f.mime) ? ' media' : ''}" data-m="${esc(m.id)}">${q}${body}<span class="meta">${m.exp ? `<span class="cd" data-exp="${m.exp}"></span> · ` : ''}${hhmm(m.ts)}${m.me ? ' ' + tick(m) : ''}</span>${re ? `<div class="rcs">${re}</div>` : ''}</div>`;
}
const nodeCache = new Map();   // msg id -> {html, el}; keeps audio/video players alive across re-renders
function renderChat() {
  const c = cur && ST && ST.contacts[cur];
  if (!c) { $('chat').classList.add('hidden'); $('empty').classList.remove('hidden'); document.body.classList.remove('in-chat'); nodeCache.clear(); return; }
  $('empty').classList.add('hidden'); $('chat').classList.remove('hidden'); document.body.classList.add('in-chat');
  $('cAv').className = 'av ' + avc(c); $('cAv').textContent = ini(c.name);
  $('cName').textContent = c.name + (c.verified ? ' ✓' : '');
  $('cSub').textContent = c.state === 'waiting' ? 'Waiting for them to accept…' : c.state === 'gone' ? 'Chat ended' : '🔐 E2EE · key epoch ' + c.ep + (c.timer ? ' · ⏱ ' + tname(c.timer) : '');
  $('tmr').value = String(c.timer || 0);
  if (c.rand) $('cSub').textContent = c.state === 'gone' ? 'Stranger left · tap ⏭ for next' : '🎲 Anonymous stranger · E2EE';
  if (c.prot && c.state === 'ok') $('cSub').textContent += ' · 🔒 Protected';
  $('msgs').classList.toggle('prot', !!c.prot);
  $('voBtn').classList.toggle('on', voNext);
  $('rNext').classList.toggle('hidden', !c.rand);
  $('rRep').classList.toggle('hidden', !c.rand || c.state !== 'ok');
  const can = c.state === 'ok';
  for (const id of ['input', 'send', 'tmr', 'aCall', 'vCall', 'attBtn', 'micBtn', 'voBtn', 'emoBtn']) $(id).disabled = !can;
  const el = $('msgs'), atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
  if (el.dataset.cid !== c.id) { el.innerHTML = ''; nodeCache.clear(); el.dataset.cid = c.id; }
  const keep = new Set();
  let i = 0;
  for (const m of c.msgs) {
    const html = msgHTML(c, m);
    let n = nodeCache.get(m.id);
    if (!n || n.html !== html) {
      const t = document.createElement('template'); t.innerHTML = html;
      const node = t.content.firstElementChild;
      if (n && n.el.parentNode) n.el.replaceWith(node);
      n = { html, el: node }; nodeCache.set(m.id, n);
    }
    keep.add(m.id);
    if (el.children[i] !== n.el) el.insertBefore(n.el, el.children[i] || null);
    i++;
  }
  for (const [id, n] of [...nodeCache]) if (!keep.has(id)) { n.el.remove(); nodeCache.delete(id); }
  while (el.children.length > c.msgs.length) el.lastElementChild.remove();
  updCountdowns();
  mountLotties(el);
  if (atBottom || renderChat.force) el.scrollTop = el.scrollHeight;
  renderChat.force = false;
  renderTyping();
}
function updCountdowns() { document.querySelectorAll('#msgs .cd').forEach((s) => { s.textContent = '⏱ ' + left(+s.dataset.exp); }); }
const left = (t) => { const s = Math.max(0, Math.round((t - now()) / 1000)); return s < 60 ? s + 's' : s < 3600 ? Math.floor(s / 60) + 'm' : s < 86400 ? Math.floor(s / 3600) + 'h' : Math.floor(s / 86400) + 'd'; };
const tick = (m) => m.st === 'r' ? '<span class="rd">✓✓</span>' : m.st === 'd' ? '✓✓' : m.st === 'q' ? '🕓' : '✓';
function renderTyping() { const on = cur && typingUntil[cur] > now(); $('typing').classList.toggle('hidden', !on); }
function render() { if (!ST) return; renderList(); renderChat(); }
function openChat(id) {
  cur = id; const c = ST.contacts[id]; if (!c) return;
  c.unread = 0; clearReply(); if (emoOpen) closeEmoPanel(); renderChat.force = true; render(); markRead(c);
  if (window.innerWidth >= 760) $('input').focus();
}
function markRead(c) {
  if (!c || !ST.set.receipts || c.state !== 'ok' || document.hidden) return;
  const ids = c.msgs.filter((m) => !m.me && !m.sys && !m.rs).map((m) => { m.rs = 1; return m.id; });
  if (ids.length) sendInner(c, { t: 'r', ids: ids.slice(-50), s: 'r' }).catch(() => {});
}
$('list').onclick = (e) => { const b = e.target.closest('[data-c]'); if (b) openChat(b.dataset.c); };
$('back').onclick = () => { cur = null; render(); };
$('invBtn').onclick = showInvite;
$('joinBtn').onclick = () => showJoin('');
$('roomBtn').onclick = showRoom;

/* ---------- composer: text, reply, files, voice ---------- */
let replyTo = null;
function setReply(m) {
  replyTo = m.id;
  $('rbWho').textContent = m.me ? 'Replying to yourself' : 'Replying to ' + ST.contacts[cur].name;
  $('rbTx').textContent = preview(m);
  $('replyBar').classList.remove('hidden'); $('input').focus();
}
function clearReply() { replyTo = null; $('replyBar').classList.add('hidden'); }
$('rbX').onclick = clearReply;
const inp = $('input');
function updSend() { const has = inp.value.trim().length > 0; $('send').classList.toggle('hidden', !has); $('micBtn').classList.toggle('hidden', has); }
inp.oninput = () => {
  inp.style.height = 'auto'; inp.style.height = Math.min(inp.scrollHeight, 140) + 'px'; updSend();
  const c = ST.contacts[cur];
  if (c && ST.set.typing && c.state === 'ok' && (!inp._t || now() - inp._t > 3000)) { inp._t = now(); sendInner(c, { t: 'typ' }).catch(() => {}); }
};
inp.onkeydown = (e) => { if (e.key === 'Enter' && !e.shiftKey && window.innerWidth >= 760) { e.preventDefault(); $('composer').requestSubmit(); } };
$('composer').onsubmit = (e) => {
  e.preventDefault();
  const c = ST.contacts[cur], x = inp.value.trim();
  if (!c || !x || c.state !== 'ok') return;
  if (te.encode(x).length > 16000) return toast('Message too long');
  const m = { id: b64(rnd(9)), me: true, x, ts: now(), st: wsUp ? '' : 'q', exp: c.timer ? now() + c.timer * 1000 : 0, rp: replyTo || undefined };
  c.msgs.push(m); inp.value = ''; inp.style.height = ''; inp._t = 0; clearReply(); updSend();
  renderChat.force = true; render(); save();
  sendInner(c, { t: 'm', id: m.id, x, ttl: c.timer || 0, rp: m.rp }).then(() => { if (m.st === 'q' && wsUp) m.st = ''; render(); }).catch(() => { m.st = 'q'; render(); });
};
$('tmr').onchange = () => {
  const c = ST.contacts[cur]; if (!c) return;
  c.timer = +$('tmr').value; sys(c, '⏱ You set disappearing messages: ' + tname(c.timer));
  sendInner(c, { t: 'tmr', s: c.timer }).catch(() => {}); render(); save();
};
$('attBtn').onclick = () => $('fileIn').click();
$('fileIn').onchange = async () => {
  const c = ST.contacts[cur], files = [...$('fileIn').files]; $('fileIn').value = '';
  for (const f of files) await sendFile(c, f, f.name, f.type || 'application/octet-stream', 0);
};
async function stripImage(blob) {   // re-encode => drops EXIF / GPS / camera serial
  const bmp = await createImageBitmap(blob, { imageOrientation: 'from-image' });
  const k = Math.min(1, 2048 / Math.max(bmp.width, bmp.height));
  const cv = document.createElement('canvas'); cv.width = Math.round(bmp.width * k); cv.height = Math.round(bmp.height * k);
  cv.getContext('2d').drawImage(bmp, 0, 0, cv.width, cv.height); bmp.close();
  const out = await new Promise((r) => cv.toBlob(r, 'image/jpeg', 0.85));
  return new Uint8Array(await out.arrayBuffer());
}
let voNext = false;
async function sendFile(c, blob, name, mime, voice, opt) {
  if (!c || c.state !== 'ok') return;
  const stk = opt && opt.stk ? 1 : 0;
  const vo = voNext && !stk ? 1 : 0;
  if (vo) { voNext = false; $('voBtn').classList.remove('on'); }
  if (blob.size > MAX_FILE) return toast('Max file size is 8 MB');
  let bytes;
  if (!stk && /^image\/(jpeg|png|webp|heic|heif|avif|bmp)$/.test(mime) && ST.set.stripMeta) {
    try { bytes = await stripImage(blob); mime = 'image/jpeg'; name = name.replace(/\.[^.]+$/, '') + '.jpg'; } catch (e) { bytes = null; }
  }
  if (!bytes) bytes = new Uint8Array(await blob.arrayBuffer());
  mime = safeMime(mime);
  const fid = b64(rnd(12)), n = Math.max(1, Math.ceil(bytes.length / CHUNK));
  await filePut(fid, bytes);
  const m = { id: b64(rnd(9)), me: true, x: '', ts: now(), st: '', exp: c.timer ? now() + c.timer * 1000 : 0, rp: replyTo || undefined, f: { fid, name: name.slice(0, 120), mime, size: bytes.length, st: 'up', p: 0, voice, vo, stk } };
  c.msgs.push(m); clearReply(); renderChat.force = true; render(); save();
  try {
    await sendInner(c, { t: 'f', id: m.id, fid, name: m.f.name, mime, size: bytes.length, n, ttl: c.timer || 0, rp: m.rp, voice, vo, stk });
    for (let i = 0; i < n; i++) {
      await sendInner(c, { t: 'fc', fid, i, d: b64(bytes.subarray(i * CHUNK, (i + 1) * CHUNK)) });
      m.f.p = Math.round((i + 1) * 100 / n);
      if (i % 3 === 0 || i === n - 1) renderChat();
    }
    m.f.st = 'ok';
    if (vo) fileDel(fid);      // sender keeps no copy of a view-once
  } catch (e) { m.f.st = 'err'; }
  save(); render();
}
let REC = null;
async function startVoice() {
  const c = ST.contacts[cur]; if (!c || c.state !== 'ok' || REC) return;
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true } });
    const mt = ['audio/webm;codecs=opus', 'audio/ogg;codecs=opus', 'audio/mp4'].find((t) => window.MediaRecorder && MediaRecorder.isTypeSupported(t)) || '';
    const rec = new MediaRecorder(stream, mt ? { mimeType: mt, audioBitsPerSecond: 32000 } : {});
    REC = { rec, stream, chunks: [], t0: now(), cancel: false, c };
    rec.ondataavailable = (e) => { if (e.data.size) REC.chunks.push(e.data); };
    rec.onstop = () => {
      const r = REC; REC = null; stream.getTracks().forEach((t) => t.stop()); voiceUI();
      if (r.cancel) return;
      const dur = Math.round((now() - r.t0) / 1000); if (dur < 1) return toast('Too short');
      const type = (rec.mimeType || 'audio/webm').split(';')[0];
      sendFile(r.c, new Blob(r.chunks, { type }), 'voice.' + (type.includes('mp4') ? 'm4a' : type.includes('ogg') ? 'ogg' : 'webm'), type, dur);
    };
    rec.start(250); voiceUI();
  } catch (e) { toast('Microphone not available'); }
}
function stopVoice(cancel) { if (!REC) return; REC.cancel = !!cancel; REC.rec.stop(); }
function voiceUI() { $('recBar').classList.toggle('hidden', !REC); $('composer').classList.toggle('hidden', !!REC); }
setInterval(() => { if (REC) { const s = Math.round((now() - REC.t0) / 1000); $('recT').textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')} · recording (encrypted)`; if (s >= 300) stopVoice(false); } }, 250);
$('micBtn').onclick = startVoice;
$('recSend').onclick = () => stopVoice(false);
$('recX').onclick = () => stopVoice(true);

/* ---------- emoji picker (all Unicode emoji) + stickers ---------- */
let EMOJI = null;
const TONES = ['', '\u{1F3FB}', '\u{1F3FC}', '\u{1F3FD}', '\u{1F3FE}', '\u{1F3FF}'];
const GROUP_ICON = ['😀', '👋', '🐶', '🍔', '✈️', '⚽', '💡', '❤️', '🏳️'];
async function loadEmoji() {
  if (!EMOJI) {
    const r = await fetch('vendor/emoji.json', { cache: 'no-cache' }); EMOJI = await r.json();
    for (const g of EMOJI) for (const it of g[1]) { if (typeof it[3] !== 'number') it[3] = 0; it[4] = it[1].toLowerCase(); }   // [emoji, name, tone, version, lowercase]
  }
  return EMOJI;
}
const emojiMaxVer = () => +(ST && ST.set.emojiVer) || 15.1;
const allowedEmoji = (it) => it[3] <= emojiMaxVer();
function toned(e, tone, ok) {
  if (!tone || !ok) return e;
  const ch = [...e]; const rest = ch.slice(1); if (rest[0] === '\uFE0F') rest.shift();
  return ch[0] + tone + rest.join('');
}
function pushRecentEmoji(e) { const r = ST.emo.recent.filter((x) => x !== e); r.unshift(e); ST.emo.recent = r.slice(0, 40); save(); }
/* renders a searchable, categorised emoji grid into `box`; onPick(emoji) */
async function emojiGrid(box, onPick, compact) {
  const data = await loadEmoji();
  let gi = ST.emo.recent.length ? -1 : 0, q = '';
  const draw = () => {
    const tone = ST.emo.tone || '';
    let list;
    if (q) { const k = q.toLowerCase(); list = []; for (const g of data) for (const it of g[1]) if (allowedEmoji(it) && it[4].includes(k)) list.push(it); list = list.slice(0, 300); }
    else if (gi < 0) list = ST.emo.recent.map((e) => [e, '', 0]);
    else list = data[gi][1].filter(allowedEmoji);
    box.querySelector('.egrid').innerHTML = list.length ? list.map((it) => { const e = toned(it[0], tone, it[2]); return `<button data-e="${esc(e)}" title="${esc(it[1])}">${e}</button>`; }).join('') : '<p class="muted small center">No emoji found</p>';
    box.querySelectorAll('.etabs button[data-gi]').forEach((b) => b.classList.toggle('act', +b.dataset.gi === gi && !q));
  };
  box.innerHTML = `<div class="ehead"><input class="esearch" placeholder="🔍 Search ${data.reduce((n, g) => n + g[1].filter(allowedEmoji).length, 0)} emoji" autocomplete="off"><div class="tones">${TONES.map((t, i) => `<button data-tone="${i}" class="${(ST.emo.tone || '') === t ? 'act' : ''}">${i ? '👋' + t : '👋'}</button>`).join('')}</div></div>
    <div class="etabs">${ST.emo.recent.length ? '<button data-gi="-1">🕘</button>' : ''}${data.map((g, i) => `<button data-gi="${i}" title="${esc(g[0])}">${GROUP_ICON[i] || '•'}</button>`).join('')}</div>
    <div class="egrid${compact ? ' compact' : ''}"></div>`;
  box.querySelector('.esearch').oninput = (e) => { q = e.target.value.trim(); draw(); };
  box.onclick = (e) => {
    const b = e.target.closest('button'); if (!b) return;
    if (b.dataset.gi !== undefined) { gi = +b.dataset.gi; q = ''; box.querySelector('.esearch').value = ''; draw(); box.querySelector('.egrid').scrollTop = 0; return; }
    if (b.dataset.tone !== undefined) { ST.emo.tone = TONES[+b.dataset.tone]; save(); box.querySelectorAll('[data-tone]').forEach((x) => x.classList.toggle('act', x === b)); draw(); return; }
    if (b.dataset.e) { pushRecentEmoji(b.dataset.e); onPick(b.dataset.e); }
  };
  draw();
}
/* --- sticker packs (stored encrypted in IndexedDB, metadata in the vault) --- */
const STK_MAX = 1024 * 1024;
let emoTab = 'emoji', stkPack = 'recent', emoOpen = false;
async function addToPack(packId, bytes, mime) {
  const pack = ST.stk.packs.find((p) => p.id === packId); if (!pack) return;
  const sid = 'S' + b64(rnd(12));
  await filePut(sid, bytes);
  pack.items.unshift({ sid, mime }); save();
}
async function normaliseSticker(file) {
  const name = (file.name || '').toLowerCase();
  if (name.endsWith('.tgs')) return { bytes: new Uint8Array(await file.arrayBuffer()), mime: 'application/x-tgsticker' };
  if (name.endsWith('.json')) return { bytes: new Uint8Array(await file.arrayBuffer()), mime: 'application/x-lottie' };
  if (/webm/.test(file.type) || name.endsWith('.webm')) return { bytes: new Uint8Array(await file.arrayBuffer()), mime: 'video/webm' };
  if (/gif/.test(file.type) || name.endsWith('.gif') || name.endsWith('.apng')) return { bytes: new Uint8Array(await file.arrayBuffer()), mime: name.endsWith('.apng') ? 'image/apng' : 'image/gif' };
  if (/webp/.test(file.type) && file.size <= STK_MAX) {           // keep (possibly animated) webp as-is
    const b = new Uint8Array(await file.arrayBuffer());
    const head = new TextDecoder('latin1').decode(b.subarray(0, 4096));
    if (head.includes('VP8X') && head.includes('ANIM')) return { bytes: b, mime: 'image/webp' };   // animated: keep frames
  }
  const bmp = await createImageBitmap(file);                       // static image -> 512px sticker, metadata stripped
  const k = Math.min(1, 512 / Math.max(bmp.width, bmp.height));
  const cv = document.createElement('canvas'); cv.width = Math.round(bmp.width * k); cv.height = Math.round(bmp.height * k);
  cv.getContext('2d').drawImage(bmp, 0, 0, cv.width, cv.height); bmp.close();
  let blob = await new Promise((r) => cv.toBlob(r, 'image/webp', 0.9));
  if (!blob || blob.type !== 'image/webp') blob = await new Promise((r) => cv.toBlob(r, 'image/png'));
  return { bytes: new Uint8Array(await blob.arrayBuffer()), mime: blob.type };
}
async function emojiSticker(e) {                                    // any emoji -> big 512px sticker
  const cv = document.createElement('canvas'); cv.width = cv.height = 512;
  const x = cv.getContext('2d'); x.textAlign = 'center'; x.textBaseline = 'middle';
  const fam = (ST.set.notoEmoji ? 'KavachEmoji,' : '') + '"Apple Color Emoji","Segoe UI Emoji","Noto Color Emoji",sans-serif';
  if (ST.set.notoEmoji && document.fonts) await document.fonts.load('400px KavachEmoji', e).catch(() => {});
  x.font = '400px ' + fam; x.fillText(e, 256, 280);
  const blob = await new Promise((r) => cv.toBlob(r, 'image/png'));
  return new Uint8Array(await blob.arrayBuffer());
}
async function sendSticker(bytes, mime) {
  const c = ST.contacts[cur]; if (!c || c.state !== 'ok') return;
  if (bytes.length > STK_MAX) return toast('Sticker too big (max 1 MB)');
  const r = ST.stk.recent; const key = b64(await sha(bytes)).slice(0, 16);
  if (!r.some((x) => x.k === key)) { const sid = 'S' + b64(rnd(12)); await filePut(sid, bytes); r.unshift({ sid, mime, k: key }); }
  else { const i = r.findIndex((x) => x.k === key); r.unshift(r.splice(i, 1)[0]); }
  for (const old of r.splice(30)) fileDel(old.sid);
  save();
  sendFile(c, new Blob([bytes], { type: mime }), 'sticker', mime, 0, { stk: 1 });
}
const stkThumb = new Map();
async function stickerUrl(it) {
  if (stkThumb.has(it.sid)) return stkThumb.get(it.sid);
  const d = await fileGet(it.sid).catch(() => null); if (!d) return '';
  const u = URL.createObjectURL(new Blob([d], { type: it.mime })); stkThumb.set(it.sid, u); return u;
}
async function renderStickerTab(box) {
  const packs = [{ id: 'recent', name: '🕘 Recent' }, { id: 'emoji', name: '😀 Emoji stickers' }, ...ST.stk.packs];
  if (!packs.some((p) => p.id === stkPack)) stkPack = 'recent';
  box.innerHTML = `<div class="etabs packs">${packs.map((p) => `<button data-pack="${esc(p.id)}" class="${p.id === stkPack ? 'act' : ''}">${esc(p.name)}</button>`).join('')}<button data-act="newpack">＋ Pack</button></div><div class="sgrid" id="sGrid"></div>`;
  const grid = $('sGrid');
  if (stkPack === 'emoji') {
    grid.classList.add('emojimode');
    await emojiGrid(grid, async (e) => sendSticker(await emojiSticker(e), 'image/png'), true);
    return;
  }
  const items = stkPack === 'recent' ? ST.stk.recent : (ST.stk.packs.find((p) => p.id === stkPack) || { items: [] }).items;
  const own = stkPack !== 'recent';
  grid.innerHTML = (own ? '<button class="sadd" data-act="import">＋<small>Add stickers</small></button>' : '') +
    (items.length ? items.map((it, i) => `<button class="sitem" data-i="${i}" data-sid="${esc(it.sid)}"></button>`).join('') : (own ? '' : '<p class="muted small center">Stickers you send appear here</p>')) +
    (own && stkPack !== 'saved' ? '<button class="sadd danger" data-act="delpack">🗑<small>Delete pack</small></button>' : '');
  for (const b of grid.querySelectorAll('.sitem')) {
    const it = items[+b.dataset.i], u = await stickerUrl(it);
    if (!u) continue;
    if (/^video\//.test(it.mime)) b.innerHTML = `<video src="${u}" autoplay loop muted playsinline></video>`;
    else if (/tgsticker|lottie/.test(it.mime)) { b.innerHTML = '<div class="lottie" data-lottie-sid="' + esc(it.sid) + '"></div>'; mountLottieEl(b.firstChild, it.sid, it.mime); }
    else b.innerHTML = `<img src="${u}" alt="">`;
  }
  grid.oncontextmenu = (e) => { const b = e.target.closest('.sitem'); if (!b || !own) return; e.preventDefault(); const pack = ST.stk.packs.find((p) => p.id === stkPack); const it = items[+b.dataset.i]; pack.items = pack.items.filter((x) => x !== it); fileDel(it.sid); save(); renderStickerTab(box); toast('Sticker removed'); };
}
async function openEmoPanel(tab) {
  emoTab = tab || emoTab; emoOpen = true;
  const P = $('emoPanel'); P.classList.remove('hidden');
  P.innerHTML = `<div class="ptabs"><button data-ptab="emoji" class="${emoTab === 'emoji' ? 'act' : ''}">😀 Emoji</button><button data-ptab="stk" class="${emoTab === 'stk' ? 'act' : ''}">🧩 Stickers</button><span class="grow"></span><button data-ptab="x" aria-label="Close">✕</button></div><div id="pBody"></div>`;
  if (emoTab === 'emoji') await emojiGrid($('pBody'), (e) => insertAtCursor(e));
  else await renderStickerTab($('pBody'));
}
function closeEmoPanel() { emoOpen = false; $('emoPanel').classList.add('hidden'); $('emoPanel').innerHTML = ''; }
function insertAtCursor(t) {
  const s0 = inp.selectionStart ?? inp.value.length, s1 = inp.selectionEnd ?? s0;
  inp.value = inp.value.slice(0, s0) + t + inp.value.slice(s1);
  const p = s0 + t.length; inp.setSelectionRange(p, p); inp.dispatchEvent(new Event('input'));
}
$('emoBtn').onclick = () => (emoOpen ? closeEmoPanel() : openEmoPanel());
$('emoPanel').addEventListener('click', async (e) => {
  const b = e.target.closest('button'); if (!b) return;
  if (b.dataset.ptab === 'x') return closeEmoPanel();
  if (b.dataset.ptab) return openEmoPanel(b.dataset.ptab);
  if (b.dataset.pack) { stkPack = b.dataset.pack; return renderStickerTab($('pBody')); }
  if (b.dataset.act === 'newpack') {
    modal('New sticker pack', '<input id="pkName" maxlength="30" placeholder="Pack name, e.g. Hum dono 💕"><div class="row2"><button class="btn" id="pkOk">Create</button></div>');
    $('pkOk').onclick = () => { const n = $('pkName').value.trim() || 'My stickers'; const id = 'p' + b64(rnd(6)); ST.stk.packs.push({ id, name: n, items: [] }); stkPack = id; save(); closeModal(); openEmoPanel('stk'); };
    return;
  }
  if (b.dataset.act === 'import') return $('stkIn').click();
  if (b.dataset.act === 'delpack') { const pack = ST.stk.packs.find((p) => p.id === stkPack); if (pack) { pack.items.forEach((it) => fileDel(it.sid)); ST.stk.packs = ST.stk.packs.filter((p) => p !== pack); stkPack = 'recent'; save(); renderStickerTab($('pBody')); } return; }
  const it = b.closest('.sitem');
  if (it) {
    const items = stkPack === 'recent' ? ST.stk.recent : ST.stk.packs.find((p) => p.id === stkPack).items;
    const x = items[+it.dataset.i]; const d = await fileGet(x.sid).catch(() => null);
    if (d) sendSticker(d, x.mime);
  }
});
$('stkIn').onchange = async () => {
  const files = [...$('stkIn').files]; $('stkIn').value = '';
  let n = 0;
  for (const f of files) {
    try { const r = await normaliseSticker(f); if (r.bytes.length > STK_MAX) { toast(f.name + ': too big (max 1 MB)'); continue; } await addToPack(stkPack, r.bytes, r.mime); n++; }
    catch (e) { toast(f.name + ': unsupported'); }
  }
  if (n) toast(`✅ ${n} sticker(s) added`);
  renderStickerTab($('pBody'));
};
/* Lottie (.tgs = gzipped Lottie JSON, Telegram's animated format) */
const lottieCache = new Map();
async function lottieData(id, mime) {
  if (lottieCache.has(id)) return lottieCache.get(id);
  const d = await fileGet(id); if (!d) return null;
  let txt;
  if (/tgsticker/.test(mime)) { const ds = new Blob([d]).stream().pipeThrough(new DecompressionStream('gzip')); txt = await new Response(ds).text(); }
  else txt = td.decode(d);
  const j = JSON.parse(txt); lottieCache.set(id, j); return j;
}
async function mountLottieEl(el, id, mime) {
  if (el._mounted || !window.lottie) return; el._mounted = true;
  try { const data = await lottieData(id, mime); if (data) lottie.loadAnimation({ container: el, renderer: 'svg', loop: true, autoplay: true, animationData: JSON.parse(JSON.stringify(data)) }); }
  catch (e) { el.textContent = '🧩'; }
}
function mountLotties(root) { root.querySelectorAll('[data-lottie]').forEach((el) => mountLottieEl(el, el.dataset.lottie, el.dataset.mime)); }

/* ---------- message actions ---------- */
const QUICK = ['👍', '❤️', '😂', '😮', '😢', '🙏', '🔥'];
function toggleReact(c, m, e) {
  m.re = m.re || {}; m.re[e] = m.re[e] || {}; m.re[e].me = !m.re[e].me;
  if (!m.re[e].me && !m.re[e].them) delete m.re[e];
  sendInner(c, { t: 'rx', id: m.id, e, on: !!(m.re[e] && m.re[e].me) }).catch(() => {});
  save(); renderChat();
}
$('msgs').onclick = (e) => {
  const c = ST.contacts[cur]; if (!c) return;
  const j = e.target.closest('[data-jump]');
  if (j) { const t = $('msgs').querySelector(`[data-m="${CSS.escape(j.dataset.jump)}"]`); if (t) { t.scrollIntoView({ block: 'center' }); t.classList.add('flash'); setTimeout(() => t.classList.remove('flash'), 1200); } return; }
  const rx = e.target.closest('[data-rx]');
  if (rx && c.state === 'ok') { const m = c.msgs.find((x) => x.id === rx.closest('[data-m]').dataset.m); if (m) toggleReact(c, m, rx.dataset.rx); return; }
  const vb = e.target.closest('[data-vo]');
  if (vb) { const m = c.msgs.find((x) => x.id === vb.dataset.vo); if (m) openViewOnce(c, m); return; }
  const ub = e.target.closest('[data-unblur]');
  if (ub) { const m = c.msgs.find((x) => x.id === ub.dataset.unblur); if (m) { m.unblur = true; renderChat(); } return; }
  const v = e.target.closest('[data-view]');
  if (v) { $('viewImg').src = v.src; $('viewer').classList.remove('hidden'); }
};
/* press-and-hold to view (protected chats) */
const holdOn = (e) => { const h = e.target.closest('[data-hold]'); if (h) { h.classList.add('reveal'); e.preventDefault(); } };
const holdOff = () => document.querySelectorAll('#msgs .holdview.reveal').forEach((h) => h.classList.remove('reveal'));
$('msgs').addEventListener('pointerdown', holdOn);
['pointerup', 'pointercancel', 'pointerleave', 'scroll'].forEach((ev) => $('msgs').addEventListener(ev, holdOff, true));
window.addEventListener('blur', holdOff);
$('msgs').addEventListener('dragstart', (e) => { if ($('msgs').classList.contains('prot')) e.preventDefault(); });
$('msgs').addEventListener('copy', (e) => { if ($('msgs').classList.contains('prot')) { e.preventDefault(); toast('🔒 Copy is disabled in Protected chat'); } });

/* view-once: opens full-screen, then destroyed on both devices */
let VO = null;
async function openViewOnce(c, m) {
  if (VO) return;
  const f = m.f;
  let d = null;
  try { d = await fileGet(f.fid); } catch (e) {}
  if (!d) { f.st = 'gone'; renderChat(); return; }
  const url = URL.createObjectURL(new Blob([d], { type: f.mime })); d.fill(0);
  VO = { c, m, url, t: null };
  const box = $('voMedia');
  const kind = kindOf(f);
  if (kind === 'photo') box.innerHTML = `<img src="${url}" alt="" draggable="false">`;
  else if (kind === 'video') box.innerHTML = `<video src="${url}" autoplay playsinline controls controlslist="nodownload noplaybackrate noremoteplayback" disablepictureinpicture></video>`;
  else if (kind === 'voice note') box.innerHTML = `<div class="vovoice">🎤</div><audio src="${url}" autoplay controls controlslist="nodownload noplaybackrate"></audio>`;
  else box.innerHTML = `<div class="vovoice">📎</div><p>${esc(f.name)}</p><p class="small">View-once files can't be saved.</p>`;
  $('vo').classList.remove('hidden');
  const media = box.querySelector('video,audio');
  if (media) { media.onended = closeViewOnce; $('voInfo').textContent = '👁 View once · disappears when it ends or you close it'; }
  else {
    let left = 10;
    const tick = () => { $('voInfo').textContent = `👁 View once · disappears in ${left}s`; if (left-- <= 0) closeViewOnce(); };
    tick(); VO.t = setInterval(tick, 1000);
  }
}
function closeViewOnce() {
  if (!VO) return;
  const { c, m, url, t } = VO; VO = null;
  clearInterval(t);
  $('voMedia').innerHTML = ''; $('vo').classList.add('hidden');
  URL.revokeObjectURL(url);
  fileDel(m.f.fid); m.f.st = 'viewed';
  if (c.state === 'ok') sendInner(c, { t: 'vo', id: m.id }).catch(() => {});
  save(); renderChat();
}
$('voX').onclick = closeViewOnce;
$('vo').addEventListener('contextmenu', (e) => e.preventDefault());
document.addEventListener('visibilitychange', () => { if (document.hidden && VO) closeViewOnce(); });
$('voBtn').onclick = () => { voNext = !voNext; $('voBtn').classList.toggle('on', voNext); toast(voNext ? '👁 Next photo / video / voice note will be view-once' : 'View-once off'); };

$('viewer').onclick = () => { $('viewer').classList.add('hidden'); $('viewImg').removeAttribute('src'); };
$('msgs').ondblclick = (e) => { const el = e.target.closest('[data-m]'); const c = ST.contacts[cur]; if (!el || !c || c.state !== 'ok' || e.target.closest('audio,video,a')) return; const m = c.msgs.find((x) => x.id === el.dataset.m); if (m) toggleReact(c, m, '❤️'); };
$('msgs').oncontextmenu = (e) => { const el = e.target.closest('[data-m]'); if (!el) return; e.preventDefault(); msgAction(el.dataset.m); };
let lpT = null;
$('msgs').addEventListener('touchstart', (e) => { const el = e.target.closest('[data-m]'); if (!el) return; lpT = setTimeout(() => msgAction(el.dataset.m), 500); }, { passive: true });
['touchend', 'touchmove'].forEach((ev) => $('msgs').addEventListener(ev, () => clearTimeout(lpT), { passive: true }));
function msgAction(id) {
  const c = ST.contacts[cur], m = c && c.msgs.find((x) => x.id === id); if (!m) return;
  const ok = c.state === 'ok';
  const locked = c.prot || (m.f && m.f.vo);
  modal('Message', `${ok ? `<div class="qreact">${QUICK.map((e) => `<button data-qr="${e}">${e}</button>`).join('')}<button id="maMore" aria-label="More reactions">➕</button></div><div id="maPick"></div>` : ''}
    ${m.f && m.f.stk && m.f.st === 'ok' && !locked ? '<div class="row2"><button class="btn ghost" id="maStk">⭐ Add to my stickers</button></div>' : ''}
    <div class="row2">${ok ? '<button class="btn ghost" id="maReply">↩️ Reply</button>' : ''}${m.x && !locked ? '<button class="btn ghost" id="maCopy">📋 Copy</button>' : ''}</div>
    ${locked ? '<p class="small muted center">🔒 Protected — copy, save and share are disabled</p>' : ''}
    ${!locked && (m.x || (m.f && m.f.st === 'ok')) ? '<div class="row2"><button class="btn ghost" id="maShare">📤 Share to other apps</button></div>' : ''}
    <div class="row2"><button class="btn ghost" id="maMe">🗑 Delete for me</button>${m.me && ok ? '<button class="btn danger" id="maAll">Delete for everyone</button>' : ''}</div>`);
  $('mBody').querySelectorAll('[data-qr]').forEach((b) => { b.onclick = () => { toggleReact(c, m, b.dataset.qr); closeModal(); }; });
  if ($('maReply')) $('maReply').onclick = () => { closeModal(); setReply(m); };
  if ($('maCopy')) $('maCopy').onclick = () => { copy(m.x, 'Copied · clipboard clears in 60s'); closeModal(); };
  if ($('maShare')) $('maShare').onclick = () => shareOut(m);
  if ($('maMore')) $('maMore').onclick = () => { emojiGrid($('maPick'), (e) => { toggleReact(c, m, e); closeModal(); }, true); $('maMore').classList.add('hidden'); };
  if ($('maStk')) $('maStk').onclick = async () => { const d = await fileGet(m.f.fid).catch(() => null); if (!d) return toast('Sticker not on device'); await addToPack('saved', d, m.f.mime); toast('⭐ Added to Saved stickers'); closeModal(); };
  const remove = () => { if (m.f) fileDel(m.f.fid); c.msgs = c.msgs.filter((x) => x !== m); save(); render(); closeModal(); };
  $('maMe').onclick = remove;
  if ($('maAll')) $('maAll').onclick = () => { sendInner(c, { t: 'del', id: m.id }).catch(() => {}); remove(); };
}
/* ---------- share out to WhatsApp / Instagram / Facebook / X / Telegram ... ---------- */
async function shareOut(m) {
  let file = null;
  if (m.f) {
    const d = await fileGet(m.f.fid).catch(() => null);
    if (!d) return toast('File no longer on this device');
    file = new File([d], m.f.name, { type: m.f.mime });
  }
  const text = m.x || '';
  modal('Share outside Kavach?', `
    <p class="muted small">⚠️ Once shared, this ${file ? (m.f.mime.startsWith('image/') ? 'photo' : m.f.mime.startsWith('video/') ? 'video' : m.f.voice ? 'voice note' : 'file') : 'message'} leaves Kavach — it is <b>no longer end-to-end encrypted</b> and that app's rules apply.${file && m.f.mime === 'image/jpeg' ? ' Location/EXIF data was already removed.' : ''}</p>
    ${file && m.f.mime.startsWith('image/') && blobUrls.get(m.f.fid) ? `<img class="fimg shareprev" src="${blobUrls.get(m.f.fid)}" alt="">` : ''}
    <div class="row2"><button class="btn" id="shNative">📤 Choose app…</button></div>
    <div class="grp">Or</div>
    <div class="apps">
      ${text ? `<a class="appbtn" target="_blank" rel="noopener noreferrer" href="https://wa.me/?text=${encodeURIComponent(text)}">WhatsApp</a>
      <a class="appbtn" target="_blank" rel="noopener noreferrer" href="https://t.me/share/url?url=%20&text=${encodeURIComponent(text)}">Telegram</a>
      <a class="appbtn" target="_blank" rel="noopener noreferrer" href="https://x.com/intent/post?text=${encodeURIComponent(text)}">X</a>
      <a class="appbtn" target="_blank" rel="noopener noreferrer" href="mailto:?body=${encodeURIComponent(text)}">Email</a>` : ''}
      ${file ? `<a class="appbtn" id="shDl" download="${esc(m.f.name)}">⬇️ Save to device</a>` : ''}
      ${text ? '<button class="appbtn" id="shCopy">📋 Copy text</button>' : ''}
    </div>
    <p class="small muted">${file ? 'For Instagram / Facebook / Snapchat: tap “Choose app…”, or save to device and post from that app.' : ''}</p>`);
  if ($('shDl')) $('shDl').href = blobUrls.get(m.f.fid) || URL.createObjectURL(file);
  if ($('shCopy')) $('shCopy').onclick = () => copy(text, 'Copied');
  $('shNative').onclick = async () => {
    const data = file ? { files: [file] } : { text };
    if (file && text) data.text = text;
    if (navigator.canShare && navigator.canShare(data)) {
      try { await navigator.share(data); closeModal(); } catch (e) { if (e.name !== 'AbortError') toast('Share failed'); }
    } else if (!file && navigator.share) {
      try { await navigator.share({ text }); closeModal(); } catch (e) {}
    } else {
      toast(file ? 'This browser cannot share files — use “Save to device”' : 'Use one of the app buttons below');
    }
  };
}
$('cWho').onclick = () => verifyModal(ST.contacts[cur]);
$('cMenu').onclick = () => {
  const c = ST.contacts[cur]; if (!c) return;
  modal(c.name, `
    <div class="opt"><div class="tx"><b>Nickname</b><small>Stored only on this device</small></div></div><input id="nick" value="${esc(c.name)}" maxlength="40">
    <div class="row2"><button class="btn ghost" id="mVer">🔍 Safety code</button><button class="btn ghost" id="mRk" ${c.state !== 'ok' ? 'disabled' : ''}>🔄 Refresh keys</button></div>
    <div class="opt"><div class="tx"><b>🔒 Protected chat</b><small>For both of you: no save, share or copy · photos are press-and-hold · video/voice can't be downloaded</small></div><button class="sw ${c.prot ? 'on' : ''}" id="protSw" ${c.state !== 'ok' ? 'disabled' : ''}></button></div>
    ${c.rand ? '<div class="row2"><button class="btn ghost" id="mSave">⭐ Save as contact</button></div>' : ''}
    <div class="row2"><button class="btn ghost" id="mClr">Clear history</button><button class="btn danger" id="mDel">Delete & destroy keys</button></div>`);
  $('nick').onchange = () => { c.name = $('nick').value.trim() || c.name; save(); render(); };
  $('mVer').onclick = () => verifyModal(c);
  $('protSw').onclick = function () {
    if (c.state !== 'ok') return;
    c.prot = !c.prot; this.className = 'sw' + (c.prot ? ' on' : '');
    sys(c, c.prot ? '🔒 You turned on Protected chat — no saving, sharing or copying; media is hold-to-view' : '🔓 You turned off Protected chat');
    sendInner(c, { t: 'prot', on: c.prot }).catch(() => {}); save(); render();
  };
  if ($('mSave')) $('mSave').onclick = () => { c.rand = false; c.name = $('nick').value.trim() || c.name; sys(c, '⭐ Saved as a contact on your device'); save(); render(); closeModal(); };
  $('mRk').onclick = () => { serial(() => (c.rk ? null : startRekeyNow(c))).then(() => toast('New keys negotiated')).catch(() => toast('Re-key failed')); closeModal(); };
  $('mClr').onclick = () => { for (const m of c.msgs) if (m.f) fileDel(m.f.fid); c.msgs = []; save(); render(); closeModal(); };
  $('mDel').onclick = () => {
    if (c.theirSid && c.state === 'ok') sendInner(c, { t: 'bye' }).catch(() => {});
    setTimeout(() => { for (const m of c.msgs) if (m.f) fileDel(m.f.fid); req({ op: 'del', rid: c.rid }).catch(() => {}); delete ST.contacts[c.id]; cur = null; save(); render(); }, 300);
    closeModal();
  };
};
function verifyModal(c) {
  if (!c || !c.sas) return;
  modal('Safety code', `<div class="req"><p class="muted small center">Compare with ${esc(c.name)}'s screen in person or on a call. Matching codes = no one in the middle.</p>
    <div class="sas">${c.sas.emoji}</div><div class="digits">${c.sas.digits}</div></div>
    <div class="opt"><div class="tx"><b>Verified</b><small>Mark only after comparing</small></div><button class="sw ${c.verified ? 'on' : ''}" id="verSw"></button></div>`);
  $('verSw').onclick = function () { c.verified = !c.verified; this.className = 'sw' + (c.verified ? ' on' : ''); save(); render(); };
}

/* =================== settings =================== */
let setTab = 'look';
$('setBtn').onclick = () => openSettings();
function openSettings() {
  const sw = (k, t, d) => `<div class="opt"><div class="tx"><b>${t}</b><small>${d}</small></div><button class="sw ${ST.set[k] ? 'on' : ''}" data-k="${k}"></button></div>`;
  const tabs = [['look', '🎨 Look'], ['privacy', '🕶 Privacy'], ['security', '🔐 Security']];
  let h = `<div class="stabs">${tabs.map(([k, n]) => `<button class="${setTab === k ? 'act' : ''}" data-tab="${k}">${n}</button>`).join('')}</div>`;
  if (setTab === 'look') {
    h += `<div class="grp">Themes (${THEMES.length})</div><div class="themes">${THEMES.map((t, i) => `<button class="th${+ST.set.theme === i ? ' act' : ''}" data-th="${i}"><i class="b1"></i><i class="b2"></i><span>${t[0]}</span></button>`).join('')}</div>
      <div class="grp">Accent colour</div><div class="swatches"><button class="${!ST.set.accent ? 'act' : ''} rainbow" data-ac="" aria-label="Theme default"></button>${ACCENTS.map((a) => `<button class="${ST.set.accent === a ? 'act' : ''}" data-ac="${a}" aria-label="${a}"></button>`).join('')}</div>
      <div class="row2"><button class="btn ghost" id="shuf">🎲 Surprise me</button></div>
      <div class="grp">Emoji</div>
      <div class="opt"><div class="tx"><b>Newest emoji in picker</b><small>Very new emoji may show as ☐ on older phones unless the font below is on</small></div><select id="evSel">${[[13.1, 'Emoji 13.1 (2020)'], [14, 'Emoji 14 (2021)'], [15, 'Emoji 15 (2022)'], [15.1, 'Emoji 15.1 (2023)'], [16, 'Emoji 16 (2024)'], [17, 'Emoji 17 (2025)'], [99, 'All available']].map(([v, n]) => `<option value="${v}" ${emojiMaxVer() === v ? 'selected' : ''}>${n}</option>`).join('')}</select></div>
      ${'<div class="opt"><div class="tx"><b>Same emoji on every phone</b><small>Uses the bundled Noto Color Emoji font (Google, open-source). Shows new emoji even on old phones. Downloads ~1–2 MB from your own server the first time.</small></div><button class="sw ' + (ST.set.notoEmoji ? 'on' : '') + '" data-k="notoEmoji"></button></div>'}`;
  } else if (setTab === 'privacy') {
    h += sw('receipts', 'Read receipts', 'Send delivered/read ticks (encrypted)') + sw('typing', 'Typing indicator', 'Let others see when you type') +
      sw('relayOnly', 'Hide my IP in calls', 'Force calls through TURN relay when available') + sw('stripMeta', 'Strip photo metadata', 'Removes EXIF, GPS location & camera info before sending') +
      `<div class="grp">Random Connect</div><div class="opt"><div class="tx"><b>I am</b><small>Self-declared · used only for matching</small></div><select id="gSel"><option value="">—</option><option value="m" ${ST.set.gender === 'm' ? 'selected' : ''}>Boy</option><option value="f" ${ST.set.gender === 'f' ? 'selected' : ''}>Girl</option></select></div>` +
      sw('blurStrangers', 'Blur photos from strangers', 'Photos in Random Connect chats stay blurred until you tap') +
      sw('ssAlert', 'Screenshot alerts', 'Warn the other person on a screenshot attempt (desktop PrintScreen; best-effort)');
  } else {
    h += `<div class="opt"><div class="tx"><b>Auto-lock</b><small>When app goes to background</small></div><select id="alSel">${[[0, 'Immediately'], [1, '1 min'], [5, '5 min'], [30, '30 min']].map(([v, n]) => `<option value="${v}" ${+ST.set.autoLock === v ? 'selected' : ''}>${n}</option>`).join('')}</select></div>
      ${sw('wipe10', 'Erase after 10 wrong PINs', 'Destroys all keys & chats on this device')}
      ${sw('disguise', 'Calculator disguise', 'Lock screen looks like a working calculator. Type your PIN then “=” to open.')}
      <div class="row2"><button class="btn ghost" id="chPin">🔑 Change PIN</button><button class="btn ghost" id="newRec">🧾 New recovery key</button></div>
      <div class="grp">Private server</div>
      <p class="small muted">If your relay runs in private mode (ACCESS_KEY set on the NUC), enter the same key here. Without it nobody can even connect.</p>
      <div class="opt"><input id="rkIn" type="password" autocomplete="off" placeholder="Relay access key" value="${esc(ST.set.relayKey || '')}"><button class="btn ghost" id="rkSave">Save</button></div>
      <div class="grp">Duress PIN</div>
      <p class="small muted">A second PIN for when someone forces you to unlock. It opens an empty, normal-looking Kavach. Optionally it silently destroys your real chats.</p>
      <div class="row2"><button class="btn ghost" id="setDur">🎭 Set duress PIN</button><button class="btn ghost" id="clrDur">Remove</button></div>
      <div class="grp">Danger</div>
      <div class="row2"><button class="btn danger" id="panic">🧨 Wipe everything</button></div>
      <p class="small muted">No account or ID exists. Each contact has fresh keys and its own random mailbox. AES-256-GCM with a new key per message, re-keying every 40 messages, padding, and relay deletion after delivery. On this device everything is encrypted with a random key locked by your PIN, recovery key and duress PIN (PBKDF2, 310k rounds).</p>`;
  }
  modal('Settings', h);
  const B = $('mBody');
  B.querySelectorAll('[data-tab]').forEach((b) => { b.onclick = () => { setTab = b.dataset.tab; openSettings(); }; });
  B.querySelectorAll('[data-th]').forEach((b) => {
    const t = THEMES[+b.dataset.th]; b.style.background = t[1]; b.style.color = t[4]; b.style.borderColor = +ST.set.theme === +b.dataset.th ? 'var(--accent)' : t[6];
    b.querySelector('.b1').style.background = t[8]; b.querySelector('.b1').style.borderColor = t[6]; b.querySelector('.b2').style.background = t[9];
    b.onclick = () => { ST.set.theme = +b.dataset.th; applyTheme(); save(); openSettings(); };
  });
  B.querySelectorAll('[data-ac]').forEach((b) => { if (b.dataset.ac) b.style.background = b.dataset.ac; b.onclick = () => { ST.set.accent = b.dataset.ac; applyTheme(); save(); openSettings(); }; });
  if ($('evSel')) $('evSel').onchange = () => { ST.set.emojiVer = +$('evSel').value; save(); toast('Emoji picker updated'); };
  if ($('shuf')) $('shuf').onclick = () => { ST.set.theme = rnd(1)[0] % THEMES.length; ST.set.accent = rnd(1)[0] % 3 === 0 ? ACCENTS[rnd(1)[0] % ACCENTS.length] : ''; applyTheme(); save(); openSettings(); toast('✨ ' + THEMES[ST.set.theme][0]); };
  B.querySelectorAll('[data-k]').forEach((b) => { b.onclick = () => {
    const k = b.dataset.k; ST.set[k] = !ST.set[k]; b.className = 'sw' + (ST.set[k] ? ' on' : '');
    if (k === 'notoEmoji') applyTheme();
    if (k === 'wipe10') localStorage.setItem('kavach_w10', ST.set[k] ? '1' : '0');
    if (k === 'disguise') { if (ST.set[k]) localStorage.setItem('kavach_dg', '1'); else localStorage.removeItem('kavach_dg'); if (ST.set[k]) toast('Next lock shows a calculator. Type PIN then = to open.'); }
    save();
  }; });
  if ($('gSel')) $('gSel').onchange = () => { ST.set.gender = $('gSel').value; save(); };
  if ($('rkSave')) $('rkSave').onclick = () => { ST.set.relayKey = $('rkIn').value.trim(); save(); failStreak = 0; toast('Access key saved · reconnecting…'); try { ws.close(); } catch (e) {} };
  if ($('alSel')) $('alSel').onchange = () => { ST.set.autoLock = +$('alSel').value; save(); };
  if ($('chPin')) $('chPin').onclick = () => {
    modal('Change PIN', `<input id="op" type="password" inputmode="numeric" autocomplete="off" placeholder="Current PIN"><p></p>
      <input id="np1" type="password" inputmode="numeric" autocomplete="off" placeholder="New PIN (min 6 digits)"><p></p>
      <input id="np2" type="password" inputmode="numeric" autocomplete="off" placeholder="Repeat new PIN">
      <div class="row2"><button class="btn ghost" id="npX">Cancel</button><button class="btn" id="npOk">Change PIN</button></div>`);
    $('npX').onclick = closeModal;
    $('npOk').onclick = async () => {
      const o = $('op').value, a = $('np1').value, b = $('np2').value;
      if (!/^\d{6,32}$/.test(a) || a !== b) return toast('New PINs must match, 6+ digits');
      if (a === o) return toast('New PIN is same as old');
      $('npOk').disabled = true;
      try { await changePin(o, a); closeModal(); toast('✅ PIN changed'); }
      catch (e) { toast('Current PIN is wrong'); $('op').value = ''; $('npOk').disabled = false; }
    };
  };
  if ($('newRec')) $('newRec').onclick = () => {
    modal('New recovery key', `<p class="muted small">Your old recovery key will stop working.</p><input id="rp" type="password" inputmode="numeric" autocomplete="off" placeholder="Current PIN"><div class="row2"><button class="btn" id="rpOk">Generate</button></div>`);
    $('rpOk').onclick = async () => { try { showRecovery(await rotateRecovery($('rp').value), 'New recovery key'); } catch (e) { toast('Current PIN is wrong'); } };
  };
  if ($('setDur')) $('setDur').onclick = () => {
    modal('Set duress PIN', `<p class="muted small">Must be different from your real PIN. Entering it shows an empty Kavach that looks completely normal.</p>
      <input id="d1" type="password" inputmode="numeric" autocomplete="off" placeholder="Duress PIN (6+ digits)"><p></p>
      <input id="d2" type="password" inputmode="numeric" autocomplete="off" placeholder="Repeat duress PIN">
      <div class="opt"><div class="tx"><b>Also destroy real chats</b><small>Silently erases your real vault the moment the duress PIN is used</small></div><button class="sw" id="dW"></button></div>
      <div class="row2"><button class="btn" id="dOk">Save duress PIN</button></div>`);
    $('dW').onclick = function () { this.classList.toggle('on'); };
    $('dOk').onclick = async () => {
      const a = $('d1').value;
      if (!/^\d{6,32}$/.test(a) || a !== $('d2').value) return toast('PINs must match, 6+ digits');
      $('dOk').disabled = true;
      try { await setDuress(a, $('dW').classList.contains('on')); closeModal(); toast('🎭 Duress PIN saved'); }
      catch (e) { toast(e.message === 'same' ? 'Must differ from your real PIN' : 'Failed'); $('dOk').disabled = false; }
    };
  };
  if ($('clrDur')) $('clrDur').onclick = () => { clearDuress(); toast('Duress PIN removed'); };
  if ($('panic')) $('panic').onclick = () => { modal('Wipe everything?', '<p class="muted">All chats, files and keys on this device will be destroyed. This cannot be undone.</p><div class="row2"><button class="btn ghost" id="pNo">Cancel</button><button class="btn danger" id="pYes">Wipe now</button></div>'); $('pNo').onclick = closeModal; $('pYes').onclick = () => { for (const c of Object.values(ST.contacts)) req({ op: 'del', rid: c.rid }).catch(() => {}); setTimeout(wipeAll, 300); }; };
}

/* =================== calls =================== */
let CALL = null;
async function iceCfg() {
  let ice = [];
  try { ice = (await req({ op: 'ice' })).ice || []; } catch (e) {}
  const hasTurn = ice.some((s) => s.username);
  return { iceServers: ice, iceTransportPolicy: ST.set.relayOnly && hasTurn ? 'relay' : 'all' };
}
async function makePC(c, cid) {
  const cfg = await iceCfg();
  const pc = new RTCPeerConnection(Object.assign({ bundlePolicy: 'max-bundle', rtcpMuxPolicy: 'require' }, cfg));
  pc.onicecandidate = (e) => { if (e.candidate) sendInner(c, { t: 'call', k: 'ice', cid, cand: e.candidate.toJSON() }).catch(() => {}); };
  pc.ontrack = (e) => { $('remoteV').srcObject = e.streams[0]; };
  pc.onconnectionstatechange = () => {
    if (!CALL || CALL.pc !== pc) return;
    const s = pc.connectionState;
    if (s === 'connected') { CALL.state = 'live'; CALL.t0 = CALL.t0 || now(); }
    if (s === 'failed') endCall(true, 'Connection failed');
    callUI();
  };
  return pc;
}
const gum = (video) => navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true }, video: video ? { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: 'user' } : false });
async function startCall(video) {
  const c = ST.contacts[cur]; if (!c || CALL || c.state !== 'ok') return;
  const cid = b64(rnd(9));
  CALL = { c, cid, video, role: 'caller', state: 'calling', queue: [] }; callUI();
  try {
    CALL.local = await gum(video); $('localV').srcObject = CALL.local;
    CALL.pc = await makePC(c, cid);
    CALL.local.getTracks().forEach((t) => CALL.pc.addTrack(t, CALL.local));
    const off = await CALL.pc.createOffer();
    await CALL.pc.setLocalDescription(off);
    await sendInner(c, { t: 'call', k: 'offer', cid, sdp: off.sdp, video: !!video });
    CALL.noAns = setTimeout(() => { if (CALL && CALL.state === 'calling') endCall(true, 'No answer'); }, 45000);
  } catch (e) { endCall(true, 'Mic/camera unavailable'); }
}
async function onCallSignal(c, m) {
  if (m.k === 'offer') {
    if (CALL) { sendNow(c, { t: 'call', k: 'busy', cid: m.cid }).catch(() => {}); return; }
    if (typeof m.sdp !== 'string') return;
    CALL = { c, cid: m.cid, video: !!m.video, role: 'callee', state: 'ringing', offer: m.sdp, queue: [] };
    callUI(); return;
  }
  if (!CALL || CALL.cid !== m.cid || CALL.c !== c) return;
  if (m.k === 'answer' && CALL.pc && typeof m.sdp === 'string') {
    clearTimeout(CALL.noAns);
    await CALL.pc.setRemoteDescription({ type: 'answer', sdp: m.sdp });
    CALL.state = 'connecting'; flushIce(); callUI();
  } else if (m.k === 'ice' && m.cand) {
    if (CALL.pc && CALL.pc.remoteDescription) CALL.pc.addIceCandidate(m.cand).catch(() => {});
    else CALL.queue.push(m.cand);
  } else if (m.k === 'end' || m.k === 'busy' || m.k === 'decline') {
    endCall(false, m.k === 'busy' ? 'Busy' : m.k === 'decline' ? 'Declined' : 'Call ended');
  }
}
function flushIce() { const q = CALL.queue; CALL.queue = []; q.forEach((cd) => CALL.pc.addIceCandidate(cd).catch(() => {})); }
async function acceptCall(video) {
  if (!CALL || CALL.role !== 'callee') return;
  const { c, cid } = CALL;
  CALL.state = 'connecting'; CALL.video = video; callUI();
  try {
    CALL.local = await gum(video); $('localV').srcObject = CALL.local;
    CALL.pc = await makePC(c, cid);
    CALL.local.getTracks().forEach((t) => CALL.pc.addTrack(t, CALL.local));
    await CALL.pc.setRemoteDescription({ type: 'offer', sdp: CALL.offer });
    flushIce();
    const ans = await CALL.pc.createAnswer();
    await CALL.pc.setLocalDescription(ans);
    await sendInner(c, { t: 'call', k: 'answer', cid, sdp: ans.sdp });
  } catch (e) { endCall(true, 'Mic/camera unavailable'); }
}
function endCall(notify, reason) {
  if (!CALL) return;
  const { c, cid, t0, role } = CALL;
  if (notify) sendInner(c, { t: 'call', k: CALL.state === 'ringing' ? 'decline' : 'end', cid }).catch(() => {});
  clearTimeout(CALL.noAns);
  if (CALL.local) CALL.local.getTracks().forEach((t) => t.stop());
  if (CALL.pc) try { CALL.pc.close(); } catch (e) {}
  $('remoteV').srcObject = null; $('localV').srcObject = null;
  CALL = null; $('call').classList.add('hidden');
  const dur = t0 ? Math.round((now() - t0) / 1000) : 0;
  if (ST) { sys(c, (role === 'caller' ? '📞 Outgoing call' : '📞 Incoming call') + (dur ? ` · ${Math.floor(dur / 60)}:${String(dur % 60).padStart(2, '0')}` : ' · ' + (reason || 'ended'))); save(); render(); }
  if (reason && !dur) toast(reason);
}
function callUI() {
  if (!CALL) return;
  const { c } = CALL, el = $('call');
  el.classList.remove('hidden'); el.classList.toggle('vid', !!CALL.video && CALL.state !== 'ringing');
  $('callAv').className = 'av big ' + avc(c); $('callAv').textContent = ini(c.name);
  $('callName').textContent = c.name;
  $('callSas').textContent = c.sas ? c.sas.emoji.match(/\p{Extended_Pictographic}/gu).slice(0, 4).join(' ') : '';
  $('callState').textContent = { calling: 'Calling…', ringing: (CALL.video ? 'Incoming video call' : 'Incoming voice call'), connecting: 'Connecting securely…', live: 'Live · end-to-end encrypted' }[CALL.state] || '';
  $('ringBtns').classList.toggle('hidden', CALL.state !== 'ringing');
  $('inBtns').classList.toggle('hidden', CALL.state === 'ringing');
  $('localV').classList.toggle('hidden', !CALL.video);
  $('remoteV').classList.toggle('hidden', !CALL.video);
}
setInterval(() => { if (CALL && CALL.state === 'live' && CALL.t0) { const s = Math.round((now() - CALL.t0) / 1000); $('callState').textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')} · end-to-end encrypted`; } }, 1000);
$('aCall').onclick = () => startCall(false);
$('vCall').onclick = () => startCall(true);
$('accA').onclick = () => acceptCall(false);
$('accV').onclick = () => acceptCall(true);
$('decl').onclick = () => endCall(true, 'Declined');
$('hang').onclick = () => endCall(true);
$('mute').onclick = () => { if (!CALL || !CALL.local) return; const t = CALL.local.getAudioTracks()[0]; if (t) { t.enabled = !t.enabled; $('mute').classList.toggle('on', !t.enabled); } };
$('cam').onclick = () => { if (!CALL || !CALL.local) return; const t = CALL.local.getVideoTracks()[0]; if (t) { t.enabled = !t.enabled; $('cam').classList.toggle('on', !t.enabled); } };

/* =================== timers & privacy =================== */
setInterval(() => {
  if (!ST) return;
  let changed = false;
  for (const c of Object.values(ST.contacts)) {
    const dead = c.msgs.filter((m) => m.exp && m.exp <= now());
    if (dead.length) { for (const m of dead) if (m.f) fileDel(m.f.fid); c.msgs = c.msgs.filter((m) => !dead.includes(m)); changed = true; }
  }
  if (changed) { save(); render(); } else updCountdowns();
  for (const fid of Object.keys(recvBuf)) { /* nothing: buffers die with the session */ }
}, 1000);
let hiddenAt = 0;
document.addEventListener('visibilitychange', () => {
  if (!ST) return;
  if (document.hidden) { hiddenAt = now(); $('shield').classList.remove('hidden'); }
  else {
    $('shield').classList.add('hidden');
    if (!CALL && !REC && hiddenAt && now() - hiddenAt >= (+ST.set.autoLock) * 60e3) lock();
    else if (cur) markRead(ST.contacts[cur]);
  }
});
function screenshotAttempt() {
  if (!ST) return;
  $('shield').classList.remove('hidden'); setTimeout(() => $('shield').classList.add('hidden'), 1500);
  navigator.clipboard && navigator.clipboard.writeText('').catch(() => {});
  const c = cur && ST.contacts[cur];
  if (c && c.state === 'ok' && ST.set.ssAlert) { sendInner(c, { t: 'ss' }).catch(() => {}); sys(c, '⚠️ Screenshot attempt detected — contact was notified'); render(); }
}
document.addEventListener('keyup', (e) => { if (e.key === 'PrintScreen') screenshotAttempt(); });
document.addEventListener('keydown', (e) => { if (e.key === 'PrintScreen' || ((e.metaKey) && e.shiftKey && /^[345]$/.test(e.key))) screenshotAttempt(); });

/* =================== lock / unlock / disguise =================== */
async function lock() {
  if (CALL) endCall(true);
  if (REC) stopVoice(true);
  if (VO) closeViewOnce();
  killAllInvites(); killAllRooms(); stopScan(); if (RS) cancelSearch(); closeModal();
  clearTimeout(saveT); await persist();
  revokeAll(); nodeCache.clear(); if (emoOpen) closeEmoPanel(); for (const u of stkThumb.values()) URL.revokeObjectURL(u); stkThumb.clear(); lottieCache.clear();
  clearTimeout($('toast')._t); $('toast').className = ''; $('toast').textContent = '';
  vaultKey = null; ST = null; cur = null; slot = 'real';
  try { if (ws) { ws.onclose = null; ws.close(); } } catch (e) {}
  wsUp = false; outbox = [];
  $('msgs').innerHTML = ''; $('msgs').dataset.cid = ''; $('list').innerHTML = '';
  $('app').classList.add('hidden');
  showLockScreen();
}
$('lockBtn').onclick = lock;
function showLockScreen() {
  const dg = localStorage.getItem('kavach_dg') === '1' && !!localStorage.getItem(VKEY);
  document.body.classList.toggle('dg', dg);
  document.title = dg ? 'Calculator' : 'Kavach';
  $('favicon').href = dg ? 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#333"/><text x="32" y="44" font-size="34" text-anchor="middle" fill="#ff9f0a">=</text></svg>') : 'icons/icon-32.png';
  $('calc').classList.toggle('hidden', !dg);
  $('lock').classList.toggle('hidden', dg);
  if (dg) { calcExpr = ''; calcShow('0'); } else setupLock();
}
let lockMode = 'unlock';
function setupLock(mode) {
  const exists = !!localStorage.getItem(VKEY);
  lockMode = !exists ? 'create' : (mode || 'unlock');
  $('pin').value = ''; $('pin2').value = ''; $('rec').value = '';
  $('rec').classList.toggle('hidden', lockMode !== 'recover');
  $('pin2').classList.toggle('hidden', lockMode === 'unlock');
  $('pin').placeholder = lockMode === 'unlock' ? 'PIN' : 'New PIN (6+ digits)';
  $('lockMsg').textContent = { create: 'Create a PIN (6+ digits). It encrypts everything on this device.', unlock: 'Enter your PIN to unlock', recover: 'Enter your recovery key and choose a new PIN' }[lockMode];
  $('pinBtn').textContent = { create: 'Create vault', unlock: 'Unlock', recover: 'Reset PIN & unlock' }[lockMode];
  $('forgotBtn').classList.toggle('hidden', lockMode === 'create');
  $('forgotBtn').textContent = lockMode === 'recover' ? '← Back to PIN' : 'Forgot PIN? Use recovery key';
  const f = +(localStorage.getItem(FKEY) || 0);
  $('lockHint').textContent = lockMode !== 'create' && f ? `${f} wrong attempt(s)` : lockMode === 'create' ? 'You will get a recovery key in case you forget the PIN.' : '';
  setTimeout(() => (lockMode === 'recover' ? $('rec') : $('pin')).focus(), 50);
}
$('forgotBtn').onclick = () => setupLock(lockMode === 'recover' ? 'unlock' : 'recover');
async function failedAttempt(what) {
  const f = +(localStorage.getItem(FKEY) || 0) + 1;
  localStorage.setItem(FKEY, String(f));
  const wipe10 = localStorage.getItem('kavach_w10') !== '0';
  if (f >= 10 && wipe10) { await wipeAll(); throw new Error('wiped'); }
  await sleep(Math.min(8000, 400 * 2 ** Math.max(0, f - 3)));
  throw new Error(`Wrong ${what} (${f}/10)`);
}
function afterUnlock(code) {
  $('lock').classList.add('hidden'); $('calc').classList.add('hidden'); $('app').classList.remove('hidden');
  document.body.classList.remove('dg'); document.title = 'Kavach'; $('favicon').href = 'icons/icon-32.png';
  if (ST.set.disguise) localStorage.setItem('kavach_dg', '1'); else localStorage.removeItem('kavach_dg');
  applyTheme(); render(); connect(); updSend();
  if (code) showRecovery(code);
  const hashInv = parseInvite(location.hash) && location.hash;
  if (hashInv) { history.replaceState(null, '', location.pathname); setTimeout(() => showJoin(location.origin + location.pathname + hashInv), code ? 0 : 700); }
}
$('pinForm').onsubmit = async (e) => {
  e.preventDefault();
  const pin = $('pin').value;
  $('pinBtn').disabled = true;
  let code = null;
  try {
    if (lockMode === 'create') {
      if (!/^\d{6,32}$/.test(pin) || pin !== $('pin2').value) throw new Error('PINs must match (6+ digits)');
      code = await vaultCreate(pin);
    } else if (lockMode === 'recover') {
      if (!/^\d{6,32}$/.test(pin) || pin !== $('pin2').value) throw new Error('New PINs must match (6+ digits)');
      try { await recoverWith($('rec').value, pin); localStorage.removeItem(FKEY); toast('✅ PIN reset — chats restored'); }
      catch (err) { await failedAttempt('recovery key'); }
    } else {
      try { code = await vaultOpen(pin); localStorage.removeItem(FKEY); }
      catch (err) { await failedAttempt('PIN'); }
    }
    afterUnlock(code);
  } catch (err) {
    $('lockHint').textContent = err.message; $('pin').value = '';
    $('lockMsg').parentNode.classList.add('shake'); setTimeout(() => $('lockMsg').parentNode.classList.remove('shake'), 450);
  } finally { $('pinBtn').disabled = false; }
};

/* calculator: fully working; "<PIN>=" unlocks; long-press "=" shows the normal lock screen */
let calcExpr = '', calcBusy = false;
function calcShow(s) { $('calcDisp').textContent = s; }
function calcEval(expr) {
  const tok = expr.match(/\d+\.?\d*|\.\d+|[-+*/()]/g); if (!tok) return NaN;
  let i = 0;
  const peek = () => tok[i], next = () => tok[i++];
  const factor = () => { const t = next(); if (t === '(') { const v = sum(); next(); return v; } if (t === '-') return -factor(); return parseFloat(t); };
  const prod = () => { let v = factor(); while (peek() === '*' || peek() === '/') { const o = next(), r = factor(); v = o === '*' ? v * r : v / r; } return v; };
  const sum = () => { let v = prod(); while (peek() === '+' || peek() === '-') { const o = next(), r = prod(); v = o === '+' ? v + r : v - r; } return v; };
  try { const v = sum(); return i === tok.length ? v : NaN; } catch (e) { return NaN; }
}
async function calcKey(k) {
  if (calcBusy) return;
  if (k === 'C') { calcExpr = ''; return calcShow('0'); }
  if (k === 'B') { calcExpr = calcExpr.slice(0, -1); return calcShow(calcExpr || '0'); }
  if (k !== '=') { if (calcExpr.length < 40) calcExpr += k; return calcShow(calcExpr.replace(/\*/g, '×').replace(/\//g, '÷')); }
  const ex = calcExpr;
  if (/^\d{6,32}$/.test(ex)) {
    calcBusy = true; calcShow(ex);
    try { const code = await vaultOpen(ex); localStorage.removeItem(FKEY); calcBusy = false; calcExpr = ''; return afterUnlock(code); }
    catch (e) { try { await failedAttempt('PIN'); } catch (e2) {} calcBusy = false; calcExpr = ex; return calcShow(ex); }
  }
  const v = calcEval(ex);
  calcExpr = isFinite(v) ? String(+v.toFixed(10)) : '';
  calcShow(isFinite(v) ? calcExpr : 'Error');
}
$('calcKeys').onclick = (e) => { const b = e.target.closest('[data-k]'); if (b) calcKey(b.dataset.k); };
let eqT = null;
$('calcKeys').addEventListener('pointerdown', (e) => { if (e.target.closest('[data-k="="]')) eqT = setTimeout(() => { eqT = null; $('calc').classList.add('hidden'); $('lock').classList.remove('hidden'); setupLock(); }, 1500); });
['pointerup', 'pointerleave'].forEach((ev) => $('calcKeys').addEventListener(ev, () => clearTimeout(eqT)));
document.addEventListener('keydown', (e) => { if ($('calc').classList.contains('hidden')) return; const map = { Enter: '=', Backspace: 'B', Escape: 'C' }; const k = map[e.key] || (/^[0-9+\-*/().=]$/.test(e.key) ? e.key : null); if (k) { e.preventDefault(); calcKey(k); } });

showLockScreen();

/* debug hook for automated tests only when ?test=1 */
if (/[?&]test=1/.test(location.search)) window.__kv = { get ST() { return ST; }, get slot() { return slot; }, get mode() { return lockMode; }, invites, rooms, parseInvite, inviteLink, get invCur() { return invCur; }, emojiCount: async () => (await loadEmoji()).reduce((n, g) => n + g[1].length, 0), shareOut: (i) => shareOut(ST.contacts[cur].msgs[i]), sendFile: (blob, name, type) => sendFile(ST.contacts[cur], blob, name, type, 0) };
})();
