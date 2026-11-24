'use strict';
/*
 * Kavach relay server — a "blind mailbox" relay.
 *
 *  - No accounts, no user IDs, no phone numbers, no names.
 *  - Clients create mailboxes from a secret random "receive id" (rid).
 *    The server only stores sid = SHA-256(rid). Anyone may PUT to a sid,
 *    only the holder of rid can SUBSCRIBE / read / delete it.
 *  - Everything the server relays is already end-to-end encrypted and padded
 *    by the clients. The server never sees keys, plaintext, SDP or names.
 *  - Nothing is written to disk. No request/IP/mailbox logging.
 *  - Invite mailboxes are single-use and expire (max 10 minutes).
 *  - Queued messages are deleted as soon as the recipient acknowledges them,
 *    or after QUEUE_TTL even if never fetched.
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const env = process.env;
const list = (v) => (v || '').split(',').map((s) => s.trim()).filter(Boolean);
const CFG = {
  host: env.HOST || '0.0.0.0',
  port: +env.PORT || 8443,
  tlsCert: env.TLS_CERT || '',
  tlsKey: env.TLS_KEY || '',
  allowInsecure: env.ALLOW_INSECURE === '1',      // dev only (localhost testing)
  origins: list(env.ALLOWED_ORIGINS),             // e.g. https://192.168.1.50:8443
  turnSecret: env.TURN_SECRET || '',              // same as coturn static-auth-secret
  turnUrls: list(env.TURN_URLS),                  // turns:nuc.lan:5349?transport=tcp,turn:nuc.lan:3478
  stunUrls: list(env.STUN_URLS),                  // stun:nuc.lan:3478
  turnTtl: 3600,                                  // TURN credential lifetime (s)
  maxMsg: 64 * 1024,                              // max envelope size (bytes)
  maxQueue: 500,                                  // max queued envelopes per mailbox
  queueTtl: 7 * 24 * 3600e3,                      // undelivered envelopes die after 7 days
  boxIdle: 30 * 24 * 3600e3,                      // idle mailboxes die after 30 days
  inviteMax: 10 * 60e3,                           // invite mailbox max lifetime
  maxBoxes: 200000,
  maxSubsPerConn: 1000,
  rate: { perSec: 100, burst: 400 },
  maxConns: 5000,
  trustProxy: env.TRUST_PROXY === '1',
  accessKey: env.ACCESS_KEY || '',                // private server mode: only devices with this key may connect
  reportsToCooldown: 3,                           // 3 reports from different people within 1 h ...
  cooldownMs: 60 * 60e3,                          // ... => that network can't use Random Connect for 1 h
};

/* ---------------- static files ---------------- */
const PUB = path.join(__dirname, 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json', '.webmanifest': 'application/manifest+json' };
const CSP = [
  "default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self' data: blob:",
  "media-src 'self' blob:", "connect-src 'self' wss: ws:", "font-src 'self'", "manifest-src 'self'",
  "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'", "object-src 'none'",
].join('; ');
function secHeaders(res, tls) {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(self), microphone=(self), geolocation=(), payment=(), usb=(), interest-cohort=()');
  res.setHeader('Cache-Control', 'no-store');
  if (tls) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}
function onRequest(req, res) {
  const tls = !!req.socket.encrypted;
  secHeaders(res, tls);
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  let p;
  try { p = decodeURIComponent(new URL(req.url, 'http://x').pathname); } catch { res.writeHead(400); return res.end(); }
  if (p === '/' || p === '') p = '/index.html';
  const file = path.normalize(path.join(PUB, p));
  if (!file.startsWith(PUB + path.sep)) { res.writeHead(403); return res.end(); }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Content-Length': st.size });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
}

let server;
if (CFG.tlsCert && CFG.tlsKey) {
  server = https.createServer({ cert: fs.readFileSync(CFG.tlsCert), key: fs.readFileSync(CFG.tlsKey), minVersion: 'TLSv1.2' }, onRequest);
} else if (CFG.allowInsecure) {
  server = http.createServer(onRequest);
  console.warn('[kavach] WARNING: running WITHOUT TLS (ALLOW_INSECURE=1). Use only on localhost for testing.');
} else {
  console.error('[kavach] TLS_CERT and TLS_KEY are required (or ALLOW_INSECURE=1 for localhost testing).');
  process.exit(1);
}

/* ---------------- mailboxes ---------------- */
const B64U = /^[A-Za-z0-9_-]{43}$/;                 // 32 random bytes, base64url
const sidOf = (rid) => crypto.createHash('sha256').update('kavach-sid|' + rid).digest('base64url');
const boxes = new Map();                            // sid -> box
// box = { once, exp, used, q: [{id, d, t}], sub: ws|null, touched }

function getBox(sid) {
  const b = boxes.get(sid);
  if (!b) return null;
  const now = Date.now();
  if ((b.exp && now > b.exp) || now - b.touched > CFG.boxIdle) { dropBox(sid); return null; }
  return b;
}
function dropBox(sid) {
  const b = boxes.get(sid);
  if (!b) return;
  if (b.sub) { b.sub.subs.delete(sid); send(b.sub, { op: 'gone', sid }); }
  b.q.length = 0;
  boxes.delete(sid);
}
function deliver(sid, b) {
  if (!b.sub || b.sub.readyState !== 1) return;
  for (const m of b.q) if (!m.sent) { m.sent = true; send(b.sub, { op: 'msg', sid, id: m.id, d: m.d }); }
}
function send(ws, obj) { if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj)); }

setInterval(() => {                                 // sweeper
  const now = Date.now();
  for (const [sid, b] of boxes) {
    if ((b.exp && now > b.exp) || now - b.touched > CFG.boxIdle) { dropBox(sid); continue; }
    if (b.q.length) b.q = b.q.filter((m) => now - m.t < CFG.queueTtl);
  }
}, 15e3).unref();

/* ---------------- TURN credentials (coturn use-auth-secret / REST API) ---------------- */
function iceServers() {
  const out = [];
  if (CFG.stunUrls.length) out.push({ urls: CFG.stunUrls });
  if (CFG.turnSecret && CFG.turnUrls.length) {
    const username = (Math.floor(Date.now() / 1000) + CFG.turnTtl) + ':' + crypto.randomBytes(8).toString('hex');
    const credential = crypto.createHmac('sha1', CFG.turnSecret).update(username).digest('base64');
    out.push({ urls: CFG.turnUrls, username, credential });
  }
  return out;
}

/* ---------------- websocket ---------------- */
const wss = new WebSocketServer({
  server, path: '/ws', maxPayload: CFG.maxMsg + 2048, perMessageDeflate: false,
  verifyClient: (info, cb) => {
    if (wss.clients.size >= CFG.maxConns) return cb(false, 503);
    if (CFG.origins.length && !CFG.origins.includes(info.origin)) return cb(false, 403);
    if (CFG.accessKey) {
      let k = '';
      try { k = new URL(info.req.url, 'http://x').searchParams.get('k') || ''; } catch {}
      const h = (v) => crypto.createHash('sha256').update(String(v)).digest();
      if (!crypto.timingSafeEqual(h(k), h(CFG.accessKey))) return setTimeout(() => cb(false, 401), 300 + Math.random() * 400);
    }
    cb(true);
  },
});

const IP_SALT = crypto.randomBytes(16);            // per-boot salt: raw IPs are never stored
const ipHash = (ip) => crypto.createHmac('sha256', IP_SALT).update(String(ip || '')).digest('base64url').slice(0, 16);
wss.on('connection', (ws, req) => {
  ws.ip = ipHash((req.headers['x-forwarded-for'] && CFG.trustProxy ? String(req.headers['x-forwarded-for']).split(',')[0] : req.socket.remoteAddress));
  ws.subs = new Set();
  ws.alive = true;
  ws.tokens = CFG.rate.burst;
  ws.last = Date.now();
  ws.on('pong', () => { ws.alive = true; });
  ws.on('message', (raw, isBinary) => {
    // token-bucket rate limit
    const now = Date.now();
    ws.tokens = Math.min(CFG.rate.burst, ws.tokens + ((now - ws.last) / 1000) * CFG.rate.perSec);
    ws.last = now;
    if (ws.tokens < 1) return send(ws, { op: 'err', e: 'rate' });
    ws.tokens -= 1;
    if (isBinary) return;
    let m;
    try { m = JSON.parse(raw.toString('utf8')); } catch { return send(ws, { op: 'err', e: 'json' }); }
    if (!m || typeof m !== 'object') return;
    try { handle(ws, m); } catch { send(ws, { op: 'err', e: 'bad', r: m.r }); }
  });
  ws.on('close', () => {
    unqueue(ws);
    for (const sid of ws.subs) { const b = boxes.get(sid); if (b && b.sub === ws) { b.sub = null; for (const q of b.q) q.sent = false; } }
    ws.subs.clear();
  });
  ws.on('error', () => {});
});

/* ---------------- Random Connect matchmaker ----------------
 * Clients send a fresh one-time public key + a fresh mailbox id, plus a self-declared
 * gender ('m'/'f'). The server only pairs m<->f and hands each side the other's key + mailbox.
 * It never sees messages. Reports put the reported side's (salted, hashed) network on cooldown. */
const queue = [];                                   // waiting entries
const matches = new Map();                          // mid -> {a, b, ipa, ipb, t}
const reports = new Map();                          // ipHash -> [{t, by}]
const cooldown = new Map();                         // ipHash -> until
function unqueue(ws) { for (let i = queue.length - 1; i >= 0; i--) if (queue[i].ws === ws) queue.splice(i, 1); }
function onCooldown(ip) { const u = cooldown.get(ip); if (u && u > Date.now()) return true; cooldown.delete(ip); return false; }
setInterval(() => {
  const t = Date.now();
  for (const [k, v] of matches) if (t - v.t > 6 * 3600e3) matches.delete(k);
  for (const [k, v] of reports) { const f = v.filter((r) => t - r.t < 3600e3); f.length ? reports.set(k, f) : reports.delete(k); }
  for (const [k, u] of cooldown) if (u < t) cooldown.delete(k);
}, 60e3).unref();

function handle(ws, m) {
  const r = m.r; // client request id, echoed back
  const ok = (extra) => send(ws, Object.assign({ op: 'ok', r }, extra || {}));
  const err = (e) => send(ws, { op: 'err', r, e });
  switch (m.op) {
    case 'new': { // create mailbox from secret rid
      if (!B64U.test(m.rid || '')) return err('rid');
      if (boxes.size >= CFG.maxBoxes) return err('full');
      const sid = sidOf(m.rid);
      if (boxes.has(sid)) return err('exists');
      const once = !!m.once;
      const ttl = Math.max(10e3, Math.min(+m.ttl || CFG.inviteMax, CFG.inviteMax));
      boxes.set(sid, { once, exp: once ? Date.now() + ttl : 0, used: false, q: [], sub: null, touched: Date.now() });
      return ok({ sid });
    }
    case 'sub': { // subscribe (proves knowledge of rid)
      if (!B64U.test(m.rid || '')) return err('rid');
      const sid = sidOf(m.rid);
      const b = getBox(sid);
      if (!b) return err('nobox');
      if (ws.subs.size >= CFG.maxSubsPerConn && !ws.subs.has(sid)) return err('subs');
      if (b.sub && b.sub !== ws) { b.sub.subs.delete(sid); for (const q of b.q) q.sent = false; }
      b.sub = ws; ws.subs.add(sid); b.touched = Date.now();
      ok({ sid });
      return deliver(sid, b);
    }
    case 'ack': { // recipient confirms receipt -> envelope deleted
      if (!B64U.test(m.rid || '')) return err('rid');
      const sid = sidOf(m.rid);
      const b = getBox(sid);
      if (!b) return;
      b.q = b.q.filter((x) => x.id !== m.id);
      if (b.once && b.used && !b.q.length) dropBox(sid);   // invite fully consumed
      return;
    }
    case 'put': { // anyone who knows sid may drop an (encrypted) envelope
      if (!B64U.test(m.sid || '') || typeof m.d !== 'string') return err('arg');
      if (Buffer.byteLength(m.d) > CFG.maxMsg) return err('size');
      const b = getBox(m.sid);
      if (!b) return err('nobox');
      if (b.once && b.used) return err('used');               // single-use invite
      if (b.q.length >= CFG.maxQueue) return err('qfull');
      if (b.once) b.used = true;
      b.touched = Date.now();
      b.q.push({ id: crypto.randomBytes(9).toString('base64url'), d: m.d, t: Date.now(), sent: false });
      ok();
      return deliver(m.sid, b);
    }
    case 'del': { // recipient deletes own mailbox
      if (!B64U.test(m.rid || '')) return err('rid');
      dropBox(sidOf(m.rid));
      return ok();
    }
    case 'rq': { // join Random Connect queue
      if (!['m', 'f'].includes(m.g) || typeof m.pub !== 'string' || m.pub.length > 120 || !B64U.test(m.sid || '') || !getBox(m.sid)) return err('arg');
      if (onCooldown(ws.ip)) return err('cooldown');
      ws.rqTimes = (ws.rqTimes || []).filter((t) => Date.now() - t < 60e3);
      if (ws.rqTimes.length >= 20) return err('rate');
      ws.rqTimes.push(Date.now());
      unqueue(ws);
      const want = m.g === 'm' ? 'f' : 'm';
      const i = queue.findIndex((q) => q.g === want && q.ws !== ws && q.ws.readyState === 1);
      if (i < 0) { queue.push({ ws, g: m.g, pub: m.pub, sid: m.sid }); return ok({ queued: true }); }
      const p = queue.splice(i, 1)[0];
      const mid = crypto.randomBytes(12).toString('base64url');
      matches.set(mid, { a: ws, b: p.ws, ipa: ws.ip, ipb: p.ws.ip, t: Date.now() });
      ok({ queued: false });
      send(ws, { op: 'match', mid, pub: p.pub, sid: p.sid });
      send(p.ws, { op: 'match', mid, pub: m.pub, sid: m.sid });
      return;
    }
    case 'rqx': unqueue(ws); return ok();
    case 'rep': { // report the person you are matched with
      const x = matches.get(m.mid);
      if (!x || (x.a !== ws && x.b !== ws)) return err('nomatch');
      const target = x.a === ws ? x.ipb : x.ipa;
      if (target === ws.ip) return ok();
      const list = (reports.get(target) || []).filter((r) => r.by !== ws.ip);
      list.push({ t: Date.now(), by: ws.ip }); reports.set(target, list);
      if (list.length >= CFG.reportsToCooldown) cooldown.set(target, Date.now() + CFG.cooldownMs);
      matches.delete(m.mid);
      return ok();
    }
    case 'ice': return ok({ ice: iceServers() });
    case 'ping': return ok();
    default: return err('op');
  }
}

setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.alive) { ws.terminate(); continue; }
    ws.alive = false;
    try { ws.ping(); } catch {}
  }
}, 25e3).unref();

server.listen(CFG.port, CFG.host, () => {
  console.log(`[kavach] relay listening on ${CFG.tlsCert ? 'https' : 'http'}://${CFG.host}:${CFG.port}  (no logs, memory-only${CFG.accessKey ? ', PRIVATE mode' : ''})`);
});
