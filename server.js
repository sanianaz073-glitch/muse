// AllWA multi-user WhatsApp panel engine — Baileys 6.7.24 + Express
// Accounts + multi-session numbers + real messaging APIs + panel frontend.
// Port 8791. Egress goes through the HTTP proxy from env (HttpsProxyAgent),
// otherwise WhatsApp sockets die with 408 in this VM.
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import QRCode from 'qrcode';
import pino from 'pino';
import makeWASocket, {
  useMultiFileAuthState,
  DisconnectReason,
  fetchLatestBaileysVersion,
  BufferJSON,
  initAuthCreds,
} from '@whiskeysockets/baileys';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { MongoClient } from 'mongodb';

const PROXY = process.env.https_proxy || process.env.HTTPS_PROXY || process.env.all_proxy || '';
const proxyAgent = PROXY ? new HttpsProxyAgent(PROXY) : undefined;
if (proxyAgent) console.log('[allwa] using egress proxy for WhatsApp sockets');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8791;
const DATA_DIR = path.join(__dirname, 'data');
const AUTH_ROOT = path.join(__dirname, 'auth');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(AUTH_ROOT, { recursive: true });

/* --------------------- MongoDB persistence (optional) --------------------- */
// When MONGODB_URI is set (e.g. on Render's free tier with an ephemeral disk),
// Baileys auth state (creds + keys) for every session lives in MongoDB, one
// collection per numberId, and users/numbers/tokens/stores are mirrored there
// too. Without MONGODB_URI everything stays in local files, unchanged.
const MONGODB_URI = process.env.MONGODB_URI || '';
let mongoDb = null;
let mongoPromise = null;
function getMongo() {
  if (!MONGODB_URI) return Promise.resolve(null);
  if (mongoDb) return Promise.resolve(mongoDb);
  if (!mongoPromise) {
    mongoPromise = new MongoClient(MONGODB_URI).connect()
      .then((c) => { mongoDb = c.db(); console.log('[allwa] MongoDB connected (auth + data persistence)'); return mongoDb; })
      .catch((e) => { console.error('[allwa] MongoDB connect failed:', e?.message || e); mongoPromise = null; return null; });
  }
  return mongoPromise;
}
function mongoMirror(collection, docId, value) {
  if (!MONGODB_URI) return;
  getMongo().then((db) => {
    if (db) return db.collection(collection).updateOne({ _id: docId }, { $set: { value: JSON.stringify(value, BufferJSON.replacer) } }, { upsert: true });
  }).catch(() => { /* mirror is best-effort */ });
}
async function useMongoAuthState(numId) {
  const db = await getMongo();
  if (!db) return null;
  const col = db.collection('auth_' + String(numId).replace(/[^a-zA-Z0-9_-]/g, '_'));
  const writeData = (keyId, value) => col.updateOne({ _id: keyId }, { $set: { value: JSON.stringify(value, BufferJSON.replacer) } }, { upsert: true });
  const readData = async (keyId) => {
    const doc = await col.findOne({ _id: keyId });
    return doc ? JSON.parse(doc.value, BufferJSON.reviver) : null;
  };
  const removeData = (keyId) => col.deleteOne({ _id: keyId });
  let creds = await readData('creds');
  if (!creds) { creds = initAuthCreds(); await writeData('creds', creds); }
  return {
    state: {
      creds,
      keys: {
        get: async (type, ids) => {
          const data = {};
          await Promise.all(ids.map(async (oneId) => {
            const v = await readData(`key:${type}:${oneId}`);
            if (v) data[oneId] = v;
          }));
          return data;
        },
        set: async (data) => {
          const tasks = [];
          for (const type in data) {
            for (const oneId in data[type]) {
              const v = data[type][oneId];
              tasks.push(v ? writeData(`key:${type}:${oneId}`, v) : removeData(`key:${type}:${oneId}`));
            }
          }
          await Promise.all(tasks);
        },
      },
    },
    saveCreds: () => writeData('creds', creds),
  };
}
async function restoreFromMongo() {
  if (!MONGODB_URI) return;
  const db = await getMongo();
  if (!db) return;
  try {
    const meta = db.collection('allwa_meta');
    const get = async (docId) => { const d = await meta.findOne({ _id: docId }); return d ? JSON.parse(d.value, BufferJSON.reviver) : null; };
    const mu = await get('users'); if (Array.isArray(mu) && mu.length) { users = mu; writeJson(USERS_FILE, users); }
    const mn = await get('numbers'); if (Array.isArray(mn)) { numbers = mn; writeJson(NUMBERS_FILE, numbers); }
    const mt = await get('tokens'); if (mt && typeof mt === 'object') { tokens = mt; writeJson(TOKENS_FILE, tokens); }
    const stores = await db.collection('allwa_stores').find({}).toArray();
    for (const s of stores) { try { fs.writeFileSync(path.join(DATA_DIR, s._id + '.json'), s.value); } catch { /* ignore */ } }
    const panels = await db.collection('allwa_panels').find({}).toArray();
    for (const p of panels) { try { fs.writeFileSync(path.join(DATA_DIR, 'panel-' + p._id + '.json'), p.value); } catch { /* ignore */ } }
    console.log('[allwa] restored from MongoDB: users', users.length, 'numbers', numbers.length);
  } catch (e) { console.error('[allwa] Mongo restore failed:', e?.message || e); }
}

const readJson = (file, fallback) => {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
};
const writeJson = (file, obj) => {
  try { fs.writeFileSync(file, JSON.stringify(obj)); } catch { /* ignore */ }
};
const id = (p) => p + crypto.randomBytes(8).toString('hex');

/* ------------------------------ users / auth ------------------------------ */
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const NUMBERS_FILE = path.join(DATA_DIR, 'numbers.json');
const TOKENS_FILE = path.join(DATA_DIR, 'tokens.json');
let users = readJson(USERS_FILE, []);
let numbers = readJson(NUMBERS_FILE, []);
let tokens = readJson(TOKENS_FILE, {}); // token -> userId
const saveUsers = () => { writeJson(USERS_FILE, users); mongoMirror('allwa_meta', 'users', users); };
const saveNumbers = () => { writeJson(NUMBERS_FILE, numbers); mongoMirror('allwa_meta', 'numbers', numbers); };
const saveTokens = () => { writeJson(TOKENS_FILE, tokens); mongoMirror('allwa_meta', 'tokens', tokens); };

function hashPass(pass) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(pass), salt, 64).toString('hex');
  return salt + ':' + hash;
}
function checkPass(pass, stored) {
  try {
    const [salt, hash] = String(stored).split(':');
    const got = crypto.scryptSync(String(pass), salt, 64);
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), got);
  } catch { return false; }
}
function newToken(userId) {
  const t = crypto.randomBytes(32).toString('hex');
  tokens[t] = userId;
  saveTokens();
  return t;
}
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, phone: u.phone || '', isAdmin: !!u.isAdmin });

function authUser(req) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : (req.query.token || '');
  const uid = t && tokens[t];
  return users.find((u) => u.id === uid) || null;
}
function requireAuth(req, res, next) {
  const u = authUser(req);
  if (!u) return res.status(401).json({ ok: false, error: 'login' });
  req.user = u;
  next();
}

/* --------------------------- per-number data store --------------------------- */
function loadStore(numId) {
  const d = readJson(path.join(DATA_DIR, numId + '.json'), {});
  return {
    me: d.me || null,
    chats: new Map((d.chats || []).map((c) => [c.jid, c])),
    msgs: new Map(Object.entries(d.msgs || {})),
    calls: d.calls || [],
    statuses: d.statuses || [],
    broadcasts: d.broadcasts || [],
  };
}
function persistStore(numId, store) {
  const data = {
    me: store.me,
    chats: [...store.chats.values()],
    msgs: Object.fromEntries([...store.msgs.entries()].map(([k, v]) => [k, v.slice(-200)])),
    calls: store.calls.slice(-200),
    statuses: store.statuses.slice(-100),
    broadcasts: store.broadcasts,
  };
  writeJson(path.join(DATA_DIR, numId + '.json'), data);
  if (MONGODB_URI) {
    getMongo().then((db) => {
      if (db) return db.collection('allwa_stores').updateOne({ _id: numId }, { $set: { value: JSON.stringify(data) } }, { upsert: true });
    }).catch(() => { /* best-effort */ });
  }
}

/* --------------------------- per-user panel store --------------------------- */
// labels, notes, chat-label assignments — simple JSON per user
function loadPanel(userId) {
  const d = readJson(path.join(DATA_DIR, 'panel-' + userId + '.json'), {});
  return { labels: d.labels || [], notes: d.notes || {}, chatLabels: d.chatLabels || {} };
}
function savePanel(userId, p) {
  writeJson(path.join(DATA_DIR, 'panel-' + userId + '.json'), p);
  if (MONGODB_URI) {
    getMongo().then((db) => {
      if (db) return db.collection('allwa_panels').updateOne({ _id: userId }, { $set: { value: JSON.stringify(p) } }, { upsert: true });
    }).catch(() => { /* best-effort */ });
  }
}

/* ------------------------------ WA sessions ------------------------------ */
const sessions = new Map(); // numberId -> session

function msgText(m) {
  const x = m.message || {};
  return x.conversation || x.extendedTextMessage?.text || x.imageMessage?.caption ||
    x.videoMessage?.caption || (x.imageMessage ? '📷 Photo' : '') ||
    (x.audioMessage ? '🎤 Voice note' : '') || (x.stickerMessage ? 'Sticker' : '') ||
    (x.documentMessage ? '📄 ' + (x.documentMessage.fileName || 'Document') : '') || '';
}
// keep only JSON-safe parts of a raw message (for quote/react/delete keys)
function sanitizeRaw(m) {
  try {
    return JSON.parse(JSON.stringify(m, (k, v) => {
      if (v && typeof v === 'object' && v.type === 'Buffer') return undefined;
      if (v instanceof Uint8Array) return undefined;
      return v;
    }));
  } catch { return { key: m.key, message: m.message }; }
}

function emitTo(session, event, data) {
  const line = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of session.clients) { try { res.write(line); } catch { /* drop */ } }
}
function setStatus(session, status) {
  session.status = status;
  const rec = numbers.find((n) => n.id === session.numId);
  if (rec) { rec.status = status; if (session.store.me) rec.me = session.store.me; saveNumbers(); }
  emitTo(session, 'status', { status, me: session.store.me });
}

function upsertChat(session, c) {
  if (!c.id) return;
  const old = session.store.chats.get(c.id) || { jid: c.id, unread: 0 };
  session.store.chats.set(c.id, {
    ...old,
    jid: c.id,
    name: c.name || old.name || c.id.split('@')[0],
    lastTs: c.conversationTimestamp ? Number(c.conversationTimestamp) : old.lastTs,
    unread: c.unreadCount ?? old.unread ?? 0,
  });
}

function addMsg(session, m, { history = false } = {}) {
  const jid = m.key?.remoteJid;
  if (!jid || !m.message) return;
  if (jid === 'status@broadcast') {
    const item = { id: m.key.id, author: m.key.participant || m.participant || '', pushName: m.pushName || '', text: msgText(m), ts: Number(m.messageTimestamp || 0) || Math.floor(Date.now() / 1000) };
    if (item.text && !session.store.statuses.some((s) => s.id === item.id)) {
      session.store.statuses.push(item);
      session.store.statuses = session.store.statuses.slice(-100);
      session.persistSoon();
    }
    return;
  }
  const arr = session.store.msgs.get(jid) || [];
  const item = {
    id: m.key.id,
    fromMe: !!m.key.fromMe,
    participant: m.key.participant || null,
    text: msgText(m),
    ts: (m.messageTimestamp ? Number(m.messageTimestamp) : Math.floor(Date.now() / 1000)),
    raw: sanitizeRaw(m),
  };
  if (!arr.some((a) => a.id === item.id)) arr.push(item);
  arr.sort((a, b) => a.ts - b.ts);
  session.store.msgs.set(jid, arr.slice(-300));
  const c = session.store.chats.get(jid) || { jid, name: m.pushName || jid.split('@')[0], unread: 0 };
  if (item.ts >= (c.lastTs || 0)) { c.lastText = item.text; c.lastTs = item.ts; }
  if (!item.fromMe && !history) c.unread = (c.unread || 0) + 1;
  if (m.pushName && !item.fromMe) c.name = m.pushName;
  session.store.chats.set(jid, c);
  if (!history) emitTo(session, 'message', { jid, msg: { id: item.id, fromMe: item.fromMe, text: item.text, ts: item.ts } });
  session.persistSoon();
}

function getSession(numId) { return sessions.get(numId); }

async function startSession(rec) {
  let session = sessions.get(rec.id);
  if (session?.starting || session?.sock) return session;
  if (!session) {
    session = {
      numId: rec.id, userId: rec.userId, sock: null, starting: false, dead: false,
      status: 'starting', qr: null, qrAt: 0, store: loadStore(rec.id),
      clients: new Set(), saveTimer: null,
      persistSoon() {
        clearTimeout(this.saveTimer);
        this.saveTimer = setTimeout(() => persistStore(this.numId, this.store), 500);
      },
    };
    sessions.set(rec.id, session);
  }
  session.dead = false;
  session.starting = true;
  setStatus(session, session.qr ? 'qr' : 'connecting');
  try {
    const authDir = path.join(AUTH_ROOT, rec.id);
    fs.mkdirSync(authDir, { recursive: true });
    let authState = null;
    if (MONGODB_URI) { try { authState = await useMongoAuthState(rec.id); } catch { authState = null; } }
    if (!authState) authState = await useMultiFileAuthState(authDir);
    const { state, saveCreds } = authState;
    const { version } = await fetchLatestBaileysVersion().catch(() => ({ version: undefined }));
    const sock = makeWASocket({
      auth: state,
      version,
      agent: proxyAgent,
      fetchAgent: proxyAgent,
      logger: pino({ level: 'silent' }),
      browser: ['AllWA Panel', 'Chrome', '1.0.0'],
      markOnlineOnConnect: false,
      syncFullHistory: true,
      shouldSyncHistoryMessage: () => true,
    });
    session.sock = sock;
    sock.ev.on('creds.update', saveCreds);
    sock.ev.on('connection.update', async (u) => {
      if (session.dead) return;
      const { connection, lastDisconnect, qr } = u;
      if (qr) {
        session.qr = qr;
        session.qrAt = Date.now();
        setStatus(session, 'qr');
        const qrFile = path.join(__dirname, 'qr-' + rec.id + '.png');
        await QRCode.toFile(qrFile, qr, { width: 512, margin: 2 }).catch(() => {});
        emitTo(session, 'qr', { at: session.qrAt });
        console.log('[allwa]', rec.id, 'QR ready');
      }
      if (connection === 'open') {
        session.qr = null;
        session.store.me = { id: sock.user.id, name: sock.user.name || null };
        rec.me = session.store.me;
        if (!rec.phone && sock.user.id) rec.phone = sock.user.id.split(':')[0].split('@')[0];
        saveNumbers();
        setStatus(session, 'connected');
        session.persistSoon();
        console.log('[allwa]', rec.id, 'CONNECTED as', sock.user.id);
      }
      if (connection === 'close') {
        const code = lastDisconnect?.error?.output?.statusCode;
        const loggedOut = code === DisconnectReason.loggedOut;
        session.sock = null;
        session.starting = false;
        setStatus(session, loggedOut ? 'logged_out' : 'closed');
        console.log('[allwa]', rec.id, 'closed, code', code, loggedOut ? '(logged out)' : '(will reconnect)');
        if (!loggedOut && !session.dead) setTimeout(() => startSession(rec), 3000);
      }
    });
    const onChats = (list) => { for (const c of list || []) upsertChat(session, c); session.persistSoon(); };
    sock.ev.on('chats.set', ({ chats }) => onChats(chats));
    sock.ev.on('chats.upsert', onChats);
    sock.ev.on('messaging-history.set', ({ chats, messages }) => {
      onChats(chats);
      for (const m of messages || []) addMsg(session, m, { history: true });
      session.persistSoon();
      console.log('[allwa]', rec.id, 'history sync: chats', session.store.chats.size);
    });
    sock.ev.on('contacts.upsert', (list) => {
      for (const ct of list || []) {
        if (!ct.id) continue;
        const name = ct.name || ct.notify;
        if (!name) continue;
        const c = session.store.chats.get(ct.id);
        if (c) { c.name = name; session.store.chats.set(ct.id, c); }
      }
      session.persistSoon();
    });
    sock.ev.on('messages.upsert', ({ messages, type }) => {
      for (const m of messages || []) addMsg(session, m, { history: type !== 'notify' });
    });
    sock.ev.on('call', (calls) => {
      for (const c of calls || []) {
        session.store.calls.push({
          id: c.id, from: c.from, status: c.status, isVideo: !!c.isVideo, isGroup: !!c.isGroup,
          ts: c.date ? Math.floor(new Date(c.date).getTime() / 1000) : Math.floor(Date.now() / 1000),
        });
      }
      session.store.calls = session.store.calls.slice(-200);
      session.persistSoon();
    });
  } catch (e) {
    console.error('[allwa]', rec.id, 'start failed', e?.message || e);
    session.starting = false;
    if (!session.dead) setTimeout(() => startSession(rec), 5000);
  }
  return session;
}

async function stopSession(rec, { logout = false } = {}) {
  const session = sessions.get(rec.id);
  if (!session) return;
  session.dead = true;
  try { if (logout && session.sock) await session.sock.logout(); } catch { /* ignore */ }
  try { session.sock?.end?.(new Error('stopped')); } catch { /* ignore */ }
  try { session.sock?.ws?.close(); } catch { /* ignore */ }
  session.sock = null;
  sessions.delete(rec.id);
}

/* --------------------------------- app --------------------------------- */
const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* auth */
app.post('/api/auth/signup', (req, res) => {
  const { name, email, pass, phone } = req.body || {};
  const em = String(email || '').trim().toLowerCase();
  if (!name || !em || !pass) return res.status(400).json({ ok: false, error: 'Name, email and password are required.' });
  if (String(pass).length < 8) return res.status(400).json({ ok: false, error: 'Password must be at least 8 characters.' });
  if (users.some((u) => u.email === em)) return res.status(409).json({ ok: false, error: 'An account with this email already exists - please log in.' });
  const u = { id: id('u_'), name: String(name).slice(0, 120), email: em, passHash: hashPass(pass), phone: String(phone || ''), isAdmin: users.length === 0, createdAt: Date.now() };
  users.push(u);
  saveUsers();
  res.json({ ok: true, token: newToken(u.id), user: publicUser(u) });
});
app.post('/api/auth/login', (req, res) => {
  const { email, pass } = req.body || {};
  const em = String(email || '').trim().toLowerCase();
  const u = users.find((x) => x.email === em);
  if (!u || !checkPass(pass || '', u.passHash)) return res.status(401).json({ ok: false, error: 'Wrong email or password.' });
  res.json({ ok: true, token: newToken(u.id), user: publicUser(u) });
});
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ ok: true, user: publicUser(req.user) }));
app.post('/api/auth/logout', requireAuth, (req, res) => {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (t) { delete tokens[t]; saveTokens(); }
  res.json({ ok: true });
});
app.post('/api/auth/change-password', requireAuth, (req, res) => {
  const { current, next } = req.body || {};
  if (!checkPass(current || '', req.user.passHash)) return res.status(401).json({ ok: false, error: 'Current password is wrong.' });
  if (String(next || '').length < 8) return res.status(400).json({ ok: false, error: 'New password must be at least 8 characters.' });
  req.user.passHash = hashPass(next);
  saveUsers();
  res.json({ ok: true });
});

/* numbers */
const ownNumber = (req, res) => {
  const rec = numbers.find((n) => n.id === req.params.id);
  if (!rec || (rec.userId !== req.user.id && !req.user.isAdmin)) { res.status(404).json({ ok: false, error: 'Number not found.' }); return null; }
  return rec;
};
const publicNumber = (rec) => {
  const s = sessions.get(rec.id);
  return { id: rec.id, name: rec.name, phone: rec.phone || '', status: s ? s.status : rec.status || 'closed', me: s ? s.store.me : rec.me || null, chats: s ? s.store.chats.size : 0 };
};
app.get('/api/numbers', requireAuth, (req, res) => {
  res.json({ ok: true, numbers: numbers.filter((n) => n.userId === req.user.id || req.user.isAdmin).map(publicNumber) });
});
app.post('/api/numbers', requireAuth, async (req, res) => {
  const { name, phone } = req.body || {};
  const rec = { id: id('n_'), userId: req.user.id, name: String(name || 'WhatsApp number').slice(0, 80), phone: String(phone || '').replace(/\D/g, ''), status: 'starting', me: null, createdAt: Date.now() };
  numbers.push(rec);
  saveNumbers();
  await startSession(rec);
  res.json({ ok: true, number: publicNumber(rec) });
});
app.get('/api/numbers/:id/status', requireAuth, (req, res) => {
  const rec = ownNumber(req, res); if (!rec) return;
  res.json({ ok: true, ...publicNumber(rec) });
});
app.get('/api/numbers/:id/qr', requireAuth, async (req, res) => {
  const rec = ownNumber(req, res); if (!rec) return;
  const s = sessions.get(rec.id);
  if (!s) return res.json({ ok: true, status: rec.status || 'closed', qr: null });
  if (s.status === 'connected') return res.json({ ok: true, status: 'connected', me: s.store.me });
  if (!s.qr) return res.json({ ok: true, status: s.status, qr: null });
  const qrDataUrl = await QRCode.toDataURL(s.qr, { width: 512, margin: 2 }).catch(() => null);
  res.json({ ok: true, status: s.status, qr: s.qr, qrDataUrl, qrAt: s.qrAt });
});
app.get('/api/numbers/:id/qr.png', requireAuth, (req, res) => {
  const rec = ownNumber(req, res); if (!rec) return;
  const f = path.join(__dirname, 'qr-' + rec.id + '.png');
  if (fs.existsSync(f)) return res.sendFile(f);
  res.status(404).json({ ok: false, error: 'no qr yet' });
});
app.post('/api/numbers/:id/pair', requireAuth, async (req, res) => {
  const rec = ownNumber(req, res); if (!rec) return;
  const s = sessions.get(rec.id);
  try {
    if (!s?.sock) return res.status(409).json({ ok: false, error: 'Engine not ready.' });
    if (s.status === 'connected') return res.json({ ok: true, status: 'connected', me: s.store.me });
    const phone = String(req.body?.phone || rec.phone || '').replace(/\D/g, '');
    if (!phone) return res.status(400).json({ ok: false, error: 'Invalid WhatsApp number (e.g. 03001234567).' });
    const code = await s.sock.requestPairingCode(phone);
    res.json({ ok: true, code });
  } catch (e) { res.status(500).json({ ok: false, error: String(e?.message || e) }); }
});
app.post('/api/numbers/:id/reconnect', requireAuth, async (req, res) => {
  const rec = ownNumber(req, res); if (!rec) return;
  const s = sessions.get(rec.id);
  if (s && !s.sock && !s.starting) await startSession(rec);
  else if (!s) await startSession(rec);
  res.json({ ok: true, ...publicNumber(rec) });
});
app.delete('/api/numbers/:id', requireAuth, async (req, res) => {
  const rec = ownNumber(req, res); if (!rec) return;
  await stopSession(rec, { logout: true });
  fs.rmSync(path.join(AUTH_ROOT, rec.id), { recursive: true, force: true });
  fs.rmSync(path.join(DATA_DIR, rec.id + '.json'), { force: true });
  numbers = numbers.filter((n) => n.id !== rec.id);
  saveNumbers();
  res.json({ ok: true });
});

/* messaging */
const needConnected = (req, res) => {
  const rec = ownNumber(req, res); if (!rec) return null;
  const s = sessions.get(rec.id);
  if (!s?.sock || s.status !== 'connected') { res.status(409).json({ ok: false, error: 'WhatsApp line not connected.', status: s ? s.status : 'closed' }); return null; }
  return { rec, s };
};
app.get('/api/numbers/:id/chats', requireAuth, (req, res) => {
  const rec = ownNumber(req, res); if (!rec) return;
  const s = sessions.get(rec.id);
  const list = s ? [...s.store.chats.values()] : [];
  list.sort((a, b) => (b.lastTs || 0) - (a.lastTs || 0));
  res.json({ ok: true, chats: list });
});
app.get('/api/numbers/:id/chats/:jid/messages', requireAuth, (req, res) => {
  const rec = ownNumber(req, res); if (!rec) return;
  const s = sessions.get(rec.id);
  const jid = decodeURIComponent(req.params.jid);
  const msgs = (s?.store.msgs.get(jid) || []).map(({ raw, ...rest }) => rest);
  if (s) { const c = s.store.chats.get(jid); if (c && c.unread) { c.unread = 0; s.persistSoon(); } }
  res.json({ ok: true, messages: msgs });
});
app.post('/api/numbers/:id/send', requireAuth, async (req, res) => {
  const ctx = needConnected(req, res); if (!ctx) return;
  const { jid, text } = req.body || {};
  if (!jid || !text) return res.status(400).json({ ok: false, error: 'jid and text required' });
  try {
    const sent = await ctx.s.sock.sendMessage(jid, { text: String(text) });
    if (sent) addMsg(ctx.s, sent);
    res.json({ ok: true, id: sent?.key?.id });
  } catch (e) { res.status(500).json({ ok: false, error: String(e?.message || e) }); }
});
app.post('/api/numbers/:id/send-self', requireAuth, async (req, res) => {
  const ctx = needConnected(req, res); if (!ctx) return;
  const text = String(req.body?.text || '');
  if (!text) return res.status(400).json({ ok: false, error: 'text required' });
  try {
    const meId = ctx.s.store.me?.id || '';
    const jid = meId.split(':')[0].split('@')[0] + '@s.whatsapp.net';
    const sent = await ctx.s.sock.sendMessage(jid, { text });
    if (sent) addMsg(ctx.s, sent);
    res.json({ ok: true, id: sent?.key?.id, jid });
  } catch (e) { res.status(500).json({ ok: false, error: String(e?.message || e) }); }
});
app.post('/api/numbers/:id/reply', requireAuth, async (req, res) => {
  const ctx = needConnected(req, res); if (!ctx) return;
  const { jid, msgId, text } = req.body || {};
  if (!jid || !text) return res.status(400).json({ ok: false, error: 'jid and text required' });
  try {
    const arr = ctx.s.store.msgs.get(jid) || [];
    const orig = arr.find((a) => a.id === msgId);
    const opts = orig?.raw ? { quoted: orig.raw } : undefined;
    const sent = await ctx.s.sock.sendMessage(jid, { text: String(text) }, opts);
    if (sent) addMsg(ctx.s, sent);
    res.json({ ok: true, id: sent?.key?.id, quoted: !!opts });
  } catch (e) { res.status(500).json({ ok: false, error: String(e?.message || e) }); }
});
app.post('/api/numbers/:id/react', requireAuth, async (req, res) => {
  const ctx = needConnected(req, res); if (!ctx) return;
  const { jid, msgId, emoji } = req.body || {};
  const arr = ctx.s.store.msgs.get(jid) || [];
  const orig = arr.find((a) => a.id === msgId);
  if (!orig?.raw?.key) return res.status(404).json({ ok: false, error: 'Message not found.' });
  try {
    await ctx.s.sock.sendMessage(jid, { react: { text: String(emoji || ''), key: orig.raw.key } });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: String(e?.message || e) }); }
});
app.post('/api/numbers/:id/delete', requireAuth, async (req, res) => {
  const ctx = needConnected(req, res); if (!ctx) return;
  const { jid, msgId } = req.body || {};
  const arr = ctx.s.store.msgs.get(jid) || [];
  const orig = arr.find((a) => a.id === msgId);
  if (!orig?.raw?.key) return res.status(404).json({ ok: false, error: 'Message not found.' });
  if (!orig.fromMe) return res.status(403).json({ ok: false, error: 'You can only delete your own messages.' });
  try {
    await ctx.s.sock.sendMessage(jid, { delete: orig.raw.key });
    orig.text = '🚫 You deleted this message for everyone';
    ctx.s.persistSoon();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: String(e?.message || e) }); }
});
app.post('/api/numbers/:id/forward', requireAuth, async (req, res) => {
  const ctx = needConnected(req, res); if (!ctx) return;
  const { fromJid, msgId, toJids } = req.body || {};
  const arr = ctx.s.store.msgs.get(fromJid) || [];
  const orig = arr.find((a) => a.id === msgId);
  if (!orig) return res.status(404).json({ ok: false, error: 'Message not found.' });
  const targets = Array.isArray(toJids) ? toJids.slice(0, 5) : [];
  if (!targets.length) return res.status(400).json({ ok: false, error: 'Pick at least one chat.' });
  const results = [];
  for (const to of targets) {
    try {
      const sent = await ctx.s.sock.sendMessage(to, { text: orig.text });
      if (sent) addMsg(ctx.s, sent);
      results.push({ jid: to, ok: true, id: sent?.key?.id });
    } catch (e) { results.push({ jid: to, ok: false, error: String(e?.message || e) }); }
  }
  res.json({ ok: true, results });
});
app.get('/api/numbers/:id/calls', requireAuth, (req, res) => {
  const rec = ownNumber(req, res); if (!rec) return;
  const s = sessions.get(rec.id);
  res.json({ ok: true, calls: s ? [...s.store.calls].reverse() : [] });
});
app.get('/api/numbers/:id/statuses', requireAuth, (req, res) => {
  const rec = ownNumber(req, res); if (!rec) return;
  const s = sessions.get(rec.id);
  res.json({ ok: true, statuses: s ? [...s.store.statuses].reverse() : [] });
});
app.get('/api/numbers/:id/events', requireAuth, (req, res) => {
  const rec = ownNumber(req, res); if (!rec) return;
  const s = sessions.get(rec.id);
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  if (!s) { res.write(`event: status\ndata: ${JSON.stringify({ status: 'closed' })}\n\n`); return res.end(); }
  res.write(`event: status\ndata: ${JSON.stringify({ status: s.status, me: s.store.me })}\n\n`);
  s.clients.add(res);
  const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch { /* drop */ } }, 25000);
  req.on('close', () => { clearInterval(ping); s.clients.delete(res); });
});

/* broadcasts — real sends through the session, with pacing */
app.get('/api/numbers/:id/broadcasts', requireAuth, (req, res) => {
  const rec = ownNumber(req, res); if (!rec) return;
  const s = sessions.get(rec.id);
  res.json({ ok: true, broadcasts: s ? [...s.store.broadcasts].reverse() : [] });
});
app.post('/api/numbers/:id/broadcasts', requireAuth, async (req, res) => {
  const rec = ownNumber(req, res); if (!rec) return;
  const s = sessions.get(rec.id);
  if (!s?.sock || s.status !== 'connected') return res.status(409).json({ ok: false, error: 'WhatsApp line not connected.' });
  const { name, text, jids, gapSec } = req.body || {};
  const targets = Array.isArray(jids) ? jids.filter(Boolean) : [];
  if (!text || !targets.length) return res.status(400).json({ ok: false, error: 'Write a message and pick recipients.' });
  const bc = {
    id: id('bc_'), name: String(name || 'Broadcast').slice(0, 80), text: String(text),
    gapSec: Math.min(120, Math.max(0, Number(gapSec) || 5)),
    status: 'running', createdAt: Date.now(),
    results: targets.map((jid) => ({ jid, ok: null })),
  };
  s.store.broadcasts.push(bc);
  s.persistSoon();
  res.json({ ok: true, broadcast: bc });
  (async () => {
    for (const r of bc.results) {
      if (bc.status !== 'running') break;
      try {
        const chat = s.store.chats.get(r.jid);
        const personalized = bc.text.replaceAll('{name}', chat?.name || 'friend');
        const sent = await s.sock.sendMessage(r.jid, { text: personalized });
        if (sent) addMsg(s, sent);
        r.ok = true; r.id = sent?.key?.id;
      } catch (e) { r.ok = false; r.error = String(e?.message || e); }
      s.persistSoon();
      if (bc.gapSec > 0 && bc.status === 'running') await new Promise((r2) => setTimeout(r2, bc.gapSec * 1000));
    }
    if (bc.status === 'running') bc.status = 'done';
    s.persistSoon();
    emitTo(s, 'broadcast', { id: bc.id, status: bc.status });
  })();
});
app.post('/api/numbers/:id/broadcasts/:bcId/stop', requireAuth, (req, res) => {
  const rec = ownNumber(req, res); if (!rec) return;
  const s = sessions.get(rec.id);
  const bc = s?.store.broadcasts.find((b) => b.id === req.params.bcId);
  if (!bc) return res.status(404).json({ ok: false, error: 'Broadcast not found.' });
  bc.status = 'stopped';
  s.persistSoon();
  res.json({ ok: true, broadcast: bc });
});

/* labels + notes (per user, server-side) */
app.get('/api/labels', requireAuth, (req, res) => res.json({ ok: true, ...loadPanel(req.user.id) }));
app.post('/api/labels', requireAuth, (req, res) => {
  const p = loadPanel(req.user.id);
  const name = String(req.body?.name || '').trim();
  if (!name) return res.status(400).json({ ok: false, error: 'Enter a name.' });
  if (p.labels.some((l) => l.name.toLowerCase() === name.toLowerCase())) return res.status(409).json({ ok: false, error: 'A label with this name already exists.' });
  const lab = { id: id('lab_'), name, color: String(req.body?.color || '#00a884') };
  p.labels.push(lab);
  savePanel(req.user.id, p);
  res.json({ ok: true, label: lab });
});
app.delete('/api/labels/:labelId', requireAuth, (req, res) => {
  const p = loadPanel(req.user.id);
  p.labels = p.labels.filter((l) => l.id !== req.params.labelId);
  for (const jid of Object.keys(p.chatLabels)) p.chatLabels[jid] = (p.chatLabels[jid] || []).filter((x) => x !== req.params.labelId);
  savePanel(req.user.id, p);
  res.json({ ok: true });
});
app.put('/api/chat-labels', requireAuth, (req, res) => {
  const p = loadPanel(req.user.id);
  const { jid, labelIds } = req.body || {};
  if (!jid) return res.status(400).json({ ok: false, error: 'jid required' });
  p.chatLabels[jid] = Array.isArray(labelIds) ? labelIds : [];
  savePanel(req.user.id, p);
  res.json({ ok: true });
});
app.get('/api/notes', requireAuth, (req, res) => {
  const p = loadPanel(req.user.id);
  const jid = String(req.query.jid || '');
  res.json({ ok: true, notes: jid ? (p.notes[jid] || []) : p.notes });
});
app.post('/api/notes', requireAuth, (req, res) => {
  const p = loadPanel(req.user.id);
  const { jid, text } = req.body || {};
  if (!jid || !String(text || '').trim()) return res.status(400).json({ ok: false, error: 'Note is empty.' });
  const note = { id: id('nt_'), text: String(text).slice(0, 1000), by: req.user.name, ts: Math.floor(Date.now() / 1000) };
  (p.notes[jid] = p.notes[jid] || []).push(note);
  savePanel(req.user.id, p);
  res.json({ ok: true, note });
});
app.delete('/api/notes/:noteId', requireAuth, (req, res) => {
  const p = loadPanel(req.user.id);
  const jid = String(req.query.jid || '');
  if (jid && p.notes[jid]) p.notes[jid] = p.notes[jid].filter((n) => n.id !== req.params.noteId);
  savePanel(req.user.id, p);
  res.json({ ok: true });
});

/* health check for an external uptime pinger (keeps free-tier instances awake) */
app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now(), users: users.length, numbers: numbers.length }));

/* legacy single-session shortcuts (owner's migrated session = first number) */
app.get('/api/status', (req, res) => {
  const first = numbers[0];
  const s = first && sessions.get(first.id);
  res.json({ status: s ? s.status : 'closed', me: s ? s.store.me : null, chats: s ? s.store.chats.size : 0, numbers: numbers.length, users: users.length });
});

app.listen(PORT, async () => {
  await restoreFromMongo();
  console.log('[allwa] multi-user engine on :' + PORT, '— users:', users.length, 'numbers:', numbers.length);
  for (const rec of numbers) {
    const hasCreds = fs.existsSync(path.join(AUTH_ROOT, rec.id, 'creds.json'));
    if (hasCreds || rec.status === 'connected') startSession(rec);
  }
});
