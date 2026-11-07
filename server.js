'use strict';
/*
  Conecta (antes Aula segura): simulación didáctica para una práctica con docentes.
  Todo el estado vive en memoria (no hace falta base de datos).
  Las contraseñas son inventadas y el "ataque" corre sobre esta misma demo.
*/
const express = require('express');
const http = require('http');
const crypto = require('crypto');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const KEY = process.env.INSTRUCTOR_KEY || 'instructor';
const SCRYPT_N = Number(process.env.SCRYPT_N) || 4096;
const PACE_MS = 15;
const SLOW_BUDGET_MS = 20000;

if (!process.env.INSTRUCTOR_KEY) {
  console.warn('[aviso] INSTRUCTOR_KEY no está definida. Se usa "instructor". Cámbiala antes de desplegar.');
}

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const wait = (ms) => new Promise((r) => (ms > 0 ? setTimeout(r, ms) : setImmediate(r)));
const send = (ws, o) => { if (ws.readyState === 1) ws.send(JSON.stringify(o)); };

const COMMON = ['123456', 'password', '12345678', 'qwerty', 'abc123', '111111', '123456789', 'iloveyou', 'admin', 'letmein', 'contraseña', 'universidad', 'colegio01', 'docente', 'dios123', 'elsalvador', '123123', 'sansalvador', '1234567890', 'maria2024'];
const COMMON_SET = new Set(COMMON);

function classify(p) {
  if (COMMON_SET.has(p.toLowerCase()) || p.length < 8) return 'debil';
  if (/^[A-Za-zñÑ]+[.#!_-]?\d{2,4}[!.]?$/.test(p) || p.length < 14) return 'media';
  return 'fuerte';
}

// Personas inventadas (nombre, usuario) y contraseña inicial. Todas son débiles a propósito:
// el atacante las descubre hasta que cada docente cambie la suya.
const PEOPLE = [
  ['Carlos Mejía', 'carlos.mejia', '123456'],
  ['María López', 'maria.lopez', 'password'],
  ['José Hernández', 'jose.hernandez', '12345678'],
  ['Ana Martínez', 'ana.martinez', 'qwerty'],
  ['Luis Rivera', 'luis.rivera', 'abc123'],
  ['Carmen Flores', 'carmen.flores', '111111'],
  ['Jorge Ramírez', 'jorge.ramirez', '123456789'],
  ['Rosa Castillo', 'rosa.castillo', '123456'],
  ['Miguel Alvarado', 'miguel.alvarado', 'iloveyou'],
  ['Sofía Menjívar', 'sofia.menjivar', 'contraseña'],
  ['Pedro Guzmán', 'pedro.guzman', 'colegio01'],
  ['Lucía Cruz', 'lucia.cruz', 'docente'],
  ['Roberto Henríquez', 'roberto.henriquez', 'dios123'],
  ['Daniela Pineda', 'daniela.pineda', 'elsalvador'],
  ['Fernando Orellana', 'fernando.orellana', 'universidad'],
];

const users = PEOPLE.map(([name, id, pass]) => ({
  id, name, orig: pass, pass, tier: classify(pass), changed: false,
  salt: crypto.randomBytes(4).toString('hex'), hash: '', result: null,
}));

let mode = 'plain'; // plain | salted | slow
function hashPw(u, pw, m = mode) {
  if (m === 'plain') return sha(pw);
  if (m === 'salted') return sha(u.salt + pw);
  return crypto.scryptSync(pw, u.salt, 32, { N: SCRYPT_N, r: 8, p: 1 }).toString('hex');
}
function rehashAll() { users.forEach((u) => { u.hash = hashPw(u, u.pass); }); }
rehashAll();

function benchmark() {
  let t = process.hrtime.bigint();
  for (let i = 0; i < 20000; i++) sha('x' + i);
  let ms = Number(process.hrtime.bigint() - t) / 1e6;
  const shaRate = Math.round(20000 / (ms / 1000));
  t = process.hrtime.bigint();
  for (let i = 0; i < 8; i++) crypto.scryptSync('x' + i, 'salt', 32, { N: SCRYPT_N, r: 8, p: 1 });
  ms = Number(process.hrtime.bigint() - t) / 1e6;
  return { shaRate, scRate: Math.max(1, Math.round(8 / (ms / 1000))) };
}
const BENCH = benchmark();

const attack = { phase: 'idle', dumped: false, tries: 0, ms: 0, cancel: false };
let running = false;
const sessions = new Map();
const teacherSockets = new Map();
const attackers = new Set();

const online = (id) => (teacherSockets.get(id) || new Set()).size > 0;

function teacherPayload(u) {
  return {
    t: 'phase', phase: attack.phase, mode, dumped: attack.dumped,
    me: { id: u.id, name: u.name, hash: u.hash, salt: mode === 'plain' ? null : u.salt, changed: u.changed },
    result: u.result,
  };
}
function pushTeachers() {
  users.forEach((u) => (teacherSockets.get(u.id) || []).forEach((ws) => send(ws, teacherPayload(u))));
}
function rosterPayload() {
  const done = attack.phase === 'done';
  return {
    t: 'roster', phase: attack.phase, mode,
    stats: { tries: attack.tries, ms: attack.ms, shaRate: BENCH.shaRate, scRate: BENCH.scRate },
    users: users.map((u) => ({
      id: u.id, name: u.name, online: online(u.id), changed: u.changed,
      hash: attack.dumped ? u.hash : null,
      salt: attack.dumped && mode !== 'plain' ? u.salt : null,
      status: u.result ? (u.result.cracked ? 'cracked' : 'resists') : (attack.phase === 'crack' ? 'working' : 'pending'),
      guess: u.result && u.result.cracked ? u.result.guess : null,
      tier: done ? u.tier : null,
    })),
  };
}
function pushAttackers(o) { attackers.forEach((ws) => send(ws, o)); }
const pushRoster = () => pushAttackers(rosterPayload());
const log = (line, cls = '') => pushAttackers({ t: 'log', line, cls });
function setPhase(p) { attack.phase = p; pushTeachers(); pushRoster(); }

function candidates() {
  const out = COMMON.slice();
  const first = PEOPLE.map((p) => p[1].split('.')[0]);
  const bases = first.concat(['colegio', 'docente', 'ugb', 'escuela', 'profesor', 'admin']);
  for (const b of bases) {
    for (const c of [b, b[0].toUpperCase() + b.slice(1)]) {
      for (let y = 1970; y <= 2026; y++) out.push(c + y, c + y + '!', c + '.' + y + '!', c + '#' + y, c + y + '.');
    }
  }
  return out;
}

async function runAttack() {
  if (running || attack.phase !== 'idle') return;
  running = true; attack.cancel = false; attack.tries = 0; attack.ms = 0;
  try {
    setPhase('intrusion');
    const intro = ['Escaneando conecta…', 'Puerto 443 abierto', 'Buscando acceso a la base de datos…', 'Acceso obtenido: la base de datos no tenía protección extra'];
    for (const l of intro) { log(l); await wait(850); if (attack.cancel) return; }

    attack.dumped = true;
    log('Volcado completo: ' + users.length + ' registros copiados', 'warn');
    setPhase('dump');
    await wait(2500); if (attack.cancel) return;

    log('Velocidad medida en este servidor: ' + BENCH.shaRate.toLocaleString('es') + ' hashes SHA-256 por segundo y ' + BENCH.scRate.toLocaleString('es') + ' de scrypt por segundo');
    log('Probando contraseñas comunes y variaciones (nombre + símbolo + año)…');
    setPhase('crack');

    const C = candidates();
    const slow = mode === 'slow';
    const budget = slow ? SLOW_BUDGET_MS : 60000;
    const cache = new Map();
    let pending = users.slice();
    const t0 = Date.now();

    for (let gi = 0; gi < C.length && pending.length && Date.now() - t0 < budget; gi++) {
      const g = C[gi];
      for (const u of pending.slice()) {
        let h;
        if (mode === 'plain') {
          if (!cache.has(g)) { cache.set(g, sha(g)); attack.tries++; }
          h = cache.get(g);
        } else { h = hashPw(u, g); attack.tries++; }
        if (h === u.hash) {
          u.result = { cracked: true, guess: g, ms: Date.now() - t0, tries: attack.tries, tier: u.tier };
          pending = pending.filter((p) => p !== u);
          log('Descubierta: ' + u.id + ' → ' + g, 'hit');
          pushRoster();
        }
      }
      const fine = gi < 40; // las primeras pruebas van una por una para que se vea caer cada cuenta
      if (slow || fine || gi % 25 === 0) {
        attack.ms = Date.now() - t0;
        pushAttackers({ t: 'progress', guess: g, tries: attack.tries, ms: attack.ms });
        await wait(slow ? 0 : (fine ? 170 : PACE_MS));
        if (attack.cancel) return;
      }
    }
    attack.ms = Date.now() - t0;
    pending.forEach((u) => { u.result = { cracked: false, tries: attack.tries, ms: attack.ms, tier: u.tier }; });
    const n = users.filter((u) => u.result && u.result.cracked).length;
    log('Fin del ataque: ' + n + ' de ' + users.length + ' contraseñas descubiertas con ' + attack.tries.toLocaleString('es') + ' intentos', 'warn');
    setPhase('done');
  } finally {
    running = false; attack.cancel = false;
  }
}

function resetRound(full) {
  if (running) attack.cancel = true;
  attack.phase = 'idle'; attack.dumped = false; attack.tries = 0; attack.ms = 0;
  users.forEach((u) => {
    u.result = null;
    if (full) { u.pass = u.orig; u.changed = false; u.tier = classify(u.pass); }
  });
  if (full) rehashAll();
  pushTeachers(); pushRoster();
  log(full ? 'Cuentas restauradas a las contraseñas de las tarjetas' : 'Ronda reiniciada');
}

const app = express();
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/atacante', (req, res) => res.sendFile(path.join(__dirname, 'public', 'atacante.html')));

const fails = new Map();
app.post('/api/login', (req, res) => {
  const ip = req.ip;
  const f = fails.get(ip) || { n: 0, t: Date.now() };
  if (Date.now() - f.t > 60000) { f.n = 0; f.t = Date.now(); }
  if (f.n >= 20) return res.status(429).json({ error: 'Demasiados intentos. Espera un minuto.' });
  const { user, pass } = req.body || {};
  const norm = String(user || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  const u = users.find((x) => x.id === norm);
  if (!u || typeof pass !== 'string' || hashPw(u, pass) !== u.hash) {
    f.n++; fails.set(ip, f);
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }
  const token = crypto.randomBytes(16).toString('hex');
  sessions.set(token, u.id);
  res.json({ token, id: u.id, name: u.name });
});

app.post('/api/password', (req, res) => {
  const { token, newPass } = req.body || {};
  const u = users.find((x) => x.id === sessions.get(token));
  if (!u) return res.status(401).json({ error: 'Sesión no válida' });
  if (attack.phase !== 'idle') return res.status(409).json({ error: 'No se puede cambiar durante un ataque' });
  if (typeof newPass !== 'string' || newPass.length < 1 || newPass.length > 100) return res.status(400).json({ error: 'Escribe una contraseña' });
  u.pass = newPass; u.changed = true; u.tier = classify(newPass); u.hash = hashPw(u, newPass);
  pushTeachers(); pushRoster();
  res.json({ ok: true });
});

app.get('/api/people', (req, res) => res.json(users.map((u) => ({ id: u.id, name: u.name }))));

app.get('/api/cards', (req, res) => {
  if (req.query.key !== KEY) return res.status(401).json({ error: 'Clave de instructor incorrecta' });
  res.json(users.map((u) => ({ id: u.id, name: u.name, pass: u.orig, tier: classify(u.orig) })));
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (ws, req) => {
  const q = new URL(req.url, 'http://x').searchParams;
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  if (q.get('role') === 'atacante') {
    if (q.get('key') !== KEY) { ws.close(4001); return; }
    attackers.add(ws);
    send(ws, rosterPayload());
    ws.on('message', (raw) => {
      let m; try { m = JSON.parse(raw); } catch { return; }
      if (m.t === 'start') runAttack();
      else if (m.t === 'reset') resetRound(false);
      else if (m.t === 'resetAll') resetRound(true);
      else if (m.t === 'setMode' && attack.phase === 'idle' && ['plain', 'salted', 'slow'].includes(m.mode)) {
        mode = m.mode; rehashAll(); pushTeachers(); pushRoster();
        log('Método de guardado cambiado a: ' + mode);
      }
    });
    ws.on('close', () => attackers.delete(ws));
    return;
  }

  const id = sessions.get(q.get('token'));
  const u = users.find((x) => x.id === id);
  if (!u) { ws.close(4002); return; }
  if (!teacherSockets.has(id)) teacherSockets.set(id, new Set());
  teacherSockets.get(id).add(ws);
  send(ws, teacherPayload(u));
  pushRoster();
  ws.on('close', () => { teacherSockets.get(id).delete(ws); pushRoster(); });
});

setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false; ws.ping();
  });
}, 25000);

server.listen(PORT, () => console.log('Conecta escuchando en el puerto ' + PORT));
