// Backend da Conduta (Vercel + Neon). Variáveis: DATABASE_URL (Neon), SESSION_SECRET (opcional), BLOXTER_ADMIN_KEY (opcional)
const crypto = require('crypto');
const { neon } = require('@neondatabase/serverless');
const BASE = (process.env.BLOXTER_API || 'https://bloxter.sbs/api').replace(/\/$/, '');
const SEED_EMAIL = 'migfracassi@icloud.com';
const SEED_HASH = 'scrypt$26f15da406216b300264aceb4b312b60$859211dd0239eecc612f4c95f223c1792159bb5d40cae9661ca893effe2efeb2';
const DBURL = () => process.env.DATABASE_URL || process.env.POSTGRES_URL || '';
let _sql, _ready;
const sql = (...a) => (_sql || (_sql = neon(DBURL())))(...a);
const E = (s, m) => Object.assign(new Error(m), { s });
const secret = () => process.env.SESSION_SECRET || crypto.createHash('sha256').update('cd:' + DBURL()).digest('hex');
const sign = (p) => { const b = Buffer.from(JSON.stringify(p)).toString('base64url'); return b + '.' + crypto.createHmac('sha256', secret()).update(b).digest('base64url'); };
const unsign = (t = '') => { const [b, m] = t.split('.'); if (!b || !m) return null; const ok = crypto.createHmac('sha256', secret()).update(b).digest('base64url'); if (m.length !== ok.length || !crypto.timingSafeEqual(Buffer.from(m), Buffer.from(ok))) return null; try { const p = JSON.parse(Buffer.from(b, 'base64url').toString()); return p.exp > Date.now() ? p : null; } catch { return null; } };
const hash = (pw) => { const s = crypto.randomBytes(16).toString('hex'); return `scrypt$${s}$${crypto.scryptSync(pw, s, 32).toString('hex')}`; };
const verify = (pw, h) => { const [, s, x] = (h || '').split('$'); if (!s) return false; const a = crypto.scryptSync(pw, s, 32), b = Buffer.from(x, 'hex'); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const cookie = (req, name) => (req.headers.cookie || '').split(';').map((x) => x.trim().split('=')).find((x) => x[0] === name)?.[1];

async function init() {
  await sql`CREATE TABLE IF NOT EXISTS cd_users (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'mod', password_hash TEXT NOT NULL, avatar TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS cd_chat (id SERIAL PRIMARY KEY, user_id INT REFERENCES cd_users(id) ON DELETE CASCADE, body TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS cd_bans (id SERIAL PRIMARY KEY, username TEXT NOT NULL, reason TEXT NOT NULL, requested_by INT REFERENCES cd_users(id) ON DELETE SET NULL, status TEXT NOT NULL DEFAULT 'pending', decided_by INT, decided_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS cd_log (id SERIAL PRIMARY KEY, user_id INT REFERENCES cd_users(id) ON DELETE SET NULL, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS cd_settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)`;
  await sql`CREATE TABLE IF NOT EXISTS cd_notes (id SERIAL PRIMARY KEY, username TEXT NOT NULL, body TEXT NOT NULL, user_id INT REFERENCES cd_users(id) ON DELETE SET NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`;
  const [{ n }] = await sql`SELECT count(*)::int AS n FROM cd_users`;
  if (!n) await sql`INSERT INTO cd_users (email, name, role, password_hash) VALUES (${SEED_EMAIL}, 'Miguel', 'admin', ${SEED_HASH})`;
}
const log = (uid, action, detail = '') => sql`INSERT INTO cd_log (user_id, action, detail) VALUES (${uid}, ${action}, ${String(detail).slice(0, 300)})`.catch(() => {});
const getKey = async () => process.env.BLOXTER_ADMIN_KEY || (await sql`SELECT v FROM cd_settings WHERE k = 'admin_key'`)[0]?.v || '';
async function bx(path, o = {}, key) {
  key = key || (await getKey());
  if (!key) throw E(412, 'Configure a chave de administração em /admin.');
  const r = await fetch(BASE + path, { method: o.method || 'GET', headers: { 'X-Admin-Key': key, 'Content-Type': 'application/json' }, body: o.body ? JSON.stringify(o.body) : undefined });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw E(r.status === 401 || r.status === 403 ? 502 : r.status, r.status === 401 || r.status === 403 ? `O Bloxter recusou a chave de administração (${r.status}).` : `Bloxter: ${d.error || r.status}`);
  return d;
}
// ---- mídia (fotos e vídeos) ----
const ORIGIN = (() => { try { return new URL(BASE).origin; } catch { return ''; } })();
const absU = (u) => { try { const x = new URL(String(u), ORIGIN + '/'); return /^https?:$/.test(x.protocol) ? x.href : ''; } catch { return ''; } };
const kindOf = (u, t = '') => (/video/i.test(t) || /\.(mp4|webm|mov|m4v|ogv)(\?|#|$)/i.test(u) ? 'video' : 'image');
const mediaOf = (p) => {
  const out = [], seen = new Set();
  const add = (x, t) => {
    if (!x) return;
    if (Array.isArray(x)) return x.forEach((y) => add(y, t));
    const o = typeof x === 'object';
    const u = absU(o ? x.url || x.src || x.href || x.video_url || x.image_url || '' : x);
    if (!u || seen.has(u)) return; seen.add(u);
    out.push({ type: kindOf(u, o ? x.type || x.mime || x.kind || t || '' : t || ''), url: u });
  };
  add(p.media); add(p.attachments); add(p.images, 'image'); add(p.photos, 'image'); add(p.image, 'image'); add(p.image_url, 'image'); add(p.photo, 'image');
  add(p.videos, 'video'); add(p.video, 'video'); add(p.video_url, 'video');
  return out;
};
const fixPost = (p) => ({ ...p, body: p.body ?? p.content ?? p.text ?? '', user: p.user || p.author || { id: p.user_id ?? p.uid, username: p.username || '', name: p.name || p.username || '', avatar: p.avatar || null }, media: mediaOf(p) });

// ---- denúncias (API de administração do Bloxter) ----
// Rotas esperadas no Bloxter: GET /admin/reports, POST /admin/reports/:id/resolve e /dismiss.
// Se os nomes forem outros, ajuste só aqui.
const REPORTS = { list: '/admin/reports', act: (id, what) => `/admin/reports/${id}/${what}` };
const U = (x, fb) => (x && typeof x === 'object' && (x.username || x.name || x.id) ? { id: x.id, username: x.username || '', name: x.name || x.username || '', avatar: x.avatar || null } : { username: String((typeof x === 'string' ? x : '') || fb || ''), name: String((typeof x === 'string' ? x : '') || fb || ''), avatar: null });
const fixRep = (r) => {
  const s = String(r.status || (r.resolved ? 'resolved' : '')).toLowerCase();
  const post = r.post || (r.post_id ? { id: r.post_id } : null);
  return {
    id: r.id,
    status: ['resolved', 'closed', 'done', 'actioned'].includes(s) ? 'resolved' : ['dismissed', 'rejected', 'ignored'].includes(s) ? 'dismissed' : 'open',
    reason: r.reason || r.category || r.type || '',
    details: r.details || r.description || r.message || r.note || '',
    created_at: r.created_at || r.createdAt,
    target: U(r.reported_user || r.target_user || r.target || r.reported, r.reported_username || r.target_username),
    reporter: U(r.reporter || r.reported_by || r.author, r.reporter_username),
    post: post ? fixPost(post) : null,
  };
};
let _rc = { t: 0, n: 0 };
const openReports = async () => {
  if (Date.now() - _rc.t < 30000) return _rc.n;
  _rc.t = Date.now();
  try { const d = await bx(REPORTS.list + '?status=open&limit=100'); _rc.n = (d.reports || d.items || []).map(fixRep).filter((r) => r.status === 'open').length; } catch { _rc.n = 0; }
  return _rc.n;
};
const cleanU = (s) => String(s || '').trim().replace(/^@/, '').toLowerCase().replace(/[^a-z0-9_.]/g, '').slice(0, 40);

module.exports = async (req, res) => {
  const send = (s, o) => { res.statusCode = s; res.setHeader('Content-Type', 'application/json'); res.setHeader('Cache-Control', 'no-store'); res.end(JSON.stringify(o)); };
  try {
    if (!DBURL()) throw E(500, 'DATABASE_URL não configurada na Vercel.');
    await (_ready || (_ready = init().catch((e) => { _ready = null; throw e; })));
    const parts = String(req.query.__p || '').split('/').filter(Boolean), [a, b, c] = parts, m = req.method;
    let body = req.body || {}; if (typeof body === 'string') try { body = JSON.parse(body); } catch { body = {}; }
    const q = req.query;
    if (a === 'health') return send(200, { ok: true, db: true });

    if (a === 'login' && m === 'POST') {
      const [u] = await sql`SELECT * FROM cd_users WHERE email = ${String(body.email || '').trim().toLowerCase()}`;
      if (!u || !verify(String(body.password || ''), u.password_hash)) { await new Promise((r) => setTimeout(r, 600)); throw E(401, 'E-mail ou senha incorretos.'); }
      res.setHeader('Set-Cookie', `cd_s=${sign({ uid: u.id, exp: Date.now() + 30 * 864e5 })}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${30 * 86400}`);
      await log(u.id, 'login');
      return send(200, { ok: true });
    }
    if (a === 'logout') { res.setHeader('Set-Cookie', 'cd_s=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'); return send(200, { ok: true }); }

    const tok = unsign(cookie(req, 'cd_s'));
    const [me] = tok ? await sql`SELECT id, email, name, role, avatar FROM cd_users WHERE id = ${tok.uid}` : [];
    if (!me) throw E(401, 'Entre para continuar.');
    const admin = me.role === 'admin', needAdmin = () => { if (!admin) throw E(403, 'Só a administração pode fazer isso.'); };

    if (a === 'stats' && m === 'GET') {
      const after = parseInt(q.chat_after, 10) || 0;
      const [s] = await sql`SELECT
        (SELECT count(*)::int FROM cd_bans WHERE status = 'pending' AND (${admin ? 1 : 0} = 1 OR requested_by = ${me.id})) AS pending,
        (SELECT count(*)::int FROM cd_users) AS team,
        (SELECT count(*)::int FROM cd_chat WHERE created_at > now() - interval '24 hours') AS chat_day,
        (SELECT count(*)::int FROM cd_chat WHERE id > ${after} AND user_id IS DISTINCT FROM ${me.id}) AS unread,
        (SELECT count(*)::int FROM cd_log WHERE created_at > now() - interval '24 hours' AND action <> 'login') AS actions_day`;
      return send(200, { ...s, reports: await openReports() });
    }
    if (a === 'me' && !b && m === 'GET') return send(200, { user: me });
    if (a === 'me' && !b && m === 'PATCH') {
      const name = body.name === undefined ? me.name : String(body.name).trim().slice(0, 40);
      const av = body.avatar === undefined ? me.avatar : String(body.avatar);
      if (!name) throw E(400, 'Informe um nome.');
      if (av && (!/^data:image\/(jpeg|png|webp);base64,/.test(av) || av.length > 250000)) throw E(400, 'Foto inválida ou muito grande.');
      const [u] = await sql`UPDATE cd_users SET name = ${name}, avatar = ${av} WHERE id = ${me.id} RETURNING id, email, name, role, avatar`;
      return send(200, { user: u });
    }
    if (a === 'me' && b === 'password' && m === 'POST') {
      const [u] = await sql`SELECT password_hash FROM cd_users WHERE id = ${me.id}`;
      if (!verify(String(body.current || ''), u.password_hash)) throw E(400, 'A senha atual está incorreta.');
      if (String(body.next || '').length < 8) throw E(400, 'A nova senha precisa ter pelo menos 8 caracteres.');
      await sql`UPDATE cd_users SET password_hash = ${hash(body.next)} WHERE id = ${me.id}`;
      await log(me.id, 'senha', 'alterou a própria senha');
      return send(200, { ok: true });
    }

    // equipe
    if (a === 'team' && !b && m === 'GET') {
      const rows = await sql`SELECT id, email, name, role, avatar, created_at FROM cd_users ORDER BY id`;
      return send(200, { users: rows.map((u) => ({ id: u.id, name: u.name, role: u.role, avatar: u.avatar, ...(admin ? { email: u.email, created_at: u.created_at } : {}) })) });
    }
    if (a === 'team' && !b && m === 'POST') {
      needAdmin();
      const email = String(body.email || '').trim().toLowerCase(), name = String(body.name || '').trim().slice(0, 40), role = body.role === 'admin' ? 'admin' : 'mod';
      if (!/^\S+@\S+\.\S+$/.test(email) || !name || String(body.password || '').length < 8) throw E(400, 'Informe nome, e-mail válido e senha com 8+ caracteres.');
      try { await sql`INSERT INTO cd_users (email, name, role, password_hash) VALUES (${email}, ${name}, ${role}, ${hash(body.password)})`; } catch { throw E(409, 'Esse e-mail já está na equipe.'); }
      await log(me.id, 'equipe', `adicionou ${name}`);
      return send(201, { ok: true });
    }
    if (a === 'team' && b && c === 'reset' && m === 'POST') {
      needAdmin(); if (String(body.password || '').length < 8) throw E(400, 'A senha precisa ter 8+ caracteres.');
      await sql`UPDATE cd_users SET password_hash = ${hash(body.password)} WHERE id = ${+b}`; await log(me.id, 'equipe', `redefiniu a senha do membro #${+b}`);
      return send(200, { ok: true });
    }
    if (a === 'team' && b && !c && m === 'DELETE') {
      needAdmin(); if (+b === me.id) throw E(400, 'Você não pode remover a si mesmo.');
      await sql`DELETE FROM cd_users WHERE id = ${+b}`; await log(me.id, 'equipe', `removeu o membro #${+b}`);
      return send(200, { ok: true });
    }

    // chat da equipe
    if (a === 'chat' && m === 'GET') {
      const after = parseInt(q.after, 10) || 0;
      const rows = after ? await sql`SELECT id, user_id AS uid, body, created_at FROM cd_chat WHERE id > ${after} ORDER BY id LIMIT 100`
        : (await sql`SELECT id, user_id AS uid, body, created_at FROM cd_chat ORDER BY id DESC LIMIT 80`).reverse();
      return send(200, { messages: rows });
    }
    if (a === 'chat' && m === 'POST') {
      const t = String(body.body || '').trim().slice(0, 1000); if (!t) throw E(400, 'Mensagem vazia.');
      const [r] = await sql`INSERT INTO cd_chat (user_id, body) VALUES (${me.id}, ${t}) RETURNING id, user_id AS uid, body, created_at`;
      return send(201, { message: r });
    }

    // tweets (via API de administração do Bloxter)
    if (a === 'feed' && m === 'GET') {
      if (await getKey()) return send(200, { posts: ((await bx('/admin/posts?limit=30')).posts || []).map(fixPost) });
      const r = await (await fetch(BASE + '/posts/recent?limit=30')).json().catch(() => ({}));
      return send(200, { posts: (r.posts || []).map(fixPost) });
    }
    if (a === 'history' && m === 'GET') {
      const u = cleanU(q.username), before = parseInt(q.before, 10) || '';
      const d = await bx(`/admin/posts?username=${u}&limit=30&before=${before}`);
      return send(200, { posts: (d.posts || []).map(fixPost), next_before: d.next_before || null });
    }
    if (a === 'profile' && b && m === 'GET') {
      const u = cleanU(b), d = await bx(`/admin/users?q=${u}`);
      const user = (d.users || []).find((x) => x.username === u);
      if (!user) throw E(404, 'Perfil não encontrado.');
      if (!admin) delete user.email;
      return send(200, { user });
    }
    if (a === 'posts' && b && m === 'DELETE') {
      await bx(`/admin/posts/${parseInt(b, 10)}`, { method: 'DELETE' }); await log(me.id, 'apagou post', `#${parseInt(b, 10)}`);
      return send(200, { ok: true });
    }

    // banimentos: pedido -> administração
    if (a === 'bans' && !b && m === 'GET') {
      const rows = admin ? await sql`SELECT b.*, u.name AS by_name FROM cd_bans b LEFT JOIN cd_users u ON u.id = b.requested_by ORDER BY b.id DESC LIMIT 200`
        : await sql`SELECT b.*, u.name AS by_name FROM cd_bans b LEFT JOIN cd_users u ON u.id = b.requested_by WHERE b.requested_by = ${me.id} ORDER BY b.id DESC LIMIT 200`;
      return send(200, { bans: rows });
    }
    if (a === 'bans' && !b && m === 'POST') {
      const username = cleanU(body.username), reason = String(body.reason || '').trim().slice(0, 500);
      if (!username || reason.length < 10) throw E(400, 'Informe o usuário e um motivo com 10+ caracteres.');
      await sql`INSERT INTO cd_bans (username, reason, requested_by) VALUES (${username}, ${reason}, ${me.id})`;
      await log(me.id, 'pediu banimento', `@${username}`);
      return send(201, { ok: true });
    }
    if (a === 'bans' && b && c && m === 'POST') {
      needAdmin();
      const [r] = await sql`SELECT * FROM cd_bans WHERE id = ${+b}`; if (!r) throw E(404, 'Pedido não encontrado.');
      let st;
      if (c === 'approve' && r.status === 'pending') { await bx(`/admin/users/${r.username}/ban`, { method: 'POST', body: { reason: r.reason } }); st = 'approved'; }
      else if (c === 'reject' && r.status === 'pending') st = 'rejected';
      else if (c === 'unban' && r.status === 'approved') { await bx(`/admin/users/${r.username}/ban`, { method: 'DELETE' }); st = 'unbanned'; }
      else throw E(400, 'Ação inválida para este pedido.');
      await sql`UPDATE cd_bans SET status = ${st}, decided_by = ${me.id}, decided_at = now() WHERE id = ${r.id}`;
      await log(me.id, { approved: 'baniu', rejected: 'recusou banimento de', unbanned: 'desbaniu' }[st], `@${r.username}`);
      return send(200, { ok: true });
    }

    // mídia: fotos e vídeos postados
    if (a === 'media' && m === 'GET') {
      const u = cleanU(q.username), before = parseInt(q.before, 10) || '';
      let d;
      if (u || (await getKey())) d = await bx(`/admin/posts?${u ? 'username=' + u + '&' : ''}limit=60${before ? '&before=' + before : ''}`);
      else d = await (await fetch(BASE + '/posts/recent?limit=60')).json().catch(() => ({}));
      const all = (d.posts || []).map(fixPost);
      return send(200, { posts: all.filter((p) => p.media.length), next_before: d.next_before || (all.length ? all[all.length - 1].id : null), scanned: all.length });
    }

    // denúncias
    if (a === 'reports' && !b && m === 'GET') {
      const st = ['open', 'resolved', 'dismissed'].includes(q.status) ? q.status : '';
      const d = await bx(`${REPORTS.list}?limit=60${st ? '&status=' + st : ''}`);
      const list = (d.reports || d.items || []).map(fixRep);
      return send(200, { reports: st ? list.filter((r) => r.status === st) : list });
    }
    if (a === 'reports' && b && (c === 'resolve' || c === 'dismiss') && m === 'POST') {
      const id = parseInt(b, 10);
      await bx(REPORTS.act(id, c), { method: 'POST', body: { note: String(body.note || '').slice(0, 300) } });
      _rc.t = 0;
      await log(me.id, c === 'resolve' ? 'resolveu denúncia' : 'dispensou denúncia', `#${id}`);
      return send(200, { ok: true });
    }

    // notas internas sobre usuários
    if (a === 'notes' && !b && m === 'GET') {
      const rows = await sql`SELECT n.id, n.body, n.created_at, n.user_id AS uid, u.name AS by_name FROM cd_notes n LEFT JOIN cd_users u ON u.id = n.user_id WHERE n.username = ${cleanU(q.username)} ORDER BY n.id DESC LIMIT 50`;
      return send(200, { notes: rows });
    }
    if (a === 'notes' && !b && m === 'POST') {
      const username = cleanU(body.username), t = String(body.body || '').trim().slice(0, 500);
      if (!username || !t) throw E(400, 'Escreva a anotação.');
      await sql`INSERT INTO cd_notes (username, body, user_id) VALUES (${username}, ${t}, ${me.id})`;
      await log(me.id, 'anotou', `@${username}`);
      return send(201, { ok: true });
    }
    if (a === 'notes' && b && m === 'DELETE') {
      const [n] = await sql`SELECT user_id FROM cd_notes WHERE id = ${+b}`;
      if (!n) throw E(404, 'Nota não encontrada.');
      if (n.user_id !== me.id) needAdmin();
      await sql`DELETE FROM cd_notes WHERE id = ${+b}`;
      return send(200, { ok: true });
    }

    // atividade da equipe (admin)
    if (a === 'activity' && m === 'GET') {
      needAdmin(); const uid = parseInt(q.uid, 10) || 0;
      const rows = await sql`SELECT l.id, l.action, l.detail, l.created_at, l.user_id AS uid FROM cd_log l WHERE (${uid} = 0 OR l.user_id = ${uid}) ORDER BY l.id DESC LIMIT 100`;
      return send(200, { items: rows });
    }

    // chave de administração do Bloxter (guardada no Neon, nunca volta ao navegador)
    if (a === 'settings' && b === 'key' && m === 'GET') { needAdmin(); const k = await getKey(); return send(200, { set: !!k, hint: k ? '…' + k.slice(-4) : '', from_env: !!process.env.BLOXTER_ADMIN_KEY }); }
    if (a === 'settings' && b === 'key' && m === 'PUT') {
      needAdmin(); const k = String(body.key || '').trim();
      if (!k.startsWith('bx_admin_')) throw E(400, 'A chave começa com bx_admin_.');
      await bx('/admin/users?q=a', {}, k);
      await sql`INSERT INTO cd_settings (k, v) VALUES ('admin_key', ${k}) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v`;
      await log(me.id, 'chave', 'atualizou a chave de administração');
      return send(200, { ok: true });
    }
    throw E(404, 'Rota não encontrada.');
  } catch (e) {
    return send(e.s || 500, { error: e.s ? e.message : 'Erro interno: ' + e.message });
  }
};
