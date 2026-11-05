// My Reading Year — backend (Cloudflare Worker + D1, free plan)
// Setup (once, in the Cloudflare dashboard):
//   1. Storage & Databases → D1 → Create database → name it "bookshelf".
//   2. Your worker → Settings → Bindings → Add → D1 database → Variable name: DB → pick "bookshelf".
//   3. Paste this whole file into the worker editor and Deploy. Tables are created automatically.
// Secrets/variables (Settings → Variables and Secrets):
//   PAYHIP_SECRET (secret, already set) · ADMIN (text, optional): your username, lets you remove any post.

const ALLOWED_ORIGINS = ["https://benjithinksyt-coder.github.io"];
const MAX_ACTIVATIONS = 5;
const PAYHIP = "https://payhip.com/api/v2/license/";
const COVER_PREFIX = "https://covers.openlibrary.org/";
const HIDE_AFTER_REPORTS = 3;
const POSTS_PER_HOUR = 30, COMMENTS_PER_HOUR = 60;

/* ---------------- helpers ---------------- */
function cors(o) {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGINS.includes(o) ? o : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400", "Vary": "Origin",
  };
}
const json = (body, origin, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...cors(origin) } });
const now = () => Date.now();
async function sha256(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, "0")).join("");
}
function randomToken() { const a = new Uint8Array(32); crypto.getRandomValues(a); return [...a].map(b => b.toString(16).padStart(2, "0")).join(""); }
const clean = (s, max) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "").trim().slice(0, max);
const cleanKey = k => String(k || "").trim().toUpperCase();
const okKey = k => /^[A-Z0-9-]{8,100}$/.test(k);
const okCover = c => !c || (typeof c === "string" && c.startsWith(COVER_PREFIX) && c.length < 200);
const AVATAR_COLORS = 8;

async function payhip(env, path, key, method = "GET") {
  const opts = { method, headers: { "product-secret-key": env.PAYHIP_SECRET } };
  let url = PAYHIP + path;
  if (method === "GET") url += "?license_key=" + encodeURIComponent(key);
  else { opts.headers["Content-Type"] = "application/x-www-form-urlencoded"; opts.body = "license_key=" + encodeURIComponent(key); }
  const t = await (await fetch(url, opts)).text();
  if (!t) return null;
  try { return JSON.parse(t).data || null; } catch { return null; }
}
async function verifyKey(env, key) {
  if (env.DEV_KEYS && env.DEV_KEYS.split(",").includes(key)) return { enabled: true, uses: 0 }; // local testing only
  try { return await payhip(env, "verify", key); } catch { return undefined; } // undefined = Payhip unreachable
}

/* ---------------- schema ---------------- */
let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady) return;
  const s = [
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, key_hash TEXT UNIQUE NOT NULL, username TEXT UNIQUE NOT NULL COLLATE NOCASE, name TEXT, bio TEXT, avatar TEXT, color INTEGER DEFAULT 0, private INTEGER DEFAULT 0, created INTEGER)",
    "CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created INTEGER)",
    "CREATE TABLE IF NOT EXISTS books (user_id INTEGER NOT NULL, bid TEXT NOT NULL, title TEXT, author TEXT, cover TEXT, status TEXT, rating INTEGER, genre TEXT, pages INTEGER, endd TEXT, PRIMARY KEY (user_id, bid))",
    "CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, kind TEXT, title TEXT, author TEXT, cover TEXT, rating INTEGER, body TEXT, created INTEGER, hidden INTEGER DEFAULT 0)",
    "CREATE INDEX IF NOT EXISTS posts_user ON posts (user_id, id)",
    "CREATE TABLE IF NOT EXISTS likes (post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, PRIMARY KEY (post_id, user_id))",
    "CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, body TEXT, created INTEGER, hidden INTEGER DEFAULT 0)",
    "CREATE INDEX IF NOT EXISTS comments_post ON comments (post_id, id)",
    "CREATE TABLE IF NOT EXISTS follows (follower INTEGER NOT NULL, followee INTEGER NOT NULL, accepted INTEGER DEFAULT 1, created INTEGER, PRIMARY KEY (follower, followee))",
    "CREATE INDEX IF NOT EXISTS follows_followee ON follows (followee)",
    "CREATE TABLE IF NOT EXISTS blocks (blocker INTEGER NOT NULL, blocked INTEGER NOT NULL, PRIMARY KEY (blocker, blocked))",
    "CREATE TABLE IF NOT EXISTS stats (user_id INTEGER PRIMARY KEY, level INTEGER DEFAULT 1, xp INTEGER DEFAULT 0, minutes INTEGER DEFAULT 0, streak INTEGER DEFAULT 0, badges TEXT DEFAULT '', frame TEXT DEFAULT '', updated INTEGER)",
    "CREATE TABLE IF NOT EXISTS reports (reporter INTEGER NOT NULL, kind TEXT NOT NULL, target INTEGER NOT NULL, reason TEXT, created INTEGER, PRIMARY KEY (reporter, kind, target))",
  ];
  await db.batch(s.map(q => db.prepare(q)));
  try { await db.prepare("ALTER TABLE stats ADD COLUMN bg TEXT DEFAULT ''").run(); } catch {} // added later; fine if it already exists
  schemaReady = true;
}

/* ---------------- auth ---------------- */
async function newSession(db, userId) {
  const tok = randomToken();
  await db.prepare("INSERT INTO sessions (token_hash, user_id, created) VALUES (?, ?, ?)").bind(await sha256(tok), userId, now()).run();
  return tok;
}
async function currentUser(req, db) {
  const h = req.headers.get("Authorization") || "";
  const tok = h.startsWith("Bearer ") ? h.slice(7).trim() : "";
  if (!/^[0-9a-f]{64}$/.test(tok)) return null;
  return db.prepare("SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?").bind(await sha256(tok)).first();
}
const publicUser = u => ({ username: u.username, name: u.name || u.username, bio: u.bio || "", avatar: u.avatar || "", color: u.color || 0, private: !!u.private });

async function blockedEither(db, a, b) {
  if (!a || !b) return false;
  return !!(await db.prepare("SELECT 1 FROM blocks WHERE (blocker=? AND blocked=?) OR (blocker=? AND blocked=?)").bind(a, b, b, a).first());
}
async function canSee(db, viewer, owner) {
  if (viewer && viewer.id === owner.id) return true;
  if (await blockedEither(db, viewer && viewer.id, owner.id)) return false;
  if (!owner.private) return true;
  if (!viewer) return false;
  return !!(await db.prepare("SELECT 1 FROM follows WHERE follower=? AND followee=? AND accepted=1").bind(viewer.id, owner.id).first());
}
async function recentCount(db, table, userId) {
  const r = await db.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE user_id=? AND created>?`).bind(userId, now() - 3600e3).first();
  return r ? r.n : 0;
}

/* posts come back with author + counts + liked flag */
const POST_COLS = `p.id, p.kind, p.title, p.author, p.cover, p.rating, p.body, p.created,
  u.username, u.name, u.avatar, u.color,
  (SELECT frame FROM stats s WHERE s.user_id=p.user_id) AS frame, (SELECT bg FROM stats s2 WHERE s2.user_id=p.user_id) AS bg,
  (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) AS likes,
  (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id AND c.hidden=0) AS comments,
  EXISTS(SELECT 1 FROM likes l2 WHERE l2.post_id=p.id AND l2.user_id=?) AS liked`;
const NOT_BLOCKED = `NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=? AND b.blocked=p.user_id) OR (b.blocker=p.user_id AND b.blocked=?))`;
const shapePost = r => ({ id: r.id, kind: r.kind, title: r.title, author: r.author, cover: r.cover, rating: r.rating || 0, body: r.body || "", created: r.created,
  user: { username: r.username, name: r.name || r.username, avatar: r.avatar || "", color: r.color || 0, frame: r.frame || "", bg: r.bg || "" }, likes: r.likes, comments: r.comments, liked: !!r.liked });

async function postVisible(db, me, postId) {
  const p = await db.prepare("SELECT p.*, u.private FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=? AND p.hidden=0").bind(postId).first();
  if (!p) return null;
  const owner = { id: p.user_id, private: p.private };
  return (await canSee(db, me, owner)) ? p : null;
}

/* ---------------- routes ---------------- */
async function route(req, env, origin) {
  const db = env.DB, url = new URL(req.url), path = url.pathname.replace(/\/+$/, ""), m = req.method;
  let body = {};
  if (m !== "GET" && m !== "DELETE") { try { body = await req.json(); } catch { body = {}; } }
  const seg = path.split("/").filter(Boolean); // e.g. ["api","posts","12","like"]

  // ---- license (unchanged behaviour) ----
  if (path.endsWith("/activate") || path.endsWith("/check")) {
    if (m !== "POST") return json({ ok: false, reason: "post_only" }, origin, 405);
    if (!env.PAYHIP_SECRET && !env.DEV_KEYS) return json({ ok: false, reason: "server_not_set_up" }, origin, 500);
    const key = cleanKey(body.key);
    if (!okKey(key)) return json({ ok: false, reason: "bad_format" }, origin);
    const lic = await verifyKey(env, key);
    if (lic === undefined) return json({ ok: false, reason: "try_again" }, origin, 503);
    if (!lic) return json({ ok: false, reason: "not_found" }, origin);
    if (!lic.enabled) return json({ ok: false, reason: "disabled" }, origin);
    if (path.endsWith("/check")) return json({ ok: true }, origin);
    if ((lic.uses || 0) >= MAX_ACTIVATIONS) return json({ ok: false, reason: "too_many" }, origin);
    if (!env.DEV_KEYS) await payhip(env, "usage", key, "PUT");
    return json({ ok: true, left: MAX_ACTIVATIONS - (lic.uses || 0) - 1 }, origin);
  }

  if (seg[0] !== "api") return json({ ok: false, reason: "unknown_path" }, origin, 404);
  if (!db) return json({ ok: false, reason: "database_not_connected" }, origin, 500);
  await ensureSchema(db);

  // ---- sign up / sign in with your license key ----
  if (seg[1] === "signup" && m === "POST") {
    const key = cleanKey(body.key);
    if (!okKey(key)) return json({ ok: false, reason: "bad_format" }, origin);
    const lic = await verifyKey(env, key);
    if (lic === undefined) return json({ ok: false, reason: "try_again" }, origin, 503);
    if (!lic) return json({ ok: false, reason: "not_found" }, origin);
    if (!lic.enabled) return json({ ok: false, reason: "disabled" }, origin);
    const kh = await sha256("key:" + key);
    const existing = await db.prepare("SELECT * FROM users WHERE key_hash=?").bind(kh).first();
    if (existing) return json({ ok: true, token: await newSession(db, existing.id), me: publicUser(existing) }, origin);
    const username = String(body.username || "").trim().toLowerCase();
    if (!username) return json({ ok: false, reason: "need_username" }, origin);
    if (!/^[a-z0-9_.]{3,20}$/.test(username)) return json({ ok: false, reason: "bad_username" }, origin);
    if (!body.agree) return json({ ok: false, reason: "need_agree" }, origin);
    if (await db.prepare("SELECT 1 FROM users WHERE username=?").bind(username).first()) return json({ ok: false, reason: "username_taken" }, origin);
    const name = clean(body.name, 40) || username;
    const r = await db.prepare("INSERT INTO users (key_hash, username, name, bio, avatar, color, private, created) VALUES (?,?,?,?,?,?,?,?)")
      .bind(kh, username, name, "", clean(body.avatar, 8), Math.abs(parseInt(body.color, 10) || 0) % AVATAR_COLORS, body.private ? 1 : 0, now()).run();
    const id = r.meta.last_row_id;
    const u = await db.prepare("SELECT * FROM users WHERE id=?").bind(id).first();
    return json({ ok: true, token: await newSession(db, id), me: publicUser(u), created: true }, origin);
  }

  let me = await currentUser(req, db);

  // Guests (free-trial readers) can browse: the Discover feed, public profiles and comments. Everything else needs an account.
  if (!me) {
    const guestOk = m === "GET" && ((seg[1] === "feed") || (seg[1] === "u" && seg[2] && !seg[3]) || (seg[1] === "posts" && seg[2] && seg[3] === "comments"));
    if (!guestOk) return json({ ok: false, reason: "signed_out" }, origin, 401);
    me = { id: 0, username: "", guest: true };
    if (seg[1] === "feed") url.searchParams.set("tab", "discover");
  }
  const isAdmin = env.ADMIN && me.username.toLowerCase() === String(env.ADMIN).toLowerCase();

  // ---- me ----
  if (seg[1] === "me" && m === "GET") {
    const pending = await db.prepare("SELECT COUNT(*) AS n FROM follows WHERE followee=? AND accepted=0").bind(me.id).first();
    return json({ ok: true, me: { ...publicUser(me), requests: pending.n, admin: !!isAdmin } }, origin);
  }
  if (seg[1] === "me" && m === "PATCH") {
    const name = body.name !== undefined ? clean(body.name, 40) || me.username : me.name;
    const bio = body.bio !== undefined ? clean(body.bio, 160) : me.bio;
    const avatar = body.avatar !== undefined ? clean(body.avatar, 8) : me.avatar;
    const color = body.color !== undefined ? Math.abs(parseInt(body.color, 10) || 0) % AVATAR_COLORS : me.color;
    const priv = body.private !== undefined ? (body.private ? 1 : 0) : me.private;
    const stmts = [db.prepare("UPDATE users SET name=?, bio=?, avatar=?, color=?, private=? WHERE id=?").bind(name, bio, avatar, color, priv, me.id)];
    if (!priv) stmts.push(db.prepare("UPDATE follows SET accepted=1 WHERE followee=?").bind(me.id)); // going public approves waiting requests
    await db.batch(stmts);
    return json({ ok: true, me: publicUser({ ...me, name, bio, avatar, color, private: priv }) }, origin);
  }
  if (seg[1] === "logout" && m === "POST") {
    const tok = (req.headers.get("Authorization") || "").slice(7).trim();
    await db.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(tok)).run();
    return json({ ok: true }, origin);
  }
  if (seg[1] === "account" && m === "DELETE") { // delete everything this user made
    const id = me.id;
    await db.batch([
      "DELETE FROM likes WHERE user_id=? OR post_id IN (SELECT id FROM posts WHERE user_id=?)",
      "DELETE FROM comments WHERE user_id=? OR post_id IN (SELECT id FROM posts WHERE user_id=?)",
    ].map(q => db.prepare(q).bind(id, id)).concat([
      db.prepare("DELETE FROM posts WHERE user_id=?").bind(id), db.prepare("DELETE FROM books WHERE user_id=?").bind(id),
      db.prepare("DELETE FROM follows WHERE follower=? OR followee=?").bind(id, id), db.prepare("DELETE FROM blocks WHERE blocker=? OR blocked=?").bind(id, id),
      db.prepare("DELETE FROM reports WHERE reporter=?").bind(id), db.prepare("DELETE FROM sessions WHERE user_id=?").bind(id),
      db.prepare("DELETE FROM users WHERE id=?").bind(id)]));
    return json({ ok: true }, origin);
  }

  // ---- shelf sync ----
  // PUT  {books:[...]}            → replace the whole library (first sync on a device)
  // PATCH {upsert:[...], remove:[ids]} → only what changed (every sync after that; far fewer database writes)
  if (seg[1] === "sync" && (m === "PUT" || m === "PATCH")) {
    const upsert = (Array.isArray(m === "PUT" ? body.books : body.upsert) ? (m === "PUT" ? body.books : body.upsert) : []).slice(0, 2000);
    const remove = m === "PATCH" && Array.isArray(body.remove) ? body.remove.slice(0, 2000) : [];
    const stmts = m === "PUT" ? [db.prepare("DELETE FROM books WHERE user_id=?").bind(me.id)] : [];
    for (const id of remove) stmts.push(db.prepare("DELETE FROM books WHERE user_id=? AND bid=?").bind(me.id, clean(id, 40)));
    for (const b of upsert) {
      const st = ["Reading", "Finished", "TBR", "DNF"].includes(b.status) ? b.status : "TBR";
      stmts.push(db.prepare("INSERT OR REPLACE INTO books (user_id, bid, title, author, cover, status, rating, genre, pages, endd) VALUES (?,?,?,?,?,?,?,?,?,?)")
        .bind(me.id, clean(b.id, 40) || randomToken().slice(0, 12), clean(b.title, 200), clean(b.author, 120), okCover(b.cover) ? (b.cover || "") : "",
          st, Math.max(0, Math.min(5, parseInt(b.rating, 10) || 0)), clean(b.genre, 30), Math.max(0, Math.min(20000, parseInt(b.pages, 10) || 0)), clean(b.end, 10)));
    }
    for (let i = 0; i < stmts.length; i += 100) await db.batch(stmts.slice(i, i + 100));
    return json({ ok: true, count: upsert.length, removed: remove.length }, origin);
  }

  // ---- reading rewards shown on your profile (level, time read, badges, frame) ----
  if (seg[1] === "stats" && m === "PATCH") {
    const badges = (Array.isArray(body.badges) ? body.badges : []).map(b => clean(b, 20)).filter(b => /^[a-z0-9_]+$/.test(b)).slice(0, 60).join(",");
    const frame = ["", "gold", "rose", "laurel", "star"].includes(body.frame) ? body.frame : "";
    const bg = ["", "ambient", "grey", "linen", "sunset", "ocean", "sage", "stars", "blossom", "gold"].includes(body.bg) ? body.bg : "";
    const n = (v, max) => Math.max(0, Math.min(max, parseInt(v, 10) || 0));
    await db.prepare("INSERT OR REPLACE INTO stats (user_id, level, xp, minutes, streak, badges, frame, bg, updated) VALUES (?,?,?,?,?,?,?,?,?)")
      .bind(me.id, Math.max(1, n(body.level, 999)), n(body.xp, 1e9), n(body.minutes, 1e7), n(body.streak, 10000), badges, frame, bg, now()).run();
    return json({ ok: true }, origin);
  }

  // ---- feed ----
  if (seg[1] === "feed" && m === "GET") {
    const before = parseInt(url.searchParams.get("before"), 10) || 9e15;
    const tab = url.searchParams.get("tab") === "discover" ? "discover" : "following";
    const where = tab === "following"
      ? "(p.user_id=? OR p.user_id IN (SELECT followee FROM follows WHERE follower=? AND accepted=1))"
      : "u.private=0";
    const args = tab === "following" ? [me.id, me.id] : [];
    const rows = await db.prepare(`SELECT ${POST_COLS} FROM posts p JOIN users u ON u.id=p.user_id
      WHERE p.hidden=0 AND p.id<? AND ${where} AND ${NOT_BLOCKED} ORDER BY p.id DESC LIMIT 20`)
      .bind(me.id, before, ...args, me.id, me.id).all();
    return json({ ok: true, posts: rows.results.map(shapePost) }, origin);
  }

  // ---- posts ----
  if (seg[1] === "posts" && !seg[2] && m === "POST") {
    if (await recentCount(db, "posts", me.id) >= POSTS_PER_HOUR) return json({ ok: false, reason: "slow_down" }, origin, 429);
    const kind = ["finished", "started", "review", "tbr"].includes(body.kind) ? body.kind : "review";
    const title = clean(body.title, 200);
    if (!title) return json({ ok: false, reason: "need_title" }, origin);
    const r = await db.prepare("INSERT INTO posts (user_id, kind, title, author, cover, rating, body, created) VALUES (?,?,?,?,?,?,?,?)")
      .bind(me.id, kind, title, clean(body.author, 120), okCover(body.cover) ? (body.cover || "") : "",
        Math.max(0, Math.min(5, parseInt(body.rating, 10) || 0)), clean(body.body, 500), now()).run();
    const row = await db.prepare(`SELECT ${POST_COLS} FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=?`).bind(me.id, r.meta.last_row_id).first();
    return json({ ok: true, post: shapePost(row) }, origin);
  }
  if (seg[1] === "posts" && seg[2]) {
    const pid = parseInt(seg[2], 10);
    if (!seg[3] && m === "DELETE") {
      const p = await db.prepare("SELECT user_id FROM posts WHERE id=?").bind(pid).first();
      if (!p || (p.user_id !== me.id && !isAdmin)) return json({ ok: false, reason: "not_yours" }, origin, 403);
      await db.batch([db.prepare("DELETE FROM likes WHERE post_id=?").bind(pid), db.prepare("DELETE FROM comments WHERE post_id=?").bind(pid), db.prepare("DELETE FROM posts WHERE id=?").bind(pid)]);
      return json({ ok: true }, origin);
    }
    const p = await postVisible(db, me, pid);
    if (!p) return json({ ok: false, reason: "not_found" }, origin, 404);
    if (seg[3] === "like") {
      if (m === "POST") await db.prepare("INSERT OR IGNORE INTO likes (post_id, user_id) VALUES (?, ?)").bind(pid, me.id).run();
      else if (m === "DELETE") await db.prepare("DELETE FROM likes WHERE post_id=? AND user_id=?").bind(pid, me.id).run();
      const n = await db.prepare("SELECT COUNT(*) AS n FROM likes WHERE post_id=?").bind(pid).first();
      return json({ ok: true, likes: n.n, liked: m === "POST" }, origin);
    }
    if (seg[3] === "comments" && m === "GET") {
      const rows = await db.prepare(`SELECT c.id, c.body, c.created, c.user_id, u.username, u.name, u.avatar, u.color FROM comments c JOIN users u ON u.id=c.user_id
        WHERE c.post_id=? AND c.hidden=0 AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=? AND b.blocked=c.user_id) OR (b.blocker=c.user_id AND b.blocked=?))
        ORDER BY c.id ASC LIMIT 200`).bind(pid, me.id, me.id).all();
      return json({ ok: true, comments: rows.results.map(c => ({ id: c.id, body: c.body, created: c.created, mine: c.user_id === me.id, canDelete: c.user_id === me.id || p.user_id === me.id || !!isAdmin,
        user: { username: c.username, name: c.name || c.username, avatar: c.avatar || "", color: c.color || 0 } })) }, origin);
    }
    if (seg[3] === "comments" && m === "POST") {
      if (await recentCount(db, "comments", me.id) >= COMMENTS_PER_HOUR) return json({ ok: false, reason: "slow_down" }, origin, 429);
      const text = clean(body.body, 300);
      if (!text) return json({ ok: false, reason: "empty" }, origin);
      const r = await db.prepare("INSERT INTO comments (post_id, user_id, body, created) VALUES (?,?,?,?)").bind(pid, me.id, text, now()).run();
      return json({ ok: true, comment: { id: r.meta.last_row_id, body: text, created: now(), mine: true, canDelete: true, user: { username: me.username, name: me.name || me.username, avatar: me.avatar || "", color: me.color || 0 } } }, origin);
    }
  }
  if (seg[1] === "comments" && seg[2] && m === "DELETE") {
    const c = await db.prepare("SELECT c.user_id, p.user_id AS owner FROM comments c JOIN posts p ON p.id=c.post_id WHERE c.id=?").bind(parseInt(seg[2], 10)).first();
    if (!c || (c.user_id !== me.id && c.owner !== me.id && !isAdmin)) return json({ ok: false, reason: "not_yours" }, origin, 403);
    await db.prepare("DELETE FROM comments WHERE id=?").bind(parseInt(seg[2], 10)).run();
    return json({ ok: true }, origin);
  }

  // ---- people ----
  if (seg[1] === "search" && m === "GET") {
    const q = clean(url.searchParams.get("q"), 30).toLowerCase().replace(/[%_]/g, "");
    if (q.length < 2) return json({ ok: true, users: [] }, origin);
    const rows = await db.prepare(`SELECT username, name, avatar, color, private FROM users u WHERE (username LIKE ? OR LOWER(name) LIKE ?) AND id<>?
      AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=? AND b.blocked=u.id) OR (b.blocker=u.id AND b.blocked=?)) ORDER BY username LIMIT 20`)
      .bind(q + "%", "%" + q + "%", me.id, me.id, me.id).all();
    return json({ ok: true, users: rows.results.map(publicUser) }, origin);
  }
  if (seg[1] === "u" && seg[2]) {
    const target = await db.prepare("SELECT * FROM users WHERE username=?").bind(decodeURIComponent(seg[2]).toLowerCase()).first();
    if (!target || await blockedEither(db, me.id, target.id)) return json({ ok: false, reason: "not_found" }, origin, 404);
    if (seg[3] === "follow") {
      if (target.id === me.id) return json({ ok: false, reason: "self" }, origin);
      if (m === "POST") await db.prepare("INSERT OR IGNORE INTO follows (follower, followee, accepted, created) VALUES (?,?,?,?)").bind(me.id, target.id, target.private ? 0 : 1, now()).run();
      if (m === "DELETE") await db.prepare("DELETE FROM follows WHERE follower=? AND followee=?").bind(me.id, target.id).run();
    }
    if (seg[3] === "block") {
      if (target.id === me.id) return json({ ok: false, reason: "self" }, origin);
      if (m === "POST") await db.batch([db.prepare("INSERT OR IGNORE INTO blocks (blocker, blocked) VALUES (?,?)").bind(me.id, target.id),
        db.prepare("DELETE FROM follows WHERE (follower=? AND followee=?) OR (follower=? AND followee=?)").bind(me.id, target.id, target.id, me.id)]);
      return json({ ok: true, blocked: true }, origin);
    }
    const f = await db.prepare("SELECT accepted FROM follows WHERE follower=? AND followee=?").bind(me.id, target.id).first();
    const counts = await db.prepare(`SELECT (SELECT COUNT(*) FROM follows WHERE followee=? AND accepted=1) AS followers,
      (SELECT COUNT(*) FROM follows WHERE follower=? AND accepted=1) AS following,
      (SELECT COUNT(*) FROM books WHERE user_id=? AND status='Finished') AS finished,
      (SELECT COUNT(*) FROM posts WHERE user_id=? AND hidden=0) AS posts`).bind(target.id, target.id, target.id, target.id).first();
    const visible = await canSee(db, me, target);
    const st = await db.prepare("SELECT level, minutes, streak, badges, frame FROM stats WHERE user_id=?").bind(target.id).first();
    const stats = st ? { level: st.level, minutes: st.minutes, streak: st.streak, badges: st.badges ? st.badges.split(",") : [], frame: st.frame || "" } : null;
    const out = { ok: true, stats, user: { ...publicUser(target), frame: stats ? stats.frame : "" }, me: target.id === me.id, follow: f ? (f.accepted ? "following" : "requested") : "none", counts, visible };
    if (visible) {
      out.books = (await db.prepare("SELECT bid AS id, title, author, cover, status, rating, genre, pages, endd AS end FROM books WHERE user_id=? ORDER BY (status='Reading') DESC, endd DESC, title LIMIT 500").bind(target.id).all()).results;
      out.posts = (await db.prepare(`SELECT ${POST_COLS} FROM posts p JOIN users u ON u.id=p.user_id WHERE p.user_id=? AND p.hidden=0 ORDER BY p.id DESC LIMIT 30`).bind(me.id, target.id).all()).results.map(shapePost);
    }
    return json(out, origin);
  }
  if (seg[1] === "requests") {
    if (m === "GET") {
      const rows = await db.prepare("SELECT u.username, u.name, u.avatar, u.color, u.private FROM follows f JOIN users u ON u.id=f.follower WHERE f.followee=? AND f.accepted=0 ORDER BY f.created DESC LIMIT 100").bind(me.id).all();
      return json({ ok: true, users: rows.results.map(publicUser) }, origin);
    }
    if (m === "POST" && seg[2]) {
      const who = await db.prepare("SELECT id FROM users WHERE username=?").bind(decodeURIComponent(seg[2]).toLowerCase()).first();
      if (!who) return json({ ok: false, reason: "not_found" }, origin, 404);
      if (body.accept) await db.prepare("UPDATE follows SET accepted=1 WHERE follower=? AND followee=?").bind(who.id, me.id).run();
      else await db.prepare("DELETE FROM follows WHERE follower=? AND followee=?").bind(who.id, me.id).run();
      return json({ ok: true }, origin);
    }
  }

  // ---- safety ----
  if (seg[1] === "report" && m === "POST") {
    const kind = ["post", "comment", "user"].includes(body.kind) ? body.kind : null;
    let target = parseInt(body.target, 10);
    if (kind === "user") { const u = await db.prepare("SELECT id FROM users WHERE username=?").bind(String(body.target || "").toLowerCase()).first(); target = u && u.id; }
    if (!kind || !target) return json({ ok: false, reason: "bad_report" }, origin);
    await db.prepare("INSERT OR IGNORE INTO reports (reporter, kind, target, reason, created) VALUES (?,?,?,?,?)").bind(me.id, kind, target, clean(body.reason, 200), now()).run();
    const n = await db.prepare("SELECT COUNT(*) AS n FROM reports WHERE kind=? AND target=?").bind(kind, target).first();
    if (n.n >= HIDE_AFTER_REPORTS && kind !== "user") await db.prepare(`UPDATE ${kind === "post" ? "posts" : "comments"} SET hidden=1 WHERE id=?`).bind(target).run();
    return json({ ok: true }, origin);
  }
  if (seg[1] === "admin" && seg[2] === "reports" && m === "GET") {
    if (!isAdmin) return json({ ok: false, reason: "not_admin" }, origin, 403);
    const rows = await db.prepare("SELECT kind, target, COUNT(*) AS n, MAX(created) AS last, GROUP_CONCAT(reason, ' | ') AS reasons FROM reports GROUP BY kind, target ORDER BY last DESC LIMIT 100").all();
    return json({ ok: true, reports: rows.results }, origin);
  }

  return json({ ok: false, reason: "unknown_path" }, origin, 404);
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    if (request.method === "OPTIONS") return new Response(null, { headers: cors(origin) });
    try { return await route(request, env, origin); }
    catch (e) { return json({ ok: false, reason: "server_error" }, origin, 500); }
  },
};
