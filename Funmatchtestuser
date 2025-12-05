/**
 * FunMatch v1.0.10 — Full script with auto-restore & admin restore commands
 * - KV binding required: FUNMATCH
 * - Env vars: TELEGRAM_BOT_TOKEN, ADMIN_IDS (comma-separated), optional WEBHOOK_SECRET
 *
 * Paste this whole file into Cloudflare Workers (Modules runtime).
 */

const MAX_MSG_LEN = 4000;
const WORKER_DEBUG = false;

const VERSIONS_LOG = [
  "fun match v1.0.10 (auto-restore + restore commands)",
].join("\n");

const PRIVACY_POLICY = `FunMatch Bot – Privacy Policy

Effective Date: August 27 2025

By using FunMatch (“the Bot”), you agree to this Privacy Policy. This explains how your information is collected, stored, and used when you interact with the Bot on Telegram.

1. Information We Collect
We store your Telegram user ID, profile details (name, bio, photo), gender, roles, hearts you give (for notification only), and visibility status (sleep mode). We also store simple per-user state and lightweight analytics like pumpkin points and browse counters.

2. How We Use Your Information
Your data is used to create/manage your profile, match you with others, notify hearts, run the pumpkin/halloween event mechanics, and provide admin utilities. We will never sell your data.

3. Data Storage
Data is stored in Cloudflare Workers KV (the FUNMATCH binding). Only keys required for service operation are stored.

4. Data Control & Deletion
You may edit or delete your profile at any time using the menu. Deleting is permanent. Backups are stored when you delete your account for possible restore.

5. Security
We take reasonable measures but no system is 100% secure.

6. Consent
By creating a profile and using FunMatch, you consent to this Privacy Policy.

Powered by L
`;

const HELP_TEXT = `FunMatch — Quick help

Commands:
• /start — create or resume your profile.
• /menu — open the main (inline) menu.
• /matches — view your mutual matches and pending hearts (shows Telegram usernames when available).
• /help — show this help message.
• /halloween_countdown — time until Oct 1 event (UTC).
• /spooky_mode — toggle Halloween border (available Oct 1-31 UTC).
• /trick — send a spooky trick to a random match (Oct event).
• /treat — send a sweet compliment to a random match (Oct event).
• /pumpkin_found — claim a pumpkin you found on a profile (Oct event).
• /restore_my_profile — restore your profile from backup if available.
`;

/* ---------------- Worker entry ---------------- */
export default {
  async fetch(request, env, ctx) {
    if (request.method === 'GET') return new Response('FunMatch Worker: healthy', { status: 200 });
    if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });

    // verify optional webhook secret header
    const headerSecret = request.headers.get('x-telegram-bot-api-secret-token') || request.headers.get('X-Telegram-Bot-Api-Secret-Token');
    if (env.WEBHOOK_SECRET && headerSecret !== env.WEBHOOK_SECRET) {
      if (WORKER_DEBUG) console.warn('Forbidden: webhook secret mismatch');
      return new Response('Forbidden', { status: 403 });
    }

    let update;
    try {
      update = await request.json();
    } catch (err) {
      if (WORKER_DEBUG) console.warn('bad json update', err);
      return new Response('Bad Request', { status: 400 });
    }

    ctx.waitUntil(handleUpdate(update, env, ctx).catch(e => { if (WORKER_DEBUG) console.error('handleUpdate top-level error', e); }));
    return new Response('OK', { status: 200 });
  }
};

/* ---------------- KV helpers ---------------- */
async function kvGetJson(env, key, fallback = null) {
  try { const v = await env.FUNMATCH.get(key, { type: 'json' }); return v === null ? fallback : v; }
  catch (e) { if (WORKER_DEBUG) console.warn('kvGetJson error', key, e); return fallback; }
}
async function kvPutJson(env, key, value) { try { await env.FUNMATCH.put(key, JSON.stringify(value)); } catch (e) { if (WORKER_DEBUG) console.warn('kvPutJson', e); throw e; } }
async function kvGet(env, key, fallback = null) { try { const v = await env.FUNMATCH.get(key); return v === null ? fallback : v; } catch (e) { if (WORKER_DEBUG) console.warn('kvGet', e); return fallback; } }
async function kvPut(env, key, value) { try { await env.FUNMATCH.put(key, String(value)); } catch (e) { if (WORKER_DEBUG) console.warn('kvPut', e); throw e; } }
async function kvDelete(env, key) { try { await env.FUNMATCH.delete(key); } catch (e) { if (WORKER_DEBUG) console.warn('kvDelete', e); } }

/* ---------------- Utilities ---------------- */
function escapeHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
function sanitizeText(text) {
  if (text === null || text === undefined) return '';
  let t = String(text).trim();
  if (t.length > MAX_MSG_LEN) t = t.slice(0, MAX_MSG_LEN - 3) + '...';
  return escapeHtml(t);
}
function parseCommand(text) {
  if (!text) return null;
  const m = text.match(/^\/([a-zA-Z0-9_]+)(?:@[\w_]+)?/);
  return m ? m[1].toLowerCase() : null;
}
function getCommandArgs(text) { if (!text) return ''; return text.replace(/^\/[a-zA-Z0-9_]+(?:@[\w_]+)?\s*/, '').trim(); }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* ---------------- Telegram API ---------------- */
async function telegramApi(env, method, body) {
  const token = env.TELEGRAM_BOT_TOKEN;
  if (!token) {
    if (WORKER_DEBUG) console.error('TELEGRAM_BOT_TOKEN not set');
    return null;
  }
  const url = `https://api.telegram.org/bot${token}/${method}`;
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const text = await res.text().catch(() => '');
    try { return JSON.parse(text); } catch { return text; }
  } catch (e) {
    if (WORKER_DEBUG) console.error('telegramApi fetch error', e);
    return null;
  }
}
async function sendMessage(env, chat_id, text, extra = {}) {
  const msg = sanitizeText(text);
  return telegramApi(env, 'sendMessage', Object.assign({ chat_id, text: msg, parse_mode: 'HTML' }, extra));
}
async function sendPhoto(env, chat_id, photo, extra = {}) {
  return telegramApi(env, 'sendPhoto', Object.assign({ chat_id, photo }, extra));
}
async function answerCallback(env, callback_query_id, text = null, show_alert = false) {
  return telegramApi(env, 'answerCallbackQuery', { callback_query_id, text, show_alert });
}
async function editMessageText(env, chat_id, message_id, text, extra = {}) {
  const msg = sanitizeText(text);
  return telegramApi(env, 'editMessageText', Object.assign({ chat_id, message_id, text: msg, parse_mode: 'HTML' }, extra));
}
async function editMessageCaption(env, chat_id, message_id, caption, extra = {}) {
  const msg = sanitizeText(caption);
  return telegramApi(env, 'editMessageCaption', Object.assign({ chat_id, message_id, caption: msg, parse_mode: 'HTML' }, extra));
}
async function editMessageMedia(env, chat_id, message_id, media, extra = {}) {
  return telegramApi(env, 'editMessageMedia', Object.assign({ chat_id, message_id, media }, extra));
}
async function deleteMessage(env, chat_id, message_id) {
  return telegramApi(env, 'deleteMessage', { chat_id, message_id });
}
async function restrictChatMember(env, chat_id, user_id, permissions = null, until_date = null) {
  const body = { chat_id, user_id: parseInt(String(user_id), 10) };
  if (permissions) body.permissions = permissions;
  if (until_date) body.until_date = until_date;
  return telegramApi(env, 'restrictChatMember', body);
}

/* ---------------- Robust edit-or-reply ---------------- */
async function safeEditOrReply(env, message, newText, reply_markup = null) {
  if (!message || !message.chat) return null;
  const chat_id = message.chat.id;
  const message_id = message.message_id;
  try {
    const res = await editMessageText(env, chat_id, message_id, newText, reply_markup ? { reply_markup } : {});
    if (res && res.ok) return res;
  } catch (e) {}
  try {
    const res = await editMessageCaption(env, chat_id, message_id, newText, reply_markup ? { reply_markup } : {});
    if (res && res.ok) return res;
  } catch (e) {}
  try {
    const originalPhotoId = message.photo && message.photo.length ? message.photo[message.photo.length - 1].file_id : null;
    if (originalPhotoId) {
      const media = { type: 'photo', media: originalPhotoId, caption: newText };
      const res = await editMessageMedia(env, chat_id, message_id, media, reply_markup ? { reply_markup } : {});
      if (res && res.ok) return res;
    }
  } catch (e) {}
  try { return await sendMessage(env, chat_id, newText, reply_markup ? { reply_markup } : {}); } catch (e) { if (WORKER_DEBUG) console.warn('safeEditOrReply fallback failed', e); return null; }
}

/* ---------------- Profiles / hearts / state ---------------- */
async function getProfile(env, userId) {
  const p = await kvGetJson(env, `profile:${userId}`, null);
  return p || { name: null, bio: null, photo: null, sleep: false, agreed: false, gender: null, roles: [], tg_username: null, spooky: false };
}
async function setProfile(env, userId, profile) {
  if (!profile || typeof profile !== 'object') profile = {};
  profile.gender = profile.gender || null;
  profile.roles = Array.isArray(profile.roles) ? profile.roles : (profile.roles ? [String(profile.roles)] : []);
  profile.tg_username = profile.tg_username || null;
  profile.spooky = !!profile.spooky;
  await kvPutJson(env, `profile:${userId}`, profile);
}
async function ensureProfile(env, userId) {
  const p = await getProfile(env, userId);
  const merged = Object.assign({ name: null, bio: null, photo: null, sleep: false, agreed: false, gender: null, roles: [], tg_username: null, spooky: false }, p);
  await setProfile(env, userId, merged);
}
function isProfileComplete(p) {
  if (!p) return false;
  return !!(p.name && p.bio && p.photo && p.agreed);
}
async function getHearts(env, userId) { const v = await kvGet(env, `hearts:${userId}`, '0'); return parseInt(v || '0', 10); }
async function incHearts(env, userId, delta = 1) { const cur = await getHearts(env, userId); const next = cur + delta; await kvPut(env, `hearts:${userId}`, String(next)); return next; }
async function getGiven(env, giverId) { return await kvGetJson(env, `given:${giverId}`, []); }
async function addGiven(env, giverId, targetId) {
  let arr = await getGiven(env, giverId);
  if (!Array.isArray(arr)) arr = [];
  if (arr.includes(String(targetId))) return false;
  arr.push(String(targetId));
  await kvPutJson(env, `given:${giverId}`, arr);
  return true;
}
async function getMatches(env, userId) { return await kvGetJson(env, `matches:${userId}`, []); }
async function addMatch(env, userA, userB) {
  const a = String(userA), b = String(userB);
  let arrA = await kvGetJson(env, `matches:${a}`, []);
  if (!Array.isArray(arrA)) arrA = [];
  if (!arrA.includes(b)) { arrA.push(b); await kvPutJson(env, `matches:${a}`, arrA); }
  let arrB = await kvGetJson(env, `matches:${b}`, []);
  if (!Array.isArray(arrB)) arrB = [];
  if (!arrB.includes(a)) { arrB.push(a); await kvPutJson(env, `matches:${b}`, arrB); }
  return true;
}
async function ensureUserMeta(env, userObj) {
  if (!userObj || !userObj.id) return;
  try {
    const id = String(userObj.id);
    const p = await getProfile(env, id);
    const uname = userObj.username || null;
    if (uname && p.tg_username !== uname) {
      p.tg_username = uname;
      await setProfile(env, id, p);
    }
  } catch (e) { if (WORKER_DEBUG) console.warn('ensureUserMeta error', e); }
}
async function clearUserState(env, userId) { await kvDelete(env, `state:${userId}`); }
async function getState(env, userId) { return await kvGetJson(env, `state:${userId}`, {}); }
async function setState(env, userId, stateObj) { await kvPutJson(env, `state:${userId}`, stateObj); }

/* ---------------- Admin helpers ---------------- */
function getAdminList(env) {
  const envIds = (env.ADMIN_IDS || env.ADMIN_ID || '').toString().trim();
  const arr = envIds ? envIds.split(',').map(s => s.trim()).filter(Boolean) : [];
  if (arr.length === 0) { /* no admin IDs configured; recommended: set ADMIN_IDS env var */ }
  return arr;
}
function isAdmin(env, userId) {
  const u = String(userId);
  const ids = getAdminList(env);
  return ids.includes(u);
}

/* ---------------- Ban helpers ---------------- */
async function banUser(env, userId) { return kvPut(env, `banned:${String(userId)}`, '1'); }
async function unbanUser(env, userId) { return kvDelete(env, `banned:${String(userId)}`); }
async function isUserBanned(env, userId) { const v = await kvGet(env, `banned:${String(userId)}`, null); return v !== null && v !== undefined; }

/* ---------------- Backup / Restore helpers ---------------- */
async function restoreBackupForUser(env, userId) {
  try {
    const key = `profile_backup:${userId}`;
    const backup = await kvGetJson(env, key, null);
    if (!backup || !backup.profile) return { ok: false, reason: 'no_backup' };

    const bp = backup.profile || {};
    // restore profile and associated lightweight data
    await setProfile(env, userId, bp);
    await kvPut(env, `hearts:${userId}`, String(backup.hearts || 0));
    await kvPutJson(env, `given:${userId}`, Array.isArray(backup.given) ? backup.given : []);
    if (Array.isArray(backup.matches)) {
      for (const mid of backup.matches) {
        try { await addMatch(env, userId, mid); } catch (e) {}
      }
    }

    // delete backup after successful restore
    await kvDelete(env, key);
    return { ok: true };
  } catch (e) {
    if (WORKER_DEBUG) console.warn('restoreBackupForUser failed', e);
    return { ok: false, reason: 'error' };
  }
}

async function listAvailableBackups(env) {
  const out = [];
  try {
    const list = await env.FUNMATCH.list({ prefix: 'profile_backup:' });
    for (const k of (list.keys || [])) {
      try {
        const id = k.name.split(':', 2)[1];
        const b = await kvGetJson(env, k.name, null);
        out.push({ id, ts: b && b.ts ? b.ts : null });
      } catch (e) {}
    }
  } catch (e) { if (WORKER_DEBUG) console.warn('listAvailableBackups failed', e); }
  return out;
}

async function restoreAllBackups(env, ctx) {
  let restored = 0, failed = 0, total = 0;
  try {
    const list = await env.FUNMATCH.list({ prefix: 'profile_backup:' });
    const keys = (list.keys || []).map(k => k.name);
    total = keys.length;
    for (const kname of keys) {
      try {
        const id = kname.split(':', 2)[1];
        const res = await restoreBackupForUser(env, id);
        if (res.ok) {
          restored++;
          try { await sendMessage(env, parseInt(id, 10), 'Your profile has been restored — you can now use FunMatch again.'); } catch (e) {}
        } else {
          failed++;
        }
      } catch (e) { failed++; if (WORKER_DEBUG) console.warn('restoreAllBackups per-item error', e); }
    }
  } catch (e) { if (WORKER_DEBUG) console.warn('restoreAllBackups failed', e); }
  return { total, restored, failed };
}

/* helper used for automatic restore when a user interacts */
async function tryAutoRestoreAndNotify(env, userId, chatId) {
  try {
    // if live profile exists nothing to do
    const live = await env.FUNMATCH.get(`profile:${userId}`);
    if (live !== null) return false;

    // if backup exists, restore
    const backup = await kvGetJson(env, `profile_backup:${userId}`, null);
    if (!backup || !backup.profile) return false;

    const res = await restoreBackupForUser(env, userId);
    if (res.ok) {
      try { await sendMessage(env, chatId, 'Your profile has been restored — you can now use FunMatch again.'); } catch (e) {}
      return true;
    }
    return false;
  } catch (e) {
    if (WORKER_DEBUG) console.warn('tryAutoRestoreAndNotify failed', e);
    return false;
  }
}

/* ---------------- Find by username ---------------- */
async function findUserIdByUsername(env, username) {
  if (!username) return null;
  const uname = username.replace(/^@/, '').toLowerCase();
  try {
    const list = await env.FUNMATCH.list({ prefix: 'profile:' });
    for (const k of (list.keys || [])) {
      try {
        const id = k.name.split(':', 2)[1];
        const p = await getProfile(env, id);
        if (p && p.tg_username && String(p.tg_username).toLowerCase() === uname) {
          return id;
        }
      } catch (e) {}
    }
  } catch (e) { if (WORKER_DEBUG) console.warn('findUserIdByUsername failed', e); }
  return null;
}

/* ---------------- Missing profile utilities ---------------- */
async function listProfilesMissing(env) {
  const out = [];
  try {
    const list = await env.FUNMATCH.list({ prefix: 'profile:' });
    for (const k of (list.keys || [])) {
      try {
        const id = k.name.split(':', 2)[1];
        const p = await getProfile(env, id);
        const missingName = !p || !p.name;
        const missingBio = !p || !p.bio;
        const missingPhoto = !p || !p.photo;
        if (missingName || missingBio || missingPhoto) {
          out.push({ id, username: p && p.tg_username ? `@${p.tg_username}` : null, missingName, missingBio, missingPhoto });
        }
      } catch (e) {}
    }
  } catch (e) { if (WORKER_DEBUG) console.warn('listProfilesMissing failed', e); }
  return out;
}
async function notifyMissingProfileOrPhoto(env) {
  try {
    const list = await listProfilesMissing(env);
    for (const m of list) {
      try {
        const todo = [];
        if (m.missingName || m.missingBio) todo.push('complete your profile (set name & bio)');
        if (m.missingPhoto) todo.push('set a profile photo');
        const msg = `Hi${m.username ? ' ' + m.username : ''}! Please ${todo.join(' and ')} to be visible in FunMatch. Use /menu to open the menu or /start to create your profile.`;
        await sendMessage(env, parseInt(m.id, 10), msg);
      } catch (e) {}
    }
  } catch (e) { if (WORKER_DEBUG) console.warn('notifyMissingProfileOrPhoto failed', e); }
}

/* ---------------- Warnings (group moderation) ---------------- */
async function getWarnCount(env, chatId, userId) {
  const k = `warn:${chatId}:${userId}`;
  const v = await kvGet(env, k, '0');
  return parseInt(v || '0', 10);
}
async function setWarnCount(env, chatId, userId, n) { const k = `warn:${chatId}:${userId}`; await kvPut(env, k, String(n)); }
async function incWarnCount(env, chatId, userId) { const cur = await getWarnCount(env, chatId, userId); const next = cur + 1; await setWarnCount(env, chatId, userId, next); return next; }
async function clearWarnCount(env, chatId, userId) { const k = `warn:${chatId}:${userId}`; await kvDelete(env, k); }

/* ---------------- Anti-link per-GC ---------------- */
function messageHasLink(message) {
  if (!message) return false;
  const ents = message.entities || message.caption_entities || [];
  for (const ent of ents || []) {
    if (ent && (ent.type === 'url' || ent.type === 'text_link')) return true;
  }
  const text = (message.text || '') + (message.caption || '');
  if (typeof text === "string" && /https?:\/\//i.test(text)) return true;
  return false;
}
async function handleLinkModeration(message, env) {
  if (!message || !message.from || !message.chat) return false;
  const chatType = message.chat.type;
  if (!(chatType === 'group' || chatType === 'supergroup')) return false;

  const chatId = String(message.chat.id);
  const mode = await kvGet(env, `gcmode:${chatId}`, 'off');
  if (mode !== 'antlink') return false;

  const userId = String(message.from.id);
  if (isAdmin(env, userId)) return false
