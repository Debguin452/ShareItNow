'use strict';
const SESSION_TTL      = 8  * 60 * 60 * 1000;
const RATE_WINDOW_MS   = 15 * 60 * 1000;
const RATE_MAX_LOGIN        = 5;
const RATE_MAX_LOGIN_USER   = 10;
const RATE_MAX_SIGNUP       = 3;
const CHUNK_B64_MAX    = 14 * 1024 * 1024;
const SMALL_MAX_BYTES  =  5 * 1024 * 1024;
const MAX_TOTAL_CHUNKS = 512;
const SHA_RE           = /^[0-9a-f]{40}$/i;
const USERNAME_RE      = /^[a-zA-Z0-9_\-]{3,32}$/;
const CLEAN_NAME_RE    = /^[a-zA-Z0-9][a-zA-Z0-9._\-()\s]{0,253}$/;
const REGISTRY_BRANCH  = 'main';
const OWNER_RE   = /^[a-zA-Z0-9][a-zA-Z0-9\-]{0,37}$/;
const REPO_RE    = /^[a-zA-Z0-9_\.\-]{1,100}$/;
const BRANCH_RE  = /^[a-zA-Z0-9_\.\-\/]{1,250}$/;
const FOLDER_RE  = /^[a-zA-Z0-9_\.\-]{1,100}$/;
const BLOCKED_EXTS = new Set([
  'exe','bat','cmd','com','msi','ps1','psm1',
  'sh','bash','zsh','fish','command',
  'php','php3','php4','php5','php7','php8','phtml','phar',
  'asp','aspx','cshtml','jsp','jspx',
  'py','pyc','pyw','rb','pl','cgi','lua',
  'js','mjs','cjs','ts','tsx','jsx',
  'html','htm','xhtml','svg','xml',
  'htaccess','htpasswd',
  'dll','so','dylib','sys',
  'vbs','vbe','wsf','wsh','hta',
  'jar','war','ear','class',
  'scr','pif','reg','lnk',
  'app','dmg','pkg','deb','rpm','apk',
]);
const BLOCKED_MAGIC = [
  [0,[0x4D,0x5A]],
  [0,[0x7F,0x45,0x4C,0x46]],
  [0,[0xFE,0xED,0xFA,0xCE]],[0,[0xFE,0xED,0xFA,0xCF]],
  [0,[0xCE,0xFA,0xED,0xFE]],[0,[0xCF,0xFA,0xED,0xFE]],
  [0,[0xCA,0xFE,0xBA,0xBE]],
  [0,[0x23,0x21]],
  [0,[0x3C,0x3F,0x70,0x68,0x70]],
  [0,[0x3C,0x73,0x63,0x72,0x69,0x70,0x74]],
  [0,[0x3C,0x68,0x74,0x6D,0x6C]],[0,[0x3C,0x48,0x54,0x4D,0x4C]],
];

const SEC = {
  'X-Content-Type-Options':    'nosniff',
  'X-Frame-Options':           'DENY',
  'Referrer-Policy':           'no-referrer',
  'Permissions-Policy':        'camera=(), microphone=(), geolocation=(), payment=(), usb=(), display-capture=(), clipboard-read=(), clipboard-write=(), screen-wake-lock=(), accelerometer=(), gyroscope=(), magnetometer=()',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'Content-Security-Policy':
    "default-src 'none'; script-src 'none'; " +
    "style-src 'none'; img-src 'none'; " +
    "connect-src 'self'; frame-ancestors 'none'; form-action 'none'; base-uri 'none';",
  'Cache-Control': 'no-store',
};
function corsHeaders(req) {
  const o = req.headers.get('Origin') || '';
  const h = req.headers.get('Host')   || '';
  const ok = o === `https://${h}` || o === `http://${h}`;
  return {
    'Access-Control-Allow-Origin':      ok ? o : 'null',
    'Access-Control-Allow-Methods':     'GET,POST,DELETE,OPTIONS',
    'Access-Control-Allow-Headers':     'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin',
  };
}
function jsonRes(req, data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...SEC, ...corsHeaders(req), 'Content-Type': 'application/json', ...extra },
  });
}
const ERRS = {
  400:'Bad request', 401:'Invalid credentials', 403:'Forbidden',
  404:'Not found',   409:'Username already taken',
  413:'Payload too large', 415:'File type not permitted',
  429:'Too many attempts — please wait and try again',
  500:'Server error', 502:'Upstream error',
};
const fail = (req, code) => jsonRes(req, { error: ERRS[code] || 'Error' }, code);
const ENC = new TextEncoder();
const DEC = new TextDecoder();
function b64Enc(u8) {
  const C = 0x8000; let s = '';
  for (let i = 0; i < u8.length; i += C)
    s += String.fromCharCode(...u8.subarray(i, Math.min(i + C, u8.length)));
  return btoa(s);
}
function b64Dec(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
function b64urlEnc(u8) { return b64Enc(u8).replace(/\+/g,'-').replace(/\
function b64urlDec(s) {
  const p = s.replace(/-/g,'+').replace(/_/g,'/');
  return b64Dec(p + '='.repeat((4 - p.length%4)%4));
}
function ab2b64(buf) { return b64Enc(new Uint8Array(buf)); }
function hexEnc(u8) { return Array.from(u8).map(b=>b.toString(16).padStart(2,'0')).join(''); }
async function gitBlobSha(buffer) {
  const prefix = ENC.encode(`blob ${buffer.byteLength}\0`);
  const combined = new Uint8Array(prefix.byteLength + buffer.byteLength);
  combined.set(prefix);
  combined.set(new Uint8Array(buffer));
  const hash = await crypto.subtle.digest('SHA-1', combined);
  return hexEnc(new Uint8Array(hash));
}
function utf8b64(str) {
  return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
    (_,p1) => String.fromCharCode(parseInt(p1,16))));
}
const chunkDir   = (folder, name)       => `${folder}/.chunks/${name}`;
const chunkPath  = (folder, name, idx)  => `${folder}/.chunks/${name}/${name}.part${idx}`;
const manifestP  = (folder, name)       => `${folder}/.manifests/${name}.json`;
const indexP     = (folder)             => `${folder}/.manifests/_index.json`;
async function deriveKey(secret, label, usage) {
  const raw = await crypto.subtle.importKey('raw', ENC.encode(secret), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'HKDF', hash:'SHA-256', salt:ENC.encode('StoreGit-v1'), info:ENC.encode(label) },
    raw, { name:'AES-GCM', length:256 }, false, usage
  );
}
async function aesEncrypt(plaintext, secret, label='enc') {
  const key = await deriveKey(secret, label, ['encrypt']);
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, ENC.encode(plaintext));
  return { iv: b64urlEnc(iv), ct: b64urlEnc(new Uint8Array(ct)) };
}
async function aesDecrypt(enc, secret, label='enc') {
  const key = await deriveKey(secret, label, ['decrypt']);
  const pt  = await crypto.subtle.decrypt(
    { name:'AES-GCM', iv: b64urlDec(enc.iv) }, key, b64urlDec(enc.ct)
  );
  return DEC.decode(pt);
}
async function hmacSign(data, secret) {
  const k = await crypto.subtle.importKey('raw', ENC.encode(secret),
    { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const s = await crypto.subtle.sign('HMAC', k, ENC.encode(data));
  return b64urlEnc(new Uint8Array(s));
}
async function timingSafeEq(a, b) {
  const k = await crypto.subtle.importKey('raw', ENC.encode('_cmp_'),
    { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const [ha, hb] = await Promise.all([
    crypto.subtle.sign('HMAC', k, ENC.encode(String(a))),
    crypto.subtle.sign('HMAC', k, ENC.encode(String(b))),
  ]);
  const ua = new Uint8Array(ha), ub = new Uint8Array(hb);
  let d = 0; for (let i = 0; i < ua.length; i++) d |= ua[i] ^ ub[i];
  return d === 0;
}
const PBKDF2_ITERS_CURRENT = 100_000;
const PBKDF2_ITERS_LEGACY  =  50_000;
async function pbkdf2Hash(password, salt, iterations = PBKDF2_ITERS_CURRENT) {
  const km = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name:'PBKDF2', salt, iterations, hash:'SHA-256' }, km, 256
  ));
}
async function blobTokenSign(jti, safeName, index, blobSha, secret) {
  return hmacSign(`blob:${jti}:${safeName}:${index}:${blobSha}`, secret);
}
function contentDisposition(safeName) {
  const ascii = safeName.replace(/[^\x20-\x7E]/g, '_').replace(/["\\/]/g, '_');
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(safeName)}`;
}
async function getFullSession(sess, env, secret) {
  if (!sess || !sess.username) return null;
  const rec = await getUser(sess.username, env).catch(() => null);
  if (!rec) return null;
  const { content: user } = rec;
  let ghToken;
  try { ghToken = await aesDecrypt(user.encGhToken, secret, `user-token:${user.username}`); }
  catch { return null; }
  return {
    ...sess,
    ghToken,
    ghOwner:  user.ghOwner,
    ghRepo:   user.ghRepo,
    ghBranch: user.ghBranch,
    folder:   user.folder,
  };
}
async function createToken(payload, secret) {
  const full = { ...payload, jti: hexEnc(crypto.getRandomValues(new Uint8Array(16))), exp: Date.now() + SESSION_TTL };
  const enc  = await aesEncrypt(JSON.stringify(full), secret, 'session');
  const body = b64urlEnc(ENC.encode(JSON.stringify(enc)));
  return `${body}.${await hmacSign(body, secret)}`;
}
async function verifyToken(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return null;
  const body = token.slice(0, dot), sig = token.slice(dot+1);
  if (!(await timingSafeEq(sig, await hmacSign(body, secret)))) return null;
  try {
    const enc  = JSON.parse(DEC.decode(b64urlDec(body)));
    const data = JSON.parse(await aesDecrypt(enc, secret, 'session'));
    return Date.now() > data.exp ? null : data;
  } catch { return null; }
}
function getIP(req) {
  return req.headers.get('CF-Connecting-IP') ||
    req.headers.get('X-Forwarded-For')?.split(',')[0].trim() || 'unknown';
}
async function checkRate(key, max, env) {
  const now = Date.now();
  const r = await env.RATE_LIMIT_KV.get(key, 'json').catch(() => null);
  if (!r || now > r.resetAt) {
    const f = { count: 1, resetAt: now + RATE_WINDOW_MS };
    await env.RATE_LIMIT_KV.put(key, JSON.stringify(f), { expirationTtl: Math.ceil(RATE_WINDOW_MS / 1000) }).catch(() => {});
    return false;
  }
  r.count++;
  await env.RATE_LIMIT_KV.put(key, JSON.stringify(r), { expirationTtl: Math.ceil((r.resetAt - now) / 1000) }).catch(() => {});
  return r.count > max;
}
async function clearRate(key, env) {
  await env.RATE_LIMIT_KV.delete(key).catch(() => {});
}
function sanitize(name) {
  if (!name || typeof name !== 'string') return null;
  const s = name.replace(/\0/g,'').replace(/\.\./g,'').replace(/[/\\]/g,'').trim();
  if (!s) return null;
  const safe = s.replace(/[^a-zA-Z0-9._\-()\s]/g,'_');
  if (!CLEAN_NAME_RE.test(safe)) return null;
  const ext = safe.split('.').pop()?.toLowerCase() || '';
  if (BLOCKED_EXTS.has(ext)) return null;
  return safe;
}
function checkMagic(bytes) {
  for (const [off, pat] of BLOCKED_MAGIC) {
    let ok = true;
    for (let i = 0; i < pat.length; i++) { if (bytes[off+i] !== pat[i]) { ok=false; break; } }
    if (ok) return false;
  }
  return true;
}
function checkMagicBase64(b64) {
  try {
    const prefix = b64.slice(0, 24).replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(prefix);
    const head = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) head[i] = bin.charCodeAt(i);
    return checkMagic(head);
  } catch { return false; }
}
const regH = env => ({
  Authorization: `token ${env.REGISTRY_GITHUB_TOKEN}`,
  Accept: 'application/vnd.github.v3+json',
  'Content-Type': 'application/json',
  'User-Agent': 'StoreGit/1',
});
const regBase = env =>
  `https://api.github.com/repos/${encodeURIComponent(env.REGISTRY_GITHUB_OWNER)}/${encodeURIComponent(env.REGISTRY_GITHUB_REPO)}`;
async function readReg(path, env) {
  const res = await fetch(`${regBase(env)}/contents/${path}?ref=${REGISTRY_BRANCH}`, { headers: regH(env) });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error('reg_read_fail');
  const d = await res.json();
  return { content: JSON.parse(atob(d.content.replace(/\s/g,''))), sha: d.sha };
}
async function writeReg(path, content, msg, env, sha = null) {
  const res = await fetch(`${regBase(env)}/contents/${path}`, {
    method: 'PUT', headers: regH(env),
    body: JSON.stringify({ message: msg, content: btoa(JSON.stringify(content,null,2)), branch: REGISTRY_BRANCH, ...(sha?{sha}:{}) }),
  });
  if (!res.ok) throw new Error('reg_write_fail');
  return (await res.json()).content?.sha;
}
function userPath(username) { return `users/${username.toLowerCase()}.json`; }
async function getUser(username, env) {
  if (!USERNAME_RE.test(username)) return null;
  return readReg(userPath(username), env).catch(() => null);
}
const ghH = token => ({
  Authorization: `token ${token}`,
  Accept: 'application/vnd.github.v3+json',
  'Content-Type': 'application/json',
  'User-Agent': 'StoreGit/1',
});
async function listFiles(sess) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const res = await fetch(
    `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/contents/${encodeURIComponent(folder)}?ref=${encodeURIComponent(ghBranch)}`,
    { headers: ghH(ghToken) }
  );
  if (res.status === 404) return [];
  if (!res.ok) throw new Error('list_fail');
  const data = await res.json();
  return Array.isArray(data)
    ? data
        .filter(f => f.type === 'file' && f.name !== '.storegit')
        .map(f => ({ name: f.name, size: f.size, sha: f.sha }))
    : [];
}
async function readIndex(sess) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const url = `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/contents/${encodeURIComponent(indexP(folder))}?ref=${encodeURIComponent(ghBranch)}`;
  const res = await fetch(url, { headers: ghH(ghToken) });
  if (res.status === 404) return { data: {}, sha: null };
  if (!res.ok) return { data: {}, sha: null };
  const d = await res.json();
  return { data: JSON.parse(atob(d.content.replace(/\s/g,''))), sha: d.sha };
}
async function writeIndex(sess, data, existingSha) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const url = `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/contents/${encodeURIComponent(indexP(folder))}`;
  const res = await fetch(url, {
    method: 'PUT', headers: ghH(ghToken),
    body: JSON.stringify({
      message: 'StoreGit: update index',
      content: utf8b64(JSON.stringify(data, null, 2)),
      branch: ghBranch,
      ...(existingSha ? { sha: existingSha } : {}),
    }),
  });
  if (!res.ok) throw new Error('index_write_fail');
}
async function createBlob(sess, b64Content) {
  const { ghToken, ghOwner, ghRepo } = sess;
  const res = await fetch(
    `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/git/blobs`,
    { method:'POST', headers: ghH(ghToken), body: JSON.stringify({ content: b64Content, encoding:'base64' }) }
  );
  if (!res.ok) throw new Error('blob_fail');
  return (await res.json()).sha;
}
async function uploadSmall(sess, filename, b64) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const url = `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/contents/${encodeURIComponent(folder)}/${encodeURIComponent(filename)}`;
  let sha = null;
  const chk = await fetch(`${url}?ref=${ghBranch}`, { headers: ghH(ghToken) });
  if (chk.ok) sha = (await chk.json()).sha;
  const res = await fetch(url, {
    method:'PUT', headers: ghH(ghToken),
    body: JSON.stringify({ message:`Upload ${filename}`, content: b64, branch: ghBranch, ...(sha?{sha}:{}) }),
  });
  if (!res.ok) throw new Error('upload_fail');
}
async function finalizeChunkedUpload(sess, safeName, blobs, totalSize, chunkSize) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const gh   = ghH(ghToken);
  const base = `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}`;
  const manifest = {
    name: safeName, totalSize, totalChunks: blobs.length, chunkSize,
    uploadedAt: new Date().toISOString(),
    chunks: blobs.map(b => ({ index: b.index, size: b.size, blobSha: b.blobSha })),
  };
  const manifestBlobSha = await createBlob(sess, utf8b64(JSON.stringify(manifest, null, 2)));
  const refRes = await fetch(`${base}/git/ref/heads/${ghBranch}`, { headers: gh });
  if (!refRes.ok) throw new Error('ref_fail');
  const { object: { sha: headSha } } = await refRes.json();
  const commitRes = await fetch(`${base}/git/commits/${headSha}`, { headers: gh });
  if (!commitRes.ok) throw new Error('commit_read_fail');
  const { tree: { sha: treeSha } } = await commitRes.json();
  const treeItems = blobs.map(b => ({
    path: chunkPath(folder, safeName, b.index),
    mode: '100644', type: 'blob', sha: b.blobSha,
  }));
  treeItems.push({
    path: manifestP(folder, safeName),
    mode: '100644', type: 'blob', sha: manifestBlobSha,
  });
  const newTreeRes = await fetch(`${base}/git/trees`, {
    method: 'POST', headers: gh,
    body: JSON.stringify({ base_tree: treeSha, tree: treeItems }),
  });
  if (!newTreeRes.ok) throw new Error('tree_fail');
  const { sha: newTreeSha } = await newTreeRes.json();
  const newCommitRes = await fetch(`${base}/git/commits`, {
    method: 'POST', headers: gh,
    body: JSON.stringify({
      message: `Upload ${safeName} (${blobs.length} parts)`,
      tree: newTreeSha, parents: [headSha],
    }),
  });
  if (!newCommitRes.ok) throw new Error('commit_fail');
  const { sha: newCommit } = await newCommitRes.json();
  const updateRes = await fetch(`${base}/git/refs/heads/${ghBranch}`, {
    method: 'PATCH', headers: gh,
    body: JSON.stringify({ sha: newCommit, force: false }),
  });
  if (!updateRes.ok) throw new Error('ref_update_fail');
}
async function deleteChunked(sess, safeName) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const gh   = ghH(ghToken);
  const base = `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}`;
  const chunkDirUrl = `${base}/contents/${chunkDir(folder, safeName)}?ref=${ghBranch}`;
  const chunkDirRes = await fetch(chunkDirUrl, { headers: gh });
  let chunkFiles = [];
  if (chunkDirRes.ok) {
    const d = await chunkDirRes.json();
    chunkFiles = Array.isArray(d) ? d.filter(f => f.type === 'file') : [];
  }
  const refRes = await fetch(`${base}/git/ref/heads/${ghBranch}`, { headers: gh });
  if (!refRes.ok) throw new Error('ref_fail');
  const { object: { sha: headSha } } = await refRes.json();
  const commitRes = await fetch(`${base}/git/commits/${headSha}`, { headers: gh });
  if (!commitRes.ok) throw new Error('commit_read_fail');
  const { tree: { sha: treeSha } } = await commitRes.json();
  const treeItems = [
    ...chunkFiles.map(f => ({
      path: `${chunkDir(folder, safeName)}/${f.name}`,
      mode: '100644', type: 'blob', sha: null,
    })),
    { path: manifestP(folder, safeName), mode: '100644', type: 'blob', sha: null },
  ];
  const newTreeRes = await fetch(`${base}/git/trees`, {
    method: 'POST', headers: gh,
    body: JSON.stringify({ base_tree: treeSha, tree: treeItems }),
  });
  if (!newTreeRes.ok) throw new Error('tree_fail');
  const { sha: newTreeSha } = await newTreeRes.json();
  const newCommitRes = await fetch(`${base}/git/commits`, {
    method: 'POST', headers: gh,
    body: JSON.stringify({ message: `Delete ${safeName}`, tree: newTreeSha, parents: [headSha] }),
  });
  if (!newCommitRes.ok) throw new Error('commit_fail');
  const { sha: newCommit } = await newCommitRes.json();
  const updateRes = await fetch(`${base}/git/refs/heads/${ghBranch}`, {
    method: 'PATCH', headers: gh, body: JSON.stringify({ sha: newCommit, force: false }),
  });
  if (!updateRes.ok) throw new Error('ref_update_fail');
}
async function deleteRegular(sess, filename, sha) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const res = await fetch(
    `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/contents/${encodeURIComponent(folder)}/${encodeURIComponent(filename)}`,
    { method:'DELETE', headers: ghH(ghToken), body: JSON.stringify({ message:`Delete ${filename}`, sha, branch: ghBranch }) }
  );
  if (!res.ok) throw new Error('delete_fail');
}
const MIMES = {
  pdf:'application/pdf', doc:'application/msword',
  docx:'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls:'application/vnd.ms-excel',
  xlsx:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt:'application/vnd.ms-powerpoint',
  pptx:'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  txt:'text/plain;charset=utf-8', csv:'text/plain;charset=utf-8',
  md:'text/plain;charset=utf-8', rtf:'application/rtf',
  jpg:'image/jpeg', jpeg:'image/jpeg', png:'image/png',
  gif:'image/gif', webp:'image/webp', bmp:'image/bmp',
  mp3:'audio/mpeg', wav:'audio/wav', ogg:'audio/ogg',
  flac:'audio/flac', m4a:'audio/mp4', aac:'audio/aac',
  mp4:'video/mp4', webm:'video/webm', mov:'video/quicktime',
  avi:'video/x-msvideo', mkv:'video/x-matroska',
  zip:'application/zip', gz:'application/gzip',
  tar:'application/x-tar', '7z':'application/x-7z-compressed', rar:'application/vnd.rar',
  json:'text/plain;charset=utf-8', yaml:'text/plain;charset=utf-8', yml:'text/plain;charset=utf-8',
};
const safeMime = name => MIMES[name.split('.').pop()?.toLowerCase()||''] || 'application/octet-stream';
export async function onRequest({ request, env, params }) {
  try {
    return await _handleRequest({ request, env, params });
  } catch (err) {
    const msg = (err instanceof Error) ? err.message : String(err);
    console.error('[StoreGit] Unhandled error:', msg, err?.stack || '');
    return new Response(
      JSON.stringify({ error: 'An unexpected server error occurred.' }),
      { status: 500, headers: { ...SEC, 'Content-Type': 'application/json' } }
    );
  }
}
async function _handleRequest({ request, env, params }) {
  const method = request.method.toUpperCase();
  const route  = (params.path || []).join('/');
  if (method === 'OPTIONS') {
    return new Response(null, { status:204, headers: { ...SEC, ...corsHeaders(request) } });
  }
  const secret = env.TOKEN_SECRET;
  if (!secret) return fail(request, 500);
  if (route === 'status' && method === 'GET') {
    return jsonRes(request, {
      ready: !!(env.REGISTRY_GITHUB_TOKEN && env.REGISTRY_GITHUB_OWNER && env.REGISTRY_GITHUB_REPO),
    });
  }
  if (route === 'signup' && method === 'POST') {
    const ip = getIP(request);
    if (await checkRate(`signup:${ip}`, RATE_MAX_SIGNUP, env)) return fail(request, 429);
    let body; try { body = await request.json(); } catch { return fail(request, 400); }
    const { username, password, ghToken, ghOwner, ghRepo, ghBranch='main', folder='uploads' } = body||{};
    if (!username||!password||!ghToken||!ghOwner||!ghRepo) return fail(request, 400);
    if (!USERNAME_RE.test(username)) return jsonRes(request,{error:'Username must be 3–32 chars: letters, numbers, hyphens, underscores'},400);
    if (password.length < 8) return jsonRes(request,{error:'Password must be at least 8 characters'},400);
    if (!OWNER_RE.test(ghOwner))   return jsonRes(request,{error:"Invalid GitHub owner name"},400);
    if (!REPO_RE.test(ghRepo))     return jsonRes(request,{error:"Invalid GitHub repository name"},400);
    if (!BRANCH_RE.test(ghBranch)) return jsonRes(request,{error:"Invalid branch name"},400);
    if (!FOLDER_RE.test(folder))   return jsonRes(request,{error:"Invalid folder name (letters, numbers, hyphens, underscores, dots only)"},400);
    if (await getUser(username, env)) return fail(request, 409);
    if (!/^(ghp_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{80,})$/.test(ghToken))
      return jsonRes(request, {error: 'Invalid GitHub token format'}, 400);
    const repoCheck = await fetch(
      `https://api.github.com/repos/${ghOwner}/${ghRepo}`,
      { headers:{ Authorization:`token ${ghToken}`, Accept:'application/vnd.github.v3+json', 'User-Agent':'StoreGit/1' } }
    );
    if (repoCheck.status===401) return jsonRes(request,{error:'Invalid GitHub token'},400);
    if (repoCheck.status===404) return jsonRes(request,{error:'Repository not found'},400);
    if (!repoCheck.ok) return jsonRes(request,{error:'GitHub validation failed'},400);
    const repoData = await repoCheck.json();
    if (!repoData.permissions?.push && !repoData.permissions?.admin)
      return jsonRes(request,{error:'Token requires write access to this repository'},400);
    const salt   = crypto.getRandomValues(new Uint8Array(16));
    const pwHash = await pbkdf2Hash(password, salt);
    const encGhToken = await aesEncrypt(ghToken, secret, `user-token:${username.toLowerCase()}`);
    const userRecord = {
      username: username.toLowerCase(), displayName: username,
      pwSalt: b64urlEnc(salt), pwHash: b64urlEnc(pwHash),
      encGhToken, ghOwner, ghRepo, ghBranch, folder,
      createdAt: new Date().toISOString(),
    };
    try { await writeReg(userPath(username), userRecord, `Register ${username.toLowerCase()}`, env); }
    catch { return fail(request, 502); }
    const markerUrl = `https://api.github.com/repos/${ghOwner}/${ghRepo}/contents/${folder}/.storegit`;
    const markerChk = await fetch(`${markerUrl}?ref=${ghBranch}`, { headers: ghH(ghToken) });
    if (markerChk.status === 404) {
      await fetch(markerUrl, {
        method:'PUT', headers: ghH(ghToken),
        body: JSON.stringify({
          message:'Initialize StoreGit storage',
          content: utf8b64(`# StoreGit Storage\nManaged by StoreGit. Do not delete this file.\nUser: ${username}\n`),
          branch: ghBranch,
        }),
      }).catch(()=>{});
    }
    return jsonRes(request, { ok:true });
  }
  if (route === 'auth' && method === 'POST') {
    const ip = getIP(request);
    if (await checkRate(`login:${ip}`, RATE_MAX_LOGIN, env)) return fail(request, 429);
    let body; try { body = await request.json(); } catch { return fail(request, 400); }
    const { username, password } = body||{};
    if (!username||!password) return fail(request, 400);
    if (await checkRate(`login:user:${username.toLowerCase()}`, RATE_MAX_LOGIN_USER, env)) return fail(request, 429);
    const rec = await getUser(username, env);
    if (!rec) {
      await pbkdf2Hash(password, crypto.getRandomValues(new Uint8Array(16)));
      await new Promise(r=>setTimeout(r,100+Math.random()*200));
      return fail(request, 401);
    }
    const { content: user } = rec;
    const salt   = b64urlDec(user.pwSalt);
    const stored = b64urlDec(user.pwHash);
    const derivedCurrent = await pbkdf2Hash(password, salt, PBKDF2_ITERS_CURRENT);
    let diffCurrent = 0; for (let i = 0; i < 32; i++) diffCurrent |= derivedCurrent[i] ^ (stored[i] ?? 0);
    if (diffCurrent !== 0) {
      const derivedLegacy = await pbkdf2Hash(password, salt, PBKDF2_ITERS_LEGACY);
      let diffLegacy = 0; for (let i = 0; i < 32; i++) diffLegacy |= derivedLegacy[i] ^ (stored[i] ?? 0);
      if (diffLegacy !== 0) {
        await new Promise(r => setTimeout(r, 300 + Math.random() * 200));
        return fail(request, 401);
      }
    }
    await clearRate(`login:${ip}`, env);
    await clearRate(`login:user:${user.username}`, env);
    let ghToken;
    try { ghToken = await aesDecrypt(user.encGhToken, secret, `user-token:${user.username}`); }
    catch { return fail(request, 500); }
    const token = await createToken({
      username: user.username, display: user.displayName||user.username,
    }, secret);
    return jsonRes(request, { ok:true, display: user.displayName||user.username }, 200, {
      'Set-Cookie': `__Host-sg_sess=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL/1000}`,
    });
  }
  if (route === 'logout' && method === 'POST') {
    return jsonRes(request, { ok:true }, 200, {
      'Set-Cookie': '__Host-sg_sess=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0',
    });
  }
  const _cookieHdr = request.headers.get('Cookie') || '';
  const rawToken   = (_cookieHdr.match(/(?:^|;\s*)__Host-sg_sess=([^;]+)/))?.[1] || '';
  const sess       = await verifyToken(rawToken, secret);
  if (!sess) return fail(request, 401);
  const fullSess = await getFullSession(sess, env, secret);
  if (!fullSess) return fail(request, 401);
  if (route === 'me' && method === 'GET') {
    return jsonRes(request, {
      username: fullSess.username, display: fullSess.display,
      repo: `${fullSess.ghOwner}/${fullSess.ghRepo}`, folder: fullSess.folder,
    });
  }
  if (route === 'files' && method === 'GET') {
    try {
      const [regular, { data: idx }] = await Promise.all([
        listFiles(fullSess),
        readIndex(fullSess).catch(() => ({ data: {} })),
      ]);
      const chunked = Object.entries(idx)
        .filter(([, info]) => info.totalChunks)
        .map(([name, info]) => ({
          name, size: info.totalSize, sha: '', chunked: true,
          parts: info.totalChunks, uploadedAt: info.uploadedAt || null,
        }));
      const chunkedNames = new Set(chunked.map(f => f.name));
      const cleanRegular = regular
        .filter(f => !chunkedNames.has(f.name))
        .map(f => ({ ...f, uploadedAt: idx[f.name]?.uploadedAt || null, chunked: false }));
      const all = [...cleanRegular, ...chunked].sort((a, b) => {
        if (!a.uploadedAt && !b.uploadedAt) return 0;
        if (!a.uploadedAt) return 1;
        if (!b.uploadedAt) return -1;
        return new Date(b.uploadedAt) - new Date(a.uploadedAt);
      });
      return jsonRes(request, all);
    } catch { return fail(request, 502); }
  }
  if (route === 'upload' && method === 'POST') {
    if (!(request.headers.get('Content-Type')||'').includes('application/json')) return fail(request,400);
    let body; try { body = await request.json(); } catch { return fail(request,400); }
    const { name: rawName, content: b64 } = body||{};
    if (!rawName || !b64 || typeof b64 !== 'string') return fail(request,400);
    if (b64.length > CHUNK_B64_MAX) return fail(request,413);
    const safe = sanitize(String(rawName));
    if (!safe) return fail(request,415);
    if (!checkMagicBase64(b64)) return fail(request,415);
    const decodedSize = Math.floor(b64.length * 3 / 4);
    try {
      if (decodedSize > SMALL_MAX_BYTES) {
        const blobSha = await createBlob(fullSess, b64);
        const { ghToken, ghOwner, ghRepo, ghBranch, folder } = fullSess;
        const gh   = ghH(ghToken);
        const base = `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}`;
        const refRes = await fetch(`${base}/git/ref/heads/${encodeURIComponent(ghBranch)}`, { headers:gh });
        if (!refRes.ok) throw new Error('ref_fail');
        const { object:{ sha:headSha } } = await refRes.json();
        const commitRes = await fetch(`${base}/git/commits/${headSha}`, { headers:gh });
        const { tree:{ sha:treeSha } } = await commitRes.json();
        const newTreeRes = await fetch(`${base}/git/trees`, {
          method:'POST', headers:gh,
          body: JSON.stringify({ base_tree:treeSha, tree:[{ path:`${folder}/${safe}`, mode:'100644', type:'blob', sha:blobSha }] }),
        });
        const { sha:newTree } = await newTreeRes.json();
        const newCommitRes = await fetch(`${base}/git/commits`, {
          method:'POST', headers:gh,
          body: JSON.stringify({ message:`Upload ${safe}`, tree:newTree, parents:[headSha] }),
        });
        const { sha:newCommit } = await newCommitRes.json();
        await fetch(`${base}/git/refs/heads/${ghBranch}`, {
          method:'PATCH', headers:gh, body: JSON.stringify({ sha:newCommit, force:false }),
        });
      } else {
        await uploadSmall(fullSess, safe, b64);
      }
      try {
        const { data: idx, sha: idxSha } = await readIndex(fullSess);
        idx[safe] = { uploadedAt: new Date().toISOString(), size: decodedSize };
        await writeIndex(fullSess, idx, idxSha);
      } catch {}
      return jsonRes(request, { ok:true, name:safe, size:decodedSize });
    } catch { return fail(request, 502); }
  }
  if (route === 'upload-chunk' && method === 'POST') {
    if (!(request.headers.get('Content-Type')||'').includes('application/json')) return fail(request,400);
    let body; try { body = await request.json(); } catch { return fail(request,400); }
    const { name: rawName, chunkIndex, totalChunks, content: b64 } = body||{};
    if (!rawName || !b64 || typeof b64 !== 'string') return fail(request,400);
    if (b64.length > CHUNK_B64_MAX) return fail(request,413);
    const idx = parseInt(chunkIndex, 10);
    const tot = parseInt(totalChunks, 10);
    if (isNaN(idx)||idx<0) return fail(request,400);
    if (isNaN(tot)||tot<1||tot>MAX_TOTAL_CHUNKS) return fail(request,400);
    const safe = sanitize(String(rawName));
    if (!safe) return fail(request,415);
    if (idx === 0 && !checkMagicBase64(b64)) return fail(request,415);
    const decodedSize = Math.floor(b64.length * 3 / 4);
    try {
      const blobSha   = await createBlob(fullSess, b64);   // forward directly — no re-encoding
      const blobToken = await blobTokenSign(sess.jti, safe, idx, blobSha, secret);
      return jsonRes(request, { ok:true, blobSha, blobToken, index: idx, size: decodedSize });
    } catch { return fail(request, 502); }
  }
  if (route === 'finalize-upload' && method === 'POST') {
    let body; try { body = await request.json(); } catch { return fail(request,400); }
    const { name, totalSize, totalChunks, chunkSize, blobs } = body||{};
    if (!name||!totalSize||!totalChunks||!Array.isArray(blobs)) return fail(request,400);
    if (blobs.length !== totalChunks) return fail(request,400);
    if (totalChunks > MAX_TOTAL_CHUNKS) return fail(request,413);
    const MAX_FILE_BYTES = MAX_TOTAL_CHUNKS * CHUNK_B64_MAX;
    if (!Number.isInteger(totalSize) || totalSize < 1 || totalSize > MAX_FILE_BYTES)
      return fail(request, 400);
    if (chunkSize !== undefined && (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > CHUNK_B64_MAX))
      return fail(request, 400);
    const safe = sanitize(String(name));
    if (!safe) return fail(request, 415);
    for (const b of blobs) {
      if (typeof b.blobSha   !== 'string' || !SHA_RE.test(b.blobSha)) return fail(request,400);
      if (typeof b.blobToken !== 'string')                             return fail(request,400);
      if (typeof b.index     !== 'number' || b.index < 0)             return fail(request,400);
      if (typeof b.size      !== 'number' || b.size  < 1)             return fail(request,400);
      const expected = await blobTokenSign(sess.jti, safe, b.index, b.blobSha, secret);
      if (!(await timingSafeEq(b.blobToken, expected))) return fail(request, 403);
    }
    try {
      await finalizeChunkedUpload(fullSess, safe, blobs, totalSize, chunkSize);
      const { data: idx, sha: idxSha } = await readIndex(fullSess);
      idx[safe] = { totalSize, totalChunks, uploadedAt: new Date().toISOString() };
      await writeIndex(fullSess, idx, idxSha);
      return jsonRes(request, { ok:true, name:safe });
    } catch { return fail(request, 502); }
  }
  if (route === 'download' && method === 'GET') {
    const nameParam = new URL(request.url).searchParams.get('name') || '';
    const safe = sanitize(nameParam);
    if (!safe) return fail(request,400);
    const { ghToken, ghOwner, ghRepo, ghBranch, folder } = fullSess;
    let manifest = null;
    try {
      const { data: idx } = await readIndex(fullSess);
      if (idx[safe]) {
        const mUrl = `https://api.github.com/repos/${ghOwner}/${ghRepo}/contents/${manifestP(folder,safe)}?ref=${ghBranch}`;
        const mRes = await fetch(mUrl, { headers: ghH(ghToken) });
        if (mRes.ok) {
          const mData = await mRes.json();
          manifest = JSON.parse(atob(mData.content.replace(/\s/g,'')));
        }
      }
    } catch {}
    if (manifest) {
      const totalChunks = manifest.totalChunks;
      const rawBase = `https://raw.githubusercontent.com/${ghOwner}/${ghRepo}/${ghBranch}`;
      const authHeader = { Authorization:`token ${ghToken}`, 'User-Agent':'StoreGit/1' };
      const stream = new ReadableStream({
        async start(controller) {
          try {
            for (let i = 0; i < totalChunks; i++) {
              const cp = chunkPath(folder, safe, i);
              const res = await fetch(`${rawBase}/${cp}`, { headers: authHeader });
              if (!res.ok) { controller.error(new Error(`chunk_${i}_missing`)); return; }
              const buf = await res.arrayBuffer();
              const expected = manifest.chunks?.[i]?.blobSha;
              if (expected) {
                const actual = await gitBlobSha(buf);
                if (actual !== expected) { controller.error(new Error(`chunk_${i}_corrupt`)); return; }
              }
              controller.enqueue(new Uint8Array(buf));
            }
            controller.close();
          } catch (e) { controller.error(e); }
        },
      });
      return new Response(stream, {
        status: 200,
        headers: {
          ...SEC, ...corsHeaders(request),
          'Content-Type':        safeMime(safe),
          'Content-Disposition': contentDisposition(safe),
          'Content-Length':      String(manifest.totalSize),
          'Accept-Ranges':       'none',
        },
      });
    }
    const rawUrl = `https://raw.githubusercontent.com/${ghOwner}/${ghRepo}/${ghBranch}/${folder}/${encodeURIComponent(safe)}`;
    let ghRes;
    try { ghRes = await fetch(rawUrl, { headers:{ Authorization:`token ${ghToken}`, 'User-Agent':'StoreGit/1' } }); }
    catch { return fail(request,502); }
    if (ghRes.status===404) return fail(request,404);
    if (!ghRes.ok) return fail(request,502);
    const len = ghRes.headers.get('Content-Length')||'';
    return new Response(ghRes.body, {
      status:200,
      headers: {
        ...SEC, ...corsHeaders(request),
        'Content-Type':        safeMime(safe),
        'Content-Disposition': contentDisposition(safe),
        ...(len?{'Content-Length':len}:{}),
        'Accept-Ranges': 'bytes',
      },
    });
  }
  if (route === 'delete' && method === 'DELETE') {
    let body; try { body = await request.json(); } catch { return fail(request,400); }
    const { name, sha, chunked } = body||{};
    if (typeof name !== 'string') return fail(request,400);
    const safe = sanitize(name);
    if (!safe) return fail(request,400);
    if (chunked) {
      try {
        await deleteChunked(fullSess, safe);
        const { data: idx, sha: idxSha } = await readIndex(fullSess);
        delete idx[safe];
        await writeIndex(fullSess, idx, idxSha);
        return jsonRes(request, { ok:true });
      } catch { return fail(request,502); }
    } else {
      if (typeof sha !== 'string' || !SHA_RE.test(sha)) return fail(request,400);
      try {
        await deleteRegular(fullSess, safe, sha);
        try {
          const { data: idx, sha: idxSha } = await readIndex(fullSess);
          if (idx[safe]) { delete idx[safe]; await writeIndex(fullSess, idx, idxSha); }
        } catch {}
        return jsonRes(request, { ok:true });
      } catch { return fail(request,502); }
    }
  }
  return fail(request, 404);
}
