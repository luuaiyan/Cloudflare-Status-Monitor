import { connect } from 'cloudflare:sockets';

// ==================== 配置常量 ====================

function getAdminConfig(env) {
  return {
    USERNAME: env.USERNAME || 'USER',
    PASSWORD: env.PASSWORD || 'PASSWORD',
  };
}

function getSecurityConfig(env) {
  if (!env.JWT_SECRET || env.JWT_SECRET === 'default-jwt-secret-please-set-in-worker-variables') {
    throw new Error('JWT_SECRET must be set in environment variables for security');
  }
  return {
    JWT_SECRET: env.JWT_SECRET,
    TOKEN_EXPIRY: 30 * 24 * 60 * 60 * 1000, 
    MAX_LOGIN_ATTEMPTS: 5,
    LOGIN_ATTEMPT_WINDOW: 15 * 60 * 1000,
    API_RATE_LIMIT: 60,
    ALLOWED_ORIGINS: env.ALLOWED_ORIGINS ? env.ALLOWED_ORIGINS.split(',').map(o => o.trim()) : [],
  };
}

// ==================== 缓存系统 ====================
class ConfigCache {
  constructor() {
    this.cache = new Map();
    this.CACHE_TTL = { BARK: 300000 };
  }
  set(key, value, ttl) { this.cache.set(key, { value, timestamp: Date.now(), ttl }); }
  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.timestamp > entry.ttl) { this.cache.delete(key); return null; }
    return entry.value;
  }
  async getBarkConfig(db) {
    const cached = this.get('bark_config'); if (cached) return cached;
    try {
      const config = await db.prepare('SELECT bark_url, enable_notifications FROM bark_config WHERE id = 1').first();
      if (config) { this.set('bark_config', config, this.CACHE_TTL.BARK); return config; }
    } catch(e) {}
    return null;
  }
  clearKey(key) { this.cache.delete(key); }
}
const configCache = new ConfigCache();
let taskCounter = 0;
let dbInitialized = false;

// ==================== 工具函数 ====================
const revokedTokens = new Map();
function revokeToken(token) { revokedTokens.set(token, Date.now()); jwtCache.delete(token); }
function isTokenRevoked(token) { return revokedTokens.has(token); }

async function parseJsonSafely(request, maxSize = 1048576) {
  const text = await request.text();
  if (text.length > maxSize) throw new Error('Request body too large');
  return JSON.parse(text);
}

async function authenticateAdmin(request, env) {
  const user = await authenticateRequest(request, env); if (!user) return null;
  const adminUser = await env.DB.prepare('SELECT username, locked_until FROM admin_credentials WHERE username = ?').bind(user.username).first();
  if (!adminUser || (adminUser.locked_until && Date.now() < adminUser.locked_until)) return null;
  return user;
}

function extractAndValidateId(path) {
  const segments = path.split('/');
  const id = segments[segments.length - 1];
  return id && /^[a-zA-Z0-9_-]{1,50}$/.test(id) ? id : null;
}

function createApiResponse(data, status = 200, corsHeaders = {}) { return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...corsHeaders } }); }
function createErrorResponse(error, message, status = 500, corsHeaders = {}) { return createApiResponse({ error, message, timestamp: Date.now() }, status, corsHeaders); }
function createSuccessResponse(data, corsHeaders = {}) { return createApiResponse({ success: true, ...data }, 200, corsHeaders); }

// ==================== 密码与JWT ====================
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  const encoder = new TextEncoder();
  let hash = encoder.encode(password + saltHex);
  for (let i = 0; i < 1000; i++) hash = new Uint8Array(await crypto.subtle.digest('SHA-256', hash));
  const hashHex = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${saltHex}$${hashHex}`;
}
async function verifyPassword(password, hashedPassword) {
  const [saltHex, expectedHash] = hashedPassword.split('$');
  const encoder = new TextEncoder();
  let hash = encoder.encode(password + saltHex);
  for (let i = 0; i < 1000; i++) hash = new Uint8Array(await crypto.subtle.digest('SHA-256', hash));
  const computedHash = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  return computedHash === expectedHash;
}

const jwtCache = new Map();
async function createJWT(payload, env) {
  const config = getSecurityConfig(env);
  const now = Date.now();
  const jwtPayload = { ...payload, iat: now, exp: now + config.TOKEN_EXPIRY };
  const data = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })) + '.' + btoa(JSON.stringify(jwtPayload));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(config.JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return data + '.' + btoa(String.fromCharCode(...new Uint8Array(signature)));
}
async function verifyJWTCached(token, env) {
  if (isTokenRevoked(token)) return null;
  const cached = jwtCache.get(token);
  if (cached && Date.now() - cached.timestamp < 60000 && cached.payload.exp > Date.now()) return cached.payload;
  
  try {
    const config = getSecurityConfig(env);
    const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
    const data = encodedHeader + '.' + encodedPayload;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(config.JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const signature = Uint8Array.from(atob(encodedSignature), c => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify('HMAC', key, signature, new TextEncoder().encode(data));
    if (!isValid) return null;
    const payload = JSON.parse(atob(encodedPayload));
    if (payload.exp && Date.now() > payload.exp) return null;
    jwtCache.set(token, { payload, timestamp: Date.now() });
    return payload;
  } catch (e) { return null; }
}

async function authenticateRequest(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) return null;
  return await verifyJWTCached(authHeader.substring(7), env);
}

// ==================== 数据库与初始化 ====================
const D1_SCHEMAS = {
  admin: `CREATE TABLE IF NOT EXISTS admin_credentials (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, created_at INTEGER, last_login INTEGER, failed_attempts INTEGER DEFAULT 0, locked_until INTEGER);`,
  servers: `CREATE TABLE IF NOT EXISTS servers (id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT, port INTEGER DEFAULT 22, description TEXT, api_key TEXT, created_at INTEGER, sort_order INTEGER, last_checked INTEGER, last_status TEXT DEFAULT 'PENDING', last_response_time_ms INTEGER, last_notified_down_at INTEGER, is_public INTEGER DEFAULT 1);`,
  server_history: `CREATE TABLE IF NOT EXISTS server_status_history (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id TEXT NOT NULL, timestamp INTEGER NOT NULL, status TEXT NOT NULL, response_time_ms INTEGER, FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE); CREATE INDEX IF NOT EXISTS idx_srv_hist ON server_status_history (server_id, timestamp DESC);`,
  sites: `CREATE TABLE IF NOT EXISTS monitored_sites (id TEXT PRIMARY KEY, url TEXT NOT NULL UNIQUE, name TEXT, added_at INTEGER NOT NULL, last_checked INTEGER, last_status TEXT DEFAULT 'PENDING', last_status_code INTEGER, last_response_time_ms INTEGER, sort_order INTEGER, last_notified_down_at INTEGER, is_public INTEGER DEFAULT 1, method TEXT DEFAULT 'HEAD', headers TEXT, body TEXT);`,
  site_history: `CREATE TABLE IF NOT EXISTS site_status_history (id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT NOT NULL, timestamp INTEGER NOT NULL, status TEXT NOT NULL, status_code INTEGER, response_time_ms INTEGER, FOREIGN KEY(site_id) REFERENCES monitored_sites(id) ON DELETE CASCADE); CREATE INDEX IF NOT EXISTS idx_site_hist ON site_status_history (site_id, timestamp DESC);`,
  bark: `CREATE TABLE IF NOT EXISTS bark_config (id INTEGER PRIMARY KEY CHECK (id = 1), bark_url TEXT, enable_notifications INTEGER DEFAULT 0, updated_at INTEGER); INSERT OR IGNORE INTO bark_config (id, bark_url, enable_notifications) VALUES (1, '', 0);`
};

async function ensureTablesExist(db, env) {
  try {
    for (const sql of Object.values(D1_SCHEMAS)) {
      const stmts = sql.split(';').filter(s => s.trim().length > 0).map(s => db.prepare(s + ';'));
      await db.batch(stmts);
    }
  } catch (e) {}

  const alterStatements = [
    "ALTER TABLE servers ADD COLUMN host TEXT",
    "ALTER TABLE servers ADD COLUMN port INTEGER DEFAULT 22",
    "ALTER TABLE servers ADD COLUMN last_checked INTEGER",
    "ALTER TABLE servers ADD COLUMN last_status TEXT DEFAULT 'PENDING'",
    "ALTER TABLE servers ADD COLUMN last_response_time_ms INTEGER",
    "ALTER TABLE servers ADD COLUMN is_public INTEGER DEFAULT 1",
    "ALTER TABLE monitored_sites ADD COLUMN method TEXT DEFAULT 'HEAD'",
    "ALTER TABLE monitored_sites ADD COLUMN headers TEXT",
    "ALTER TABLE monitored_sites ADD COLUMN body TEXT"
  ];
  for (const stmt of alterStatements) {
    try { await db.exec(stmt); } catch (e) {}
  }

  const adminConfig = getAdminConfig(env);
  const adminExists = await db.prepare("SELECT username FROM admin_credentials WHERE username = ?").bind(adminConfig.USERNAME).first();
  if (!adminExists) {
    const hash = await hashPassword(adminConfig.PASSWORD);
    await db.prepare(`INSERT INTO admin_credentials (username, password_hash, created_at, failed_attempts) VALUES (?, ?, ?, 0)`).bind(adminConfig.USERNAME, hash, Math.floor(Date.now() / 1000)).run();
  }
}

// ==================== 探测逻辑 ====================
async function checkTcpPort(host, port, timeoutMs = 5000) {
  const start = Date.now();
  try {
    const socket = connect({ hostname: host, port: parseInt(port) });
    const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), timeoutMs));
    await Promise.race([socket.opened, timeoutPromise]);
    const latency = Date.now() - start;
    socket.close();
    return { status: 'UP', latency };
  } catch (e) {
    return { status: 'DOWN', latency: Date.now() - start };
  }
}

async function checkHttpAdvanced(url, method, headers, bodyStr, timeoutMs = 10000) {
  const start = Date.now();
  try {
    const reqMethod = method || 'HEAD';
    const options = { method: reqMethod, redirect: 'follow', signal: AbortSignal.timeout(timeoutMs) };
    if (headers) { try { options.headers = JSON.parse(headers); } catch(e){} }
    if (bodyStr && ['POST','PUT','PATCH'].includes(reqMethod)) { options.body = bodyStr; }

    const response = await fetch(url, options);
    const latency = Date.now() - start;
    const isUp = response.ok || (response.status >= 300 && response.status < 500);
    return { status: isUp ? 'UP' : 'DOWN', statusCode: response.status, latency };
  } catch (e) {
    return { status: e.name === 'TimeoutError' ? 'TIMEOUT' : 'ERROR', statusCode: null, latency: Date.now() - start };
  }
}

async function sendBarkNotification(db, message) {
  try {
    const cfg = await configCache.getBarkConfig(db);
    if (!cfg?.enable_notifications || !cfg.bark_url) return;
    await fetch(cfg.bark_url.trim(), { 
        method: 'POST', 
        headers: { 'Content-Type': 'application/json; charset=utf-8' }, 
        body: JSON.stringify({ title: "Status Monitor Alert", body: message, group: "StatusMonitor", level: "active" }) 
    });
  } catch (e) {}
}

async function processServerCheck(server, db, ctx) {
  const { id, name, host, port, last_status, last_notified_down_at } = server;
  const result = await checkTcpPort(host, port);
  const checkTime = Math.floor(Date.now() / 1000);
  let newNotify = last_notified_down_at;

  if (result.status === 'DOWN' && last_status !== 'DOWN') {
    ctx.waitUntil(sendBarkNotification(db, `🔴 TCP宕机: [${name}] 端口 ${port} 无法连接`));
    newNotify = checkTime;
  } else if (result.status === 'UP' && last_status === 'DOWN') {
    ctx.waitUntil(sendBarkNotification(db, `✅ TCP恢复: [${name}] 已重新上线`));
    newNotify = null;
  }

  await db.batch([
    db.prepare('UPDATE servers SET last_checked=?, last_status=?, last_response_time_ms=?, last_notified_down_at=? WHERE id=?').bind(checkTime, result.status, result.latency, newNotify, id),
    db.prepare('INSERT INTO server_status_history (server_id, timestamp, status, response_time_ms) VALUES (?, ?, ?, ?)').bind(id, checkTime, result.status, result.latency)
  ]);
}

async function processSiteCheck(site, db, ctx) {
  const { id, name, url, method, headers, body, last_status, last_notified_down_at } = site;
  const result = await checkHttpAdvanced(url, method, headers, body);
  const checkTime = Math.floor(Date.now() / 1000);
  let newNotify = last_notified_down_at;

  if (['DOWN', 'TIMEOUT', 'ERROR'].includes(result.status) && !['DOWN', 'TIMEOUT', 'ERROR'].includes(last_status)) {
    ctx.waitUntil(sendBarkNotification(db, `🔴 HTTP宕机: [${name || url}] 状态 ${result.status} (${result.statusCode || '-'})`));
    newNotify = checkTime;
  } else if (result.status === 'UP' && ['DOWN', 'TIMEOUT', 'ERROR'].includes(last_status)) {
    ctx.waitUntil(sendBarkNotification(db, `✅ HTTP恢复: [${name || url}] 已重新连通`));
    newNotify = null;
  }

  await db.batch([
    db.prepare('UPDATE monitored_sites SET last_checked=?, last_status=?, last_status_code=?, last_response_time_ms=?, last_notified_down_at=? WHERE id=?').bind(checkTime, result.status, result.statusCode, result.latency, newNotify, id),
    db.prepare('INSERT INTO site_status_history (site_id, timestamp, status, status_code, response_time_ms) VALUES (?, ?, ?, ?, ?)').bind(id, checkTime, result.status, result.statusCode, result.latency)
  ]);
}

// ==================== API 路由分发 ====================
async function handleApiRequest(request, env, ctx) {
  const corsHeaders = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' };
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders });

  try {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (path === '/api/auth/login' && method === 'POST') {
      const { username, password } = await parseJsonSafely(request);
      const user = await env.DB.prepare('SELECT username, password_hash FROM admin_credentials WHERE username = ?').bind(username).first();
      if (!user || !(await verifyPassword(password, user.password_hash))) return createErrorResponse('Auth failed', '账号或密码错误', 401, corsHeaders);
      const token = await createJWT({ username }, env);
      return createSuccessResponse({ token }, corsHeaders);
    }
    
    if (path === '/api/auth/status' && method === 'GET') {
      const user = await authenticateRequest(request, env);
      return createApiResponse({ authenticated: !!user }, 200, corsHeaders);
    }
    
    if (path === '/api/status/all' && method === 'GET') {
      const user = await authenticateRequest(request, env);
      const isAdmin = !!user;
      
      const condition = isAdmin ? '' : 'WHERE is_public = 1';
      const serversRaw = (await env.DB.prepare(`SELECT id, name, host, port, last_status, last_response_time_ms, last_checked, is_public FROM servers ${condition} ORDER BY sort_order ASC NULLS LAST, name ASC`).all()).results || [];
      const sitesRaw = (await env.DB.prepare(`SELECT id, name, url, method, headers, body, last_status, last_status_code, last_response_time_ms, last_checked, is_public FROM monitored_sites ${condition} ORDER BY sort_order ASC NULLS LAST, name ASC`).all()).results || [];
      const ago24h = Math.floor(Date.now() / 1000) - 86400;
      
      for (let s of serversRaw) {
        try { s.history = (await env.DB.prepare('SELECT timestamp, status, response_time_ms FROM server_status_history WHERE server_id=? AND timestamp>=? ORDER BY timestamp ASC').bind(s.id, ago24h).all()).results || []; } catch(e){ s.history = []; }
      }
      for (let s of sitesRaw) {
        try { s.history = (await env.DB.prepare('SELECT timestamp, status, response_time_ms, status_code FROM site_status_history WHERE site_id=? AND timestamp>=? ORDER BY timestamp ASC').bind(s.id, ago24h).all()).results || []; } catch(e){ s.history = []; }
      }

      const safeServers = serversRaw.map(s => {
        if (isAdmin) return s;
        return {
            id: s.id,
            name: s.name || '未命名服务',
            last_status: s.last_status,
            last_response_time_ms: s.last_response_time_ms,
            last_checked: s.last_checked,
            history: s.history
        };
      });

      const safeSites = sitesRaw.map(s => {
        if (isAdmin) return s; 
        return {
            id: s.id,
            name: s.name || '未命名网站', 
            last_status: s.last_status,
            last_status_code: s.last_status_code,
            last_response_time_ms: s.last_response_time_ms,
            last_checked: s.last_checked,
            history: s.history
        };
      });
      
      return createApiResponse({ servers: safeServers, sites: safeSites }, 200, corsHeaders);
    }

    const adminUser = await authenticateAdmin(request, env);
    if (!adminUser && path.startsWith('/api/admin/')) return createErrorResponse('Unauthorized', '请先登录', 401, corsHeaders);

    if (path === '/api/admin/servers/batch-reorder' && method === 'POST') {
      const { ids } = await parseJsonSafely(request);
      const stmts = ids.map((id, index) => env.DB.prepare('UPDATE servers SET sort_order = ? WHERE id = ?').bind(index, id));
      await env.DB.batch(stmts);
      return createSuccessResponse({}, corsHeaders);
    }
    if (path === '/api/admin/sites/batch-reorder' && method === 'POST') {
      const { ids } = await parseJsonSafely(request);
      const stmts = ids.map((id, index) => env.DB.prepare('UPDATE monitored_sites SET sort_order = ? WHERE id = ?').bind(index, id));
      await env.DB.batch(stmts);
      return createSuccessResponse({}, corsHeaders);
    }

    if (path === '/api/admin/servers' && method === 'POST') {
      const { name, host, port } = await parseJsonSafely(request);
      const id = Math.random().toString(36).substring(2, 10);
      const dummyApiKey = crypto.randomUUID ? crypto.randomUUID().replace(/-/g, '') : Math.random().toString(36).substring(2, 15);
      await env.DB.prepare('INSERT INTO servers (id, name, host, port, description, api_key, created_at, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, 0)').bind(id, name, host, port||22, '', dummyApiKey, Math.floor(Date.now()/1000)).run();
      ctx.waitUntil(processServerCheck({id, name, host, port: port||22}, env.DB, ctx));
      return createSuccessResponse({}, corsHeaders);
    }
    if (path.match(/\/api\/admin\/servers\/[^\/]+$/) && method === 'PUT') {
      const { name, host, port } = await parseJsonSafely(request);
      await env.DB.prepare('UPDATE servers SET name=?, host=?, port=? WHERE id=?').bind(name, host, port||22, extractAndValidateId(path)).run();
      return createSuccessResponse({}, corsHeaders);
    }
    if (path.match(/\/api\/admin\/servers\/[^\/]+$/) && method === 'DELETE') {
      await env.DB.prepare('DELETE FROM servers WHERE id=?').bind(extractAndValidateId(path)).run();
      return createSuccessResponse({}, corsHeaders);
    }

    if (path === '/api/admin/sites' && method === 'POST') {
      const { name, url, reqMethod, headers, body } = await parseJsonSafely(request);
      const id = Math.random().toString(36).substring(2, 10);
      await env.DB.prepare('INSERT INTO monitored_sites (id, url, name, method, headers, body, added_at, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, 0)')
        .bind(id, url, name||'', reqMethod||'HEAD', headers||null, body||null, Math.floor(Date.now()/1000)).run();
      ctx.waitUntil(processSiteCheck({id, name, url, method:reqMethod, headers, body}, env.DB, ctx));
      return createSuccessResponse({}, corsHeaders);
    }
    if (path.match(/\/api\/admin\/sites\/[^\/]+$/) && method === 'PUT') {
      const { name, url, reqMethod, headers, body } = await parseJsonSafely(request);
      await env.DB.prepare('UPDATE monitored_sites SET name=?, url=?, method=?, headers=?, body=? WHERE id=?')
        .bind(name||'', url, reqMethod||'HEAD', headers||null, body||null, extractAndValidateId(path)).run();
      return createSuccessResponse({}, corsHeaders);
    }
    if (path.match(/\/api\/admin\/sites\/[^\/]+$/) && method === 'DELETE') {
      await env.DB.prepare('DELETE FROM monitored_sites WHERE id=?').bind(extractAndValidateId(path)).run();
      return createSuccessResponse({}, corsHeaders);
    }

    if (path === '/api/admin/bark-settings' && method === 'GET') {
      let config = await configCache.getBarkConfig(env.DB);
      if (!config) config = { bark_url: '', enable_notifications: 0 };
      return createApiResponse(config, 200, corsHeaders);
    }
    if (path === '/api/admin/bark-settings' && method === 'POST') {
      const { bark_url, enable_notifications } = await parseJsonSafely(request);
      await env.DB.prepare('REPLACE INTO bark_config (id, bark_url, enable_notifications, updated_at) VALUES (1, ?, ?, ?)').bind(bark_url, enable_notifications ? 1 : 0, Math.floor(Date.now() / 1000)).run();
      configCache.clearKey('bark_config');
      return createSuccessResponse({}, corsHeaders);
    }
    
    // Bark Push Test API
    if (path === '/api/admin/bark-settings/test' && method === 'POST') {
      const { bark_url } = await parseJsonSafely(request);
      if (!bark_url) return createErrorResponse('Error', 'Bark URL is empty', 400, corsHeaders);
      try {
        const res = await fetch(bark_url.trim(), { 
            method: 'POST', 
            headers: { 'Content-Type': 'application/json; charset=utf-8' }, 
            body: JSON.stringify({ title: "Status Monitor Test", body: "🔔 Bark push notification is working perfectly!", group: "StatusMonitor", level: "active" }) 
        });
        if (!res.ok) throw new Error('Bark API returned ' + res.status);
        return createSuccessResponse({ message: 'Test message sent' }, corsHeaders);
      } catch (e) {
        return createErrorResponse('Error', e.message, 500, corsHeaders);
      }
    }

    if (path === '/api/admin/maintenance/clear' && method === 'POST') {
      const { hours } = await parseJsonSafely(request);
      const threshold = hours === 0 ? Math.floor(Date.now() / 1000) : Math.floor(Date.now() / 1000) - (hours * 3600);
      
      await env.DB.prepare('DELETE FROM site_status_history WHERE timestamp < ?').bind(threshold).run();
      await env.DB.prepare('DELETE FROM server_status_history WHERE timestamp < ?').bind(threshold).run();
      
      if (hours === 0) {
          await env.DB.prepare("UPDATE servers SET last_checked=NULL, last_status='PENDING', last_response_time_ms=NULL").run();
          await env.DB.prepare("UPDATE monitored_sites SET last_checked=NULL, last_status='PENDING', last_response_time_ms=NULL, last_status_code=NULL").run();
      }
      return createSuccessResponse({ message: 'History and current status cleared' }, corsHeaders);
    }

    if (path.match(/^\/api\/admin\/(servers|sites)\/([^\/]+)\/visibility$/) && method === 'POST') {
      const type = path.split('/')[3], id = path.split('/')[4]; const { is_public } = await request.json();
      const table = type === 'servers' ? 'servers' : 'monitored_sites';
      await env.DB.prepare(`UPDATE ${table} SET is_public = ? WHERE id = ?`).bind(is_public ? 1 : 0, id).run();
      return createSuccessResponse({}, corsHeaders);
    }

    return createErrorResponse('Not found', 'API Endpoint Not Found', 404, corsHeaders);
  } catch (error) {
    return createErrorResponse(error.name || 'ServerError', error.message || 'Internal Server Error', 500, corsHeaders);
  }
}

// ==================== 主入口与路由分发 ====================
function handleFrontendRequest(request, path, env) {
  const loginRoute = env.LOGIN ? `/${env.LOGIN.replace(/^\//, '')}` : '/login.html';
  
  const routes = {
    '/': () => new Response(getIndexHtml(loginRoute), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } }),
    '/index.html': () => new Response(getIndexHtml(loginRoute), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } }),
    [loginRoute]: () => new Response(getLoginHtml(), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } }),
    '/admin.html': () => new Response(getAdminHtml(), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } }),
    '/css/style.css': () => new Response(getStyleCss(), { headers: { 'Content-Type': 'text/css;charset=UTF-8' } }),
    '/js/main.js': () => new Response(getMainJs(), { headers: { 'Content-Type': 'application/javascript;charset=UTF-8' } }),
    '/js/admin.js': () => new Response(getAdminJs(), { headers: { 'Content-Type': 'application/javascript;charset=UTF-8' } }),
    '/favicon.svg': () => new Response(getFaviconSvg(), { headers: { 'Content-Type': 'image/svg+xml' } })
  };
  return routes[path] ? routes[path]() : new Response('Not Found', { status: 404 });
}

export default {
  async fetch(request, env, ctx) {
    if (!env.DB) {
      return new Response(getMissingDbHtml(), { 
        status: 503, 
        headers: { 'Content-Type': 'text/html;charset=UTF-8' } 
      });
    }

    if (!dbInitialized) { 
      try { 
        await ensureTablesExist(env.DB, env); 
        dbInitialized = true; 
      } catch (e) {} 
    }

    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) return handleApiRequest(request, env, ctx);
    return handleFrontendRequest(request, url.pathname, env);
  },

  async scheduled(event, env, ctx) {
    taskCounter++;
    ctx.waitUntil((async () => {
      if (!env.DB) return;
      if (!dbInitialized) { 
          await ensureTablesExist(env.DB, env); 
          dbInitialized = true; 
      }
      
      const servers = (await env.DB.prepare('SELECT * FROM servers').all()).results || [];
      const sites = (await env.DB.prepare('SELECT * FROM monitored_sites').all()).results || [];
      
      const promises = [];
      for (const srv of servers) promises.push(processServerCheck(srv, env.DB, ctx));
      for (const site of sites) promises.push(processSiteCheck(site, env.DB, ctx));
      await Promise.all(promises);

      if (taskCounter % 1440 === 0) {
        const threshold = Math.floor(Date.now() / 1000) - (30 * 86400);
        await env.DB.prepare('DELETE FROM site_status_history WHERE timestamp < ?').bind(threshold).run();
        await env.DB.prepare('DELETE FROM server_status_history WHERE timestamp < ?').bind(threshold).run();
      }
    })());
  }
};

// ==================== 自定义 SVG Favicon ====================
function getFaviconSvg() {
  return `<?xml version="1.0" ?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1" viewBox="0 0 59.357 59.357" xml:space="preserve"><g fill="#3885EE" style="fill:#3885EE;stroke:none" stroke="none"><path d="M1.5,26.203c-0.349,0-0.699-0.121-0.983-0.367c-0.626-0.543-0.692-1.49-0.149-2.116L13.522,8.566     c0.285-0.329,0.698-0.517,1.133-0.517l0,0c0.434,0,0.848,0.188,1.133,0.517L28.934,23.72c0.543,0.626,0.476,1.573-0.149,2.116     c-0.627,0.544-1.574,0.476-2.117-0.149L14.655,11.838L2.633,25.687C2.336,26.029,1.919,26.203,1.5,26.203z"/><path d="M35.759,51.307c-13.056,0-23.465-10.422-23.465-23.232V10.331c0-0.828,0.672-1.5,1.5-1.5     c0.829,0,1.5,0.672,1.5,1.5v17.744c0,11.156,9.063,20.232,20.465,20.232c11.208,0,20.571-9.315,20.571-20.34     c0-0.828,0.618-1.5,1.446-1.5c0.829,0,1.581,0.672,1.581,1.5C59.357,40.837,48.814,51.307,35.759,51.307z"/></g></svg>`;
}

// ==================== 前端模板 ====================
function getIndexHtml(loginRoute) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Status Monitor</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.5.0/dist/echarts.min.js"></script>
    <script>
      (function(){
        let t = localStorage.getItem('vps-monitor-theme');
        if(!t) {
            const h = new Date().getHours();
            t = (h < 6 || h >= 18) ? 'dark' : 'light';
            localStorage.setItem('vps-monitor-theme', t);
        }
        document.documentElement.setAttribute('data-bs-theme', t);
      })();
    </script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <link href="/css/style.css" rel="stylesheet">
</head>
<body class="d-flex flex-column min-vh-100">
    <div id="toastContainer" class="toast-container"></div>
    <nav class="navbar custom-glass-nav sticky-top">
        <div class="container-fluid px-4 px-md-5 w-80">
            <a class="navbar-brand d-flex align-items-center gap-2 m-0 text-decoration-none" href="/">
                <img src="/favicon.svg" width="28" height="28" alt="Logo">
                <span class="text-white fw-bold fs-5 tracking-tight">Status Monitor</span>
            </a>
            <div class="d-flex align-items-center gap-2 flex-nowrap" id="navButtonGroup">
                <button id="themeToggler" class="btn nav-action-btn border-0"><i class="bi bi-moon-stars-fill fs-5"></i></button>
            </div>
        </div>
    </nav>
    <div class="container-fluid px-4 px-md-5 mt-4 mt-md-5 mb-5 flex-grow-1 w-80">
        <div class="card border-0 shadow-sm main-card">
            <div class="card-body p-3 p-md-5">
                <div class="mb-5">
                    <h5 class="card-title mb-4 fw-bold d-flex align-items-center px-2 px-md-0"><i class="bi bi-hdd-network me-2 text-primary fs-4"></i>Services</h5>
                    <div class="table-responsive d-none d-md-block">
                        <table class="table align-middle custom-table public-status-table">
                            <thead><tr><th>名称</th><th>状态</th><th>连通率</th><th>延迟</th><th>最后检查</th><th>24h趋势</th></tr></thead>
                            <tbody id="serverTableBody"><tr><td colspan="6" class="text-center text-muted py-5">Connecting...</td></tr></tbody>
                        </table>
                    </div>
                    <div id="mobileServerContainer" class="d-block d-md-none"></div>
                </div>
                <hr class="my-5 border-secondary opacity-10">
                <div class="mb-3">
                    <h5 class="card-title mb-4 fw-bold d-flex align-items-center px-2 px-md-0"><i class="bi bi-globe me-2 text-success fs-4"></i>Websites</h5>
                    <div class="table-responsive d-none d-md-block">
                        <table class="table align-middle custom-table public-status-table">
                            <thead><tr><th>名称</th><th>状态</th><th>连通率</th><th>延迟</th><th>最后检查</th><th>24h趋势</th></tr></thead>
                            <tbody id="siteStatusTableBody"><tr><td colspan="6" class="text-center text-muted py-5">Connecting...</td></tr></tbody>
                        </table>
                    </div>
                    <div id="mobileSiteContainer" class="d-block d-md-none"></div>
                </div>
            </div>
        </div>
    </div>
    <footer class="footer py-4 mt-auto glass-footer">
        <div class="container text-center"><span class="text-muted small fw-medium">Power by Allen &copy; 2026 &middot; Status Monitor</span></div>
    </footer>
    <script src="/js/main.js"></script>
</body>
</html>`;
}

function getLoginHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Status Monitor</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script>
      (function(){
        let t = localStorage.getItem('vps-monitor-theme');
        if(!t) {
            const h = new Date().getHours();
            t = (h < 6 || h >= 18) ? 'dark' : 'light';
            localStorage.setItem('vps-monitor-theme', t);
        }
        document.documentElement.setAttribute('data-bs-theme', t);
      })();
    </script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <link href="/css/style.css" rel="stylesheet">
</head>
<body class="d-flex flex-column min-vh-100">
    <div id="toastContainer" class="toast-container"></div>
    <nav class="navbar custom-glass-nav sticky-top">
        <div class="container-fluid px-4 px-md-5 w-80">
            <a class="navbar-brand d-flex align-items-center gap-2 m-0 text-decoration-none" href="/">
                <img src="/favicon.svg" width="28" height="28" alt="Logo">
                <span class="text-white fw-bold fs-5 tracking-tight">Status Monitor</span>
            </a>
            <div class="d-flex align-items-center gap-2 flex-nowrap" id="navButtonGroup">
                <a class="btn nav-action-btn border-0 text-decoration-none" href="/" title="返回首页"><i class="bi bi-house fs-5"></i></a>
                <button id="themeToggler" class="btn nav-action-btn border-0"><i class="bi bi-moon-stars-fill fs-5"></i></button>
            </div>
        </div>
    </nav>
    <div class="container d-flex flex-column justify-content-center align-items-center flex-grow-1" style="padding: 20px 0;">
        <div class="col-11 col-md-6 col-lg-4">
            <div class="card border-0 shadow-lg main-card" style="border-radius: 24px;">
                <div class="card-body p-4 p-md-5">
                    <h4 class="fw-bold mb-4 text-center">Admin Login</h4>
                    <form id="loginForm">
                        <div class="mb-3">
                            <input type="text" name="username" autocomplete="username" class="form-control bg-light-subtle border-0 rounded-4 px-4 py-3 fs-6" id="username" placeholder="Username" required>
                        </div>
                        <div class="mb-4">
                            <input type="password" name="password" autocomplete="current-password" class="form-control bg-light-subtle border-0 rounded-4 px-4 py-3 fs-6" id="password" placeholder="Password" required>
                        </div>
                        <div class="d-grid mt-4">
                            <button type="submit" class="btn btn-primary rounded-4 fw-bold shadow-sm py-3 fs-6">Access Dashboard</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
    <footer class="footer py-4 mt-auto glass-footer">
        <div class="container text-center"><span class="text-muted small fw-medium">Power by Allen &copy; 2026 &middot; Status Monitor</span></div>
    </footer>
    <script src="/js/main.js"></script>
</body>
</html>`;
}

function getAdminHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Status Monitor</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
      (function(){
        let t = localStorage.getItem('vps-monitor-theme');
        if(!t) {
            const h = new Date().getHours();
            t = (h < 6 || h >= 18) ? 'dark' : 'light';
            localStorage.setItem('vps-monitor-theme', t);
        }
        document.documentElement.setAttribute('data-bs-theme', t);
      })();
    </script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <link href="/css/style.css" rel="stylesheet">
</head>
<body class="d-flex flex-column min-vh-100">
    <div id="toastContainer" class="toast-container"></div>
    <nav class="navbar custom-glass-nav sticky-top">
        <div class="container-fluid px-4 px-md-5 w-80">
            <a class="navbar-brand d-flex align-items-center gap-2 m-0 text-decoration-none" href="/">
                <img src="/favicon.svg" width="28" height="28" alt="Logo">
                <span class="text-white fw-bold fs-5 tracking-tight d-none d-sm-inline">Status Monitor</span>
            </a>
            <div class="d-flex align-items-center gap-2 flex-nowrap" id="navButtonGroup" style="white-space: nowrap;">
                <a class="btn nav-action-btn border-0 text-decoration-none" href="/" title="返回首页"><i class="bi bi-house fs-5"></i></a>
                <button id="themeToggler" class="btn nav-action-btn border-0"><i class="bi bi-moon-stars-fill fs-5"></i></button>
                <button id="logoutBtn" class="btn bg-white text-primary rounded-pill px-3 px-sm-4 fw-bold shadow-sm ms-1 ms-sm-2" style="height: 38px; font-size: 0.9rem;">Logout</button>
            </div>
        </div>
    </nav>
    <div class="container-fluid px-4 px-md-5 mt-4 mt-md-5 mb-5 flex-grow-1 w-80">
        <div class="card border-0 shadow-sm main-card">
            <div class="card-body p-3 p-md-5">
                <div class="mb-5">
                    <div class="d-flex justify-content-between align-items-center mb-4 px-2 px-md-0">
                        <h5 class="fw-bold mb-0 fs-5"><i class="bi bi-hdd-network me-2 text-primary fs-4"></i>Services</h5>
                        <button class="btn btn-primary rounded-pill px-3 px-sm-4 fw-bold shadow-sm" onclick="showServerModal()"><i class="bi bi-plus-lg me-1"></i> Add Target</button>
                    </div>
                    <div class="table-responsive">
                        <table class="table align-middle custom-table admin-status-table">
                            <thead><tr><th></th><th>名称</th><th>Host:Port</th><th>状态</th><th>公开展示</th><th>操作</th></tr></thead>
                            <tbody id="adminServerTableBody"></tbody>
                        </table>
                    </div>
                </div>
                
                <hr class="my-5 border-secondary opacity-10">
                
                <div class="mb-5">
                    <div class="d-flex justify-content-between align-items-center mb-4 px-2 px-md-0">
                        <h5 class="fw-bold mb-0 fs-5"><i class="bi bi-globe me-2 text-success fs-4"></i>Websites</h5>
                        <button class="btn btn-success rounded-pill px-3 px-sm-4 fw-bold shadow-sm" onclick="showSiteModal()"><i class="bi bi-plus-lg me-1"></i> Add Monitor</button>
                    </div>
                    <div class="table-responsive">
                        <table class="table align-middle custom-table admin-status-table">
                            <thead><tr><th></th><th>名称</th><th>HTTP 请求详情</th><th>状态</th><th>公开展示</th><th>操作</th></tr></thead>
                            <tbody id="adminSiteTableBody"></tbody>
                        </table>
                    </div>
                </div>
                
                <hr class="my-5 border-secondary opacity-10">
                
                <div class="row g-4">
                    <div class="col-md-6">
                        <div class="bg-light-subtle p-4 p-md-5 rounded-4 h-100 border-0 shadow-sm">
                            <h5 class="fw-bold mb-4"><i class="bi bi-bell-fill me-2 text-danger"></i>Bark Push Notify</h5>
                            <form id="barkForm">
                                <div class="mb-4">
                                    <label class="form-label text-muted small fw-bold text-uppercase">Bark API URL</label>
                                    <input type="url" class="form-control form-control-lg border-0 rounded-3 bg-body" id="barkUrl" placeholder="https://api.day.app/YourKey">
                                </div>
                                <div class="form-check form-switch mb-4">
                                    <input class="form-check-input" type="checkbox" id="enableBark">
                                    <label class="form-check-label fw-medium" for="enableBark">Enable Real-time Push</label>
                                </div>
                                <div class="d-flex gap-2">
                                    <button type="button" onclick="saveBark()" class="btn btn-dark rounded-pill px-4 py-2 fw-bold flex-grow-1">Save Settings</button>
                                    <button type="button" onclick="testBark()" class="btn btn-outline-primary rounded-pill px-4 py-2 fw-bold">Test Push</button>
                                </div>
                            </form>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="bg-light-subtle p-4 p-md-5 rounded-4 h-100 border-0 shadow-sm">
                            <h5 class="fw-bold mb-4"><i class="bi bi-database-gear me-2 text-warning"></i>Data Maintenance</h5>
                            <p class="text-muted small mb-4">Optimizing the database keeps your monitor running fast and within Cloudflare D1 limits.</p>
                            <div class="d-flex flex-column gap-3">
                                <div class="p-3 bg-body rounded-3 border border-secondary-subtle d-flex flex-column flex-sm-row justify-content-between align-items-sm-center gap-2">
                                    <div>
                                        <h6 class="mb-1 fw-bold fs-6">Clear Old Logs</h6>
                                        <span class="small text-muted">Delete records older than 24h.</span>
                                    </div>
                                    <button onclick="cleanHistory(24)" class="btn btn-sm btn-outline-warning rounded-pill px-4 fw-bold">Clean</button>
                                </div>
                                <div class="p-3 bg-body rounded-3 border border-secondary-subtle d-flex flex-column flex-sm-row justify-content-between align-items-sm-center gap-2">
                                    <div>
                                        <h6 class="mb-1 fw-bold fs-6">Purge All Logs</h6>
                                        <span class="small text-muted">Delete all historical records and reset current status.</span>
                                    </div>
                                    <button onclick="cleanHistory(0)" class="btn btn-sm btn-outline-danger rounded-pill px-4 fw-bold">Purge</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="serverModal" tabindex="-1"><div class="modal-dialog modal-dialog-centered"><div class="modal-content border-0 shadow-lg rounded-4 p-2"><div class="modal-header border-0"><h5 class="modal-title fw-bold" id="srvModalTitle">TCP Monitor</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="serverForm"><input type="hidden" id="srvId"><div class="mb-4"><label class="form-label small text-muted fw-bold text-uppercase">Monitor Name</label><input type="text" class="form-control form-control-lg bg-light-subtle border-0 rounded-3" id="srvName" required></div><div class="row g-3"><div class="col-8 mb-3"><label class="form-label small text-muted fw-bold text-uppercase">Host / IP</label><input type="text" class="form-control form-control-lg bg-light-subtle border-0 rounded-3" id="srvHost" placeholder="Host or IP" required></div><div class="col-4 mb-3"><label class="form-label small text-muted fw-bold text-uppercase">Port</label><input type="number" class="form-control form-control-lg bg-light-subtle border-0 rounded-3" id="srvPort" value="22" required></div></div></form></div><div class="modal-footer border-0"><button type="button" class="btn btn-primary rounded-pill px-5 py-2 fw-bold w-100" onclick="saveServer()">Confirm & Save</button></div></div></div></div>
    
    <div class="modal fade" id="siteModal" tabindex="-1"><div class="modal-dialog modal-dialog-centered"><div class="modal-content border-0 shadow-lg rounded-4 p-2"><div class="modal-header border-0"><h5 class="modal-title fw-bold" id="siteModalTitle">API / Web Monitor</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="siteForm"><input type="hidden" id="siteId"><div class="mb-4"><label class="form-label small text-muted fw-bold text-uppercase">Monitor Name</label><input type="text" class="form-control form-control-lg bg-light-subtle border-0 rounded-3" id="siteName"></div><div class="mb-3"><label class="form-label small text-muted fw-bold text-uppercase">URL (http/https)</label><input type="url" class="form-control form-control-lg bg-light-subtle border-0 rounded-3" id="siteUrl" placeholder="https://" required></div><div class="mb-3"><label class="form-label small text-muted fw-bold text-uppercase">HTTP Method</label><select class="form-select bg-light-subtle border-0 rounded-3" id="siteMethod"><option value="HEAD">HEAD (Lightweight Ping)</option><option value="GET">GET</option><option value="POST">POST</option><option value="PUT">PUT</option></select></div><div class="mb-3"><label class="form-label small text-muted fw-bold text-uppercase">Headers (JSON format)</label><textarea class="form-control bg-light-subtle border-0 rounded-3" id="siteHeaders" placeholder='{"Authorization": "Bearer token"}' rows="2"></textarea></div><div class="mb-3"><label class="form-label small text-muted fw-bold text-uppercase">Request Body (optional)</label><textarea class="form-control bg-light-subtle border-0 rounded-3" id="siteBody" placeholder='{"key":"value"}' rows="2"></textarea></div></form></div><div class="modal-footer border-0"><button type="button" class="btn btn-success rounded-pill px-5 py-2 fw-bold w-100" onclick="saveSite()">Confirm & Save</button></div></div></div></div>

    <footer class="footer py-4 mt-auto glass-footer">
        <div class="container text-center"><span class="text-muted small fw-medium">Power by Allen &copy; 2026 &middot; Status Monitor</span></div>
    </footer>
    <script src="/js/admin.js"></script>
</body>
</html>`;
}

function getStyleCss() {
  return `
:root {
    --bs-font-sans-serif: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    --bs-body-bg: #f3f4f6;
    --card-radius: 24px;
    --glass-bg: rgba(255, 255, 255, 0.7);
}
[data-bs-theme="dark"] {
    --bs-body-bg: #030712;
    --bs-card-bg: #111827;
    --glass-bg: rgba(15, 23, 42, 0.7);
    --bs-primary: #3b82f6;
    --bs-success: #10b981;
}
body { background-color: var(--bs-body-bg); transition: background-color 0.3s; font-family: var(--bs-font-sans-serif); }

/* Layout width control for perfect alignment */
@media (min-width: 992px) { .w-80 { padding-left: 8vw !important; padding-right: 8vw !important; } }
@media (min-width: 1400px) { .w-80 { padding-left: 12vw !important; padding-right: 12vw !important; } }

/* Hero Navbar */
.custom-glass-nav {
    background: linear-gradient(135deg, rgba(56, 189, 248, 0.8), rgba(99, 102, 241, 0.8)) !important;
    backdrop-filter: saturate(200%) blur(24px);
    -webkit-backdrop-filter: saturate(200%) blur(24px);
    padding: 1.2rem 0;
    box-shadow: 0 4px 30px rgba(0,0,0,0.1);
    border-bottom: 1px solid rgba(255,255,255,0.2);
}
[data-bs-theme="dark"] .custom-glass-nav {
    background: linear-gradient(135deg, rgba(15, 23, 42, 0.8), rgba(30, 27, 75, 0.8)) !important;
    border-bottom: 1px solid rgba(255,255,255,0.05);
}
.tracking-tight { letter-spacing: -0.5px; }

/* Buttons */
.nav-action-btn { width: 38px; height: 38px; display: flex; align-items: center; justify-content: center; border-radius: 12px; background: rgba(255,255,255,0.15) !important; color: #fff !important; transition: all 0.2s; }
.nav-action-btn:hover { background: rgba(255,255,255,0.3) !important; transform: scale(1.05); }

/* Layout & Cards */
.main-card { border-radius: var(--card-radius); background-color: var(--bs-card-bg); width: 100%; box-shadow: 0 20px 40px rgba(0,0,0,0.03) !important; }
[data-bs-theme="dark"] .main-card { box-shadow: 0 20px 40px rgba(0,0,0,0.3) !important; border: 1px solid rgba(255,255,255,0.05) !important; }
.bg-light-subtle { background-color: rgba(var(--bs-light-rgb), 0.5) !important; }
[data-bs-theme="dark"] .bg-light-subtle { background-color: rgba(255,255,255,0.03) !important; }

/* Tables - PERFECT ALIGNMENT */
.custom-table { width: 100%; margin-bottom: 0; table-layout: fixed; }
.custom-table th { border-bottom: 1px solid rgba(0,0,0,0.05); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.5px; color: var(--bs-secondary-color); padding: 1.5rem 0.5rem; }
[data-bs-theme="dark"] .custom-table th { border-bottom-color: rgba(255,255,255,0.05); }
.custom-table td { padding: 1.25rem 0.5rem; border-bottom: 1px solid rgba(0,0,0,0.02); vertical-align: middle; }
[data-bs-theme="dark"] .custom-table td { border-bottom-color: rgba(255,255,255,0.02); }
.custom-table tbody tr { transition: background 0.2s; }
.custom-table tbody tr:hover td { background-color: rgba(var(--bs-primary-rgb), 0.03); }

/* Drag & Drop */
.drag-handle { cursor: grab; font-size: 1.2rem; opacity: 0.5; transition: opacity 0.2s; }
.drag-handle:hover { opacity: 1; color: var(--bs-primary) !important; }
.drag-handle:active { cursor: grabbing; }

/* Public Table Columns */
.public-status-table th, .public-status-table td { text-align: center; }
.public-status-table th:nth-child(1), .public-status-table td:nth-child(1) { width: 22%; text-align: left; padding-left: 1.5rem; }
.public-status-table th:nth-child(2), .public-status-table td:nth-child(2) { width: 13%; }
.public-status-table th:nth-child(3), .public-status-table td:nth-child(3) { width: 13%; }
.public-status-table th:nth-child(4), .public-status-table td:nth-child(4) { width: 13%; }
.public-status-table th:nth-child(5), .public-status-table td:nth-child(5) { width: 15%; }
.public-status-table th:nth-child(6), .public-status-table td:nth-child(6) { width: 24%; }

/* Admin Table Columns */
.admin-status-table { min-width: 850px; }
.admin-status-table th, .admin-status-table td { text-align: center; }
.admin-status-table th:nth-child(1), .admin-status-table td:nth-child(1) { width: 5%; padding: 0; }
.admin-status-table th:nth-child(2), .admin-status-table td:nth-child(2) { width: 20%; text-align: left; }
.admin-status-table th:nth-child(3), .admin-status-table td:nth-child(3) { width: 30%; text-align: left; }
.admin-status-table th:nth-child(4), .admin-status-table td:nth-child(4) { width: 15%; }
.admin-status-table th:nth-child(5), .admin-status-table td:nth-child(5) { width: 15%; }
.admin-status-table th:nth-child(6), .admin-status-table td:nth-child(6) { width: 15%; }

/* Charts */
.sparkline-container { width: 100%; min-width: 140px; max-width: 180px; height: 45px; display: inline-block; vertical-align: middle; }

/* Mobile Cards */
.mobile-status-card { background: var(--bs-card-bg); border-radius: 16px; border: 1px solid rgba(0,0,0,0.05); padding: 1.25rem; margin-bottom: 1rem; box-shadow: 0 4px 12px rgba(0,0,0,0.02); }
[data-bs-theme="dark"] .mobile-status-card { border-color: rgba(255,255,255,0.05); box-shadow: 0 4px 12px rgba(0,0,0,0.2); }

/* Toasts */
.toast-container { position: fixed; top: 20px; left: 50%; transform: translateX(-50%); z-index: 1055; display: flex; flex-direction: column; align-items: center; pointer-events: none; }
.unified-toast { pointer-events: auto; padding: 12px 24px; margin-bottom: 10px; border-radius: 50px; font-weight: 600; font-size: 0.9rem; display: inline-flex; align-items: center; gap: 8px; box-shadow: 0 10px 30px rgba(0,0,0,0.15); animation: toastIn 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); color: #fff; }
.unified-toast.success { background: #10b981; }
.unified-toast.danger { background: #ef4444; }
.unified-toast.warning { background: #f59e0b; color: #000; }
@keyframes toastIn { from { opacity: 0; transform: translateY(-20px) scale(0.9); } to { opacity: 1; transform: translateY(0) scale(1); } }
.hiding { animation: toastOut 0.2s ease forwards; }
@keyframes toastOut { from { opacity: 1; transform: scale(1); } to { opacity: 0; transform: scale(0.9); } }
`;
}

function getMainJs() {
  return `
// main.js (Public Dashboard)
const API_URL = '/api/status/all';
let echartInstances = [];

document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    checkAdminStatus();
    if(document.getElementById('serverTableBody')){
        loadData();
        setInterval(loadData, 60000);
    }
    const lf = document.getElementById('loginForm');
    if(lf) {
        checkLoginRedirect();
        lf.addEventListener('submit', handleLogin);
    }
});

function initTheme() {
    const t = document.getElementById('themeToggler');
    if(t) t.addEventListener('click', () => {
        const nt = document.documentElement.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-bs-theme', nt);
        localStorage.setItem('vps-monitor-theme', nt);
        echartInstances.forEach(i => i.dispose());
        echartInstances = [];
        loadData();
    });
}

function showToast(type, msg) {
    const c = document.getElementById('toastContainer'); if (!c) return;
    const t = document.createElement('div'); t.className = 'unified-toast ' + type;
    t.innerHTML = \`<div>\${msg}</div>\`;
    c.appendChild(t); setTimeout(() => { t.classList.add('hiding'); setTimeout(()=>t.remove(), 200); }, 3000);
}

async function checkAdminStatus() {
    const token = localStorage.getItem('auth_token');
    if(!token) return;
    try {
        const r = await fetch('/api/auth/status', { headers: { 'Authorization': 'Bearer ' + token } });
        const d = await r.json();
        if(d.authenticated && document.getElementById('serverTableBody')) {
            const navGroup = document.getElementById('navButtonGroup');
            if(navGroup && !document.getElementById('adminEntryBtn')) {
                const a = document.createElement('a');
                a.id = 'adminEntryBtn';
                a.className = 'btn nav-action-btn border-0 text-decoration-none ms-1';
                a.href = '/admin.html';
                a.title = 'Enter Dashboard';
                a.innerHTML = '<i class="bi bi-speedometer2 fs-5"></i>';
                navGroup.insertBefore(a, navGroup.firstChild);
            }
        }
    } catch(e) {}
}

async function checkLoginRedirect() {
    const token = localStorage.getItem('auth_token');
    if(!token) return;
    try { 
        const r = await fetch('/api/auth/status', {headers:{'Authorization':'Bearer ' + token}}); 
        const d = await r.json(); 
        if(d.authenticated) window.location.replace('/admin.html'); 
    } catch(e) {}
}

async function handleLogin(e) {
    e.preventDefault();
    const u = document.getElementById('username').value, p = document.getElementById('password').value, b=e.target.querySelector('button');
    b.disabled=true; b.textContent='Verifying...';
    try {
        const r = await fetch('/api/auth/login', { method:'POST', body:JSON.stringify({username:u,password:p}) });
        const d = await r.json();
        if(!r.ok) throw new Error(d.message);
        localStorage.setItem('auth_token', d.token); 
        window.location.replace('/admin.html');
    } catch(err) { showToast('danger', err.message); b.disabled=false; b.textContent='Access Dashboard'; }
}

async function loadData() {
    try {
        const r = await fetch(API_URL, { headers: { 'Authorization': 'Bearer ' + (localStorage.getItem('auth_token')||'') } });
        const d = await r.json();
        
        renderTable('serverTableBody', d.servers, 'TCP');
        renderTable('siteStatusTableBody', d.sites, 'HTTP');
        
        renderMobileCards('mobileServerContainer', d.servers, 'TCP');
        renderMobileCards('mobileSiteContainer', d.sites, 'HTTP');
    } catch(e) {}
}

function getStatusUI(status) {
    const m = { 'UP': {c:'text-success', i:'bi-check-circle-fill'}, 'DOWN': {c:'text-danger', i:'bi-x-circle-fill'}, 'TIMEOUT': {c:'text-warning', i:'bi-exclamation-circle-fill'} };
    const s = m[status] || {c:'text-secondary', i:'bi-question-circle-fill'};
    return \`<span class="\${s.c} fw-bold"><i class="bi \${s.i} me-1"></i>\${status}</span>\`;
}

function calcUptime(history) {
    if(!history || !history.length) return '-';
    const up = history.filter(h => h.status === 'UP').length;
    return ((up / history.length) * 100).toFixed(2) + '%';
}

function renderTable(tbodyId, items, type) {
    const tb = document.getElementById(tbodyId); if(!tb) return;
    tb.innerHTML = '';
    if(!items || items.length === 0) { tb.innerHTML = \`<tr><td colspan="6" class="text-center py-5 text-muted">No \${type} target configured.</td></tr>\`; return; }
    
    items.forEach((item, index) => {
        const tr = document.createElement('tr');
        const st = item.last_status || 'PENDING';
        const lat = item.last_response_time_ms ? \`<span class="fw-bold \${item.last_response_time_ms>500?'text-warning':'text-body'}">\${item.last_response_time_ms}ms</span>\` : '-';
        const time = item.last_checked ? new Date(item.last_checked*1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}) : '-';
        const chartId = \`chart-\${type}-\${index}\`;
        
        tr.innerHTML = \`
            <td class="fw-bold text-truncate" style="max-width: 200px;" title="\${item.name || item.url || item.host}">\${item.name || item.url || item.host}</td>
            <td>\${getStatusUI(st)}</td>
            <td class="fw-semibold text-muted">\${calcUptime(item.history)}</td>
            <td>\${lat}</td>
            <td class="text-muted small">\${time}</td>
            <td><div id="\${chartId}" class="sparkline-container"></div></td>
        \`;
        tb.appendChild(tr);
        if(item.history) renderSparkline(chartId, item.history);
    });
}

function renderMobileCards(containerId, items, type) {
    const c = document.getElementById(containerId); if(!c) return;
    c.innerHTML = '';
    if(!items || items.length === 0) { c.innerHTML = \`<div class="text-center py-4 text-muted">No \${type} target configured.</div>\`; return; }
    
    items.forEach((item, index) => {
        const div = document.createElement('div');
        div.className = 'mobile-status-card';
        const st = item.last_status || 'PENDING';
        const chartId = \`mobile-chart-\${type}-\${index}\`;
        
        div.innerHTML = \`
            <div class="d-flex justify-content-between align-items-center mb-3">
                <div class="fw-bold fs-5 text-truncate pe-3">\${item.name || item.url || item.host}</div>
                <div>\${getStatusUI(st)}</div>
            </div>
            <div class="d-flex justify-content-between text-muted small mb-3">
                <div>Uptime: <span class="fw-bold text-body">\${calcUptime(item.history)}</span></div>
                <div>Ping: <span class="fw-bold \${item.last_response_time_ms>500?'text-warning':'text-body'}">\${item.last_response_time_ms||'-'}ms</span></div>
            </div>
            <div id="\${chartId}" style="width:100%; height:45px;"></div>
        \`;
        c.appendChild(div);
        if(item.history) renderSparkline(chartId, item.history);
    });
}

function renderSparkline(elementId, history) {
    const el = document.getElementById(elementId); if(!el) return;
    const chart = echarts.init(el);
    echartInstances.push(chart);
    
    const isDark = document.documentElement.getAttribute('data-bs-theme') === 'dark';
    
    const data = [];
    const now = Date.now();
    let maxFoundLatency = 10;

    for(let i=23; i>=0; i--) {
        const bucketStart = now - ((i+1) * 3600000);
        const bucketEnd = now - (i * 3600000);
        const records = history.filter(h => h.timestamp*1000 >= bucketStart && h.timestamp*1000 < bucketEnd);
        
        if (records.length > 0) {
            const maxL = Math.max(...records.map(r => r.response_time_ms || 1));
            const hasDown = records.some(r => r.status !== 'UP');
            if(maxL > maxFoundLatency) maxFoundLatency = maxL;
            data.push({
                name: new Date(bucketEnd).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}),
                value: [bucketEnd, maxL],
                status: hasDown ? 'DOWN' : 'UP',
                latency: maxL
            });
        } else {
            data.push({
                name: new Date(bucketEnd).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}),
                value: [bucketEnd, 0], 
                status: 'NODATA',
                latency: 0
            });
        }
    }

    const yAxisMax = Math.max(maxFoundLatency * 1.3, 100);

    chart.setOption({
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'none' },
            backgroundColor: isDark ? 'rgba(31, 41, 55, 0.95)' : 'rgba(255, 255, 255, 0.95)',
            borderColor: isDark ? '#374151' : '#e5e7eb',
            textStyle: { color: isDark ? '#f9fafb' : '#111827', fontSize: 12, fontFamily: 'Inter, sans-serif' },
            padding: [8, 12],
            formatter: (params) => {
                const d = params[0].data;
                if(d.status === 'NODATA') return \`<div class="small fw-bold text-muted">\${d.name}</div><div class="small">No Data recorded</div>\`;
                const c = d.status==='UP' ? '#10b981' : (d.status==='DOWN'?'#ef4444':'#f59e0b');
                return \`<div class="fw-bold mb-1" style="font-size:11px;color:#6b7280;">\${d.name}</div>
                        <div class="d-flex align-items-center gap-2 mb-1">
                            <div style="width:8px;height:8px;border-radius:50%;background-color:\${c}"></div>
                            <span class="fw-bold" style="color:\${c}">\${d.status}</span>
                        </div>
                        <div class="small fw-medium">Max Latency: \${d.latency} ms</div>\`;
            }
        },
        grid: { left: 0, right: 0, top: 5, bottom: 2 },
        xAxis: { type: 'time', show: false, boundaryGap: true },
        yAxis: { type: 'value', show: false, min: 0, max: yAxisMax },
        series: [{
            type: 'bar',
            data: data,
            barWidth: '70%',
            showBackground: true, 
            backgroundStyle: {
                color: isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.05)',
                borderRadius: [3, 3, 3, 3]
            },
            itemStyle: {
                color: (params) => {
                    if(params.data.status === 'UP') return '#10b981';
                    if(params.data.status === 'DOWN' || params.data.status === 'ERROR') return '#ef4444';
                    if(params.data.status === 'NODATA') return 'transparent';
                    return '#f59e0b';
                },
                borderRadius: [3, 3, 3, 3]
            }
        }]
    });
}

window.addEventListener('resize', () => echartInstances.forEach(c => c.resize()));
`;
}

function getAdminJs() {
  return `
// admin.js
const API_BASE = '/api/admin';
let adminServers = [];
let adminSites = [];

document.addEventListener('DOMContentLoaded', () => {
    if(!localStorage.getItem('auth_token')) { window.location.replace('/'); return; }
    initTheme();
    loadAdminData();
    initDragDrop('adminServerTableBody', 'servers');
    initDragDrop('adminSiteTableBody', 'sites');
    document.getElementById('logoutBtn').addEventListener('click', () => { localStorage.removeItem('auth_token'); window.location.replace('/'); });
});

function initTheme() {
    const t = document.getElementById('themeToggler');
    if(t) t.addEventListener('click', () => {
        const nt = document.documentElement.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-bs-theme', nt);
        localStorage.setItem('vps-monitor-theme', nt);
    });
}

function getHeaders() { return { 'Content-Type': 'application/json', 'Authorization': 'Bearer '+localStorage.getItem('auth_token') }; }
async function apiCall(endpoint, options={}) {
    const res = await fetch(API_BASE + endpoint, { headers: getHeaders(), ...options });
    if(res.status === 401) { localStorage.removeItem('auth_token'); window.location.replace('/'); }
    const json = await res.json();
    if(!res.ok) throw new Error(json.message || 'API Error');
    return json;
}

function showToast(type, msg) {
    const c = document.getElementById('toastContainer'); if (!c) return;
    const t = document.createElement('div'); t.className = 'unified-toast ' + type;
    t.innerHTML = \`<div>\${msg}</div>\`;
    c.appendChild(t); setTimeout(() => { t.classList.add('hiding'); setTimeout(()=>t.remove(), 200); }, 3000);
}

async function loadAdminData() {
    try {
        const publicData = await fetch('/api/status/all', {headers: getHeaders()}).then(r=>r.json());
        adminServers = publicData.servers;
        adminSites = publicData.sites;
        renderAdminTable('adminServerTableBody', adminServers, 'servers');
        renderAdminTable('adminSiteTableBody', adminSites, 'sites');
        
        const bark = await apiCall('/bark-settings');
        document.getElementById('barkUrl').value = bark.bark_url || '';
        document.getElementById('enableBark').checked = !!bark.enable_notifications;
    } catch(e) { showToast('danger', e.message); }
}

function renderAdminTable(tbodyId, items, type) {
    const tb = document.getElementById(tbodyId); tb.innerHTML = '';
    if(!items.length) { tb.innerHTML = \`<tr><td colspan="6" class="text-center py-5 text-muted">No data configured.</td></tr>\`; return; }
    
    items.forEach(item => {
        let identifier = '';
        if(type === 'servers') {
            identifier = \`<span class="text-muted">\${item.host}:\${item.port}</span>\`;
        } else {
            let badge = '';
            if(item.method && item.method !== 'HEAD') badge = \`<span class="badge bg-secondary me-2">\${item.method}</span>\`;
            identifier = \`\${badge}<a href="\${item.url}" target="_blank" class="text-decoration-none text-truncate" style="max-width:200px;display:inline-block;vertical-align:bottom;" title="\${item.url}">\${item.url}</a>\`;
        }
        
        const tr = document.createElement('tr');
        tr.setAttribute('data-id', item.id);
        tr.setAttribute('draggable', 'true');
        const isPub = item.is_public == 1;
        
        tr.innerHTML = \`
            <td class="drag-handle text-muted fs-5"><i class="bi bi-grip-vertical"></i></td>
            <td class="fw-bold">\${item.name || 'Unnamed'}</td>
            <td>\${identifier}</td>
            <td><span class="badge \${item.last_status==='UP'?'bg-success':'bg-danger'}">\${item.last_status||'PENDING'}</span></td>
            <td>
                <div class="form-check form-switch m-0 d-flex justify-content-center">
                    <input class="form-check-input" type="checkbox" onchange="toggleVis('\${type}', '\${item.id}', this.checked)" \${isPub?'checked':''}>
                </div>
            </td>
            <td>
                <button class="btn btn-sm btn-light border text-primary me-2 px-3" onclick="edit('\${type}', '\${item.id}')"><i class="bi bi-pencil"></i></button>
                <button class="btn btn-sm btn-light border text-danger px-3" onclick="del('\${type}', '\${item.id}')"><i class="bi bi-trash"></i></button>
            </td>
        \`;
        tb.appendChild(tr);
    });
}

function initDragDrop(tbodyId, type) {
    const tbody = document.getElementById(tbodyId);
    let draggedRow = null;
    
    tbody.addEventListener('dragstart', e => {
        draggedRow = e.target.closest('tr');
        if(!draggedRow) return;
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', draggedRow.dataset.id);
        setTimeout(() => draggedRow.classList.add('opacity-50'), 0);
    });
    
    tbody.addEventListener('dragover', e => {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        const targetRow = e.target.closest('tr');
        if(targetRow && targetRow !== draggedRow && targetRow.parentElement === tbody) {
            const rect = targetRow.getBoundingClientRect();
            const next = (e.clientY - rect.top)/(rect.bottom - rect.top) > 0.5;
            tbody.insertBefore(draggedRow, next ? targetRow.nextSibling : targetRow);
        }
    });
    
    tbody.addEventListener('dragend', async e => {
        if(!draggedRow) return;
        draggedRow.classList.remove('opacity-50');
        const ids = Array.from(tbody.querySelectorAll('tr')).map(tr => tr.dataset.id);
        try {
            await apiCall(\`/\${type}/batch-reorder\`, {method: 'POST', body: JSON.stringify({ids})});
            showToast('success', '排序已保存');
        } catch(err) {
            showToast('danger', '排序保存失败');
        }
    });
}

let editId = null;

window.showServerModal = () => { editId = null; document.getElementById('serverForm').reset(); new bootstrap.Modal(document.getElementById('serverModal')).show(); }
window.showSiteModal = () => { editId = null; document.getElementById('siteForm').reset(); document.getElementById('siteMethod').value='HEAD'; new bootstrap.Modal(document.getElementById('siteModal')).show(); }

window.edit = (type, id) => {
    editId = id;
    if(type === 'servers') {
        const s = adminServers.find(x => x.id === id);
        document.getElementById('srvName').value = s.name || '';
        document.getElementById('srvHost').value = s.host || '';
        document.getElementById('srvPort').value = s.port || 22;
        new bootstrap.Modal(document.getElementById('serverModal')).show();
    } else {
        const s = adminSites.find(x => x.id === id);
        document.getElementById('siteName').value = s.name || '';
        document.getElementById('siteUrl').value = s.url || '';
        document.getElementById('siteMethod').value = s.method || 'HEAD';
        document.getElementById('siteHeaders').value = s.headers || '';
        document.getElementById('siteBody').value = s.body || '';
        new bootstrap.Modal(document.getElementById('siteModal')).show();
    }
}

window.saveServer = async () => {
    const n=document.getElementById('srvName').value;
    let h=document.getElementById('srvHost').value;
    const p=document.getElementById('srvPort').value;
    if(!n||!h) return showToast('warning', 'Fill required fields');
    
    h = h.replace(/^https?:\\/\\//, '').split('/')[0];
    
    try { 
        await apiCall('/servers'+(editId?'/'+editId:''), {method:editId?'PUT':'POST', body:JSON.stringify({name:n, host:h, port:p})}); 
        showToast('success', 'Saved successfully'); 
        bootstrap.Modal.getInstance(document.getElementById('serverModal')).hide(); 
        loadAdminData(); 
    } catch(e){showToast('danger',e.message);}
}

window.saveSite = async () => {
    const n=document.getElementById('siteName').value;
    const u=document.getElementById('siteUrl').value;
    const method=document.getElementById('siteMethod').value;
    const headers=document.getElementById('siteHeaders').value.trim();
    const body=document.getElementById('siteBody').value.trim();

    if(!u) return showToast('warning', 'URL required');
    if(headers) { try { JSON.parse(headers); } catch(e) { return showToast('warning', 'Headers must be valid JSON'); } }

    try { 
        await apiCall('/sites'+(editId?'/'+editId:''), {method:editId?'PUT':'POST', body:JSON.stringify({name:n, url:u, reqMethod:method, headers, body})}); 
        showToast('success', 'Saved successfully'); 
        bootstrap.Modal.getInstance(document.getElementById('siteModal')).hide(); 
        loadAdminData(); 
    } catch(e){showToast('danger',e.message);}
}

window.del = async (type, id) => {
    if(!confirm('Are you sure you want to delete this target?')) return;
    try { await apiCall(\`/\${type}/\${id}\`, {method:'DELETE'}); showToast('success', 'Deleted'); loadAdminData(); } catch(e){showToast('danger',e.message);}
}

window.toggleVis = async (type, id, val) => {
    try { await apiCall(\`/\${type}/\${id}/visibility\`, {method:'POST', body:JSON.stringify({is_public:val})}); showToast('success', 'Visibility updated'); } catch(e){showToast('danger',e.message); loadAdminData();}
}

window.saveBark = async () => {
    try { await apiCall('/bark-settings', {method:'POST', body:JSON.stringify({bark_url: document.getElementById('barkUrl').value, enable_notifications: document.getElementById('enableBark').checked})}); showToast('success', 'Bark config saved'); } catch(e){showToast('danger',e.message);}
}

window.testBark = async () => {
    const url = document.getElementById('barkUrl').value;
    if(!url) return showToast('warning', 'Please enter a Bark API URL first');
    try {
        await apiCall('/bark-settings/test', {method:'POST', body:JSON.stringify({bark_url: url})});
        showToast('success', 'Test message sent!');
    } catch(e) {
        showToast('danger', 'Failed to send: ' + e.message);
    }
}

window.cleanHistory = async (hours) => {
    if(!confirm(\`Are you sure you want to \${hours===0?'PURGE ALL records and reset status':'CLEAR records older than 24h'}?\`)) return;
    try {
        await apiCall('/maintenance/clear', { method: 'POST', body: JSON.stringify({ hours }) });
        showToast('success', 'Database maintenance complete');
        loadAdminData();
    } catch (e) { showToast('danger', e.message); }
}
`;
}

function getMissingDbHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Action Required - Status Monitor</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        body { background-color: #030712; color: #f3f4f6; font-family: 'Inter', sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
        .glass-card { background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.05); border-radius: 24px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); padding: 3rem; max-width: 600px; width: 90%; }
        .step-box { background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.05); border-radius: 12px; padding: 1.5rem; margin-top: 1.5rem; }
        .step-number { background: #3b82f6; color: white; width: 24px; height: 24px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 0.8rem; font-weight: bold; margin-right: 10px; }
        .code-block { background: #000; color: #10b981; padding: 4px 8px; border-radius: 6px; font-family: monospace; font-size: 0.9rem; }
    </style>
</head>
<body>
    <div class="glass-card">
        <div class="text-center mb-4">
            <i class="bi bi-database-exclamation text-warning" style="font-size: 4rem;"></i>
            <h2 class="fw-bold mt-3">Action Required</h2>
            <p class="text-muted">Status Monitor is running, but the D1 Database is not bound.</p>
        </div>
        
        <div class="step-box">
            <h5 class="fw-bold mb-3 fs-6">如何解决此问题？</h5>
            <div class="d-flex align-items-start mb-3">
                <span class="step-number">1</span>
                <div>进入 Cloudflare Dashboard，打开当前 Worker 的设置页面。</div>
            </div>
            <div class="d-flex align-items-start mb-3">
                <span class="step-number">2</span>
                <div>导航至 <strong>设置 (Settings)</strong> -> <strong>绑定 (Bindings)</strong>。</div>
            </div>
            <div class="d-flex align-items-start mb-3">
                <span class="step-number">3</span>
                <div>添加一个 D1 数据库绑定：<br>变量名称必须严格填写为 <span class="code-block">DB</span><br>然后选择你创建好的 D1 数据库。</div>
            </div>
            <div class="d-flex align-items-start">
                <span class="step-number"><i class="bi bi-check2"></i></span>
                <div class="text-success fw-bold">完成绑定后，重新刷新本页面即可，系统会自动初始化建表，无需其他任何操作！</div>
            </div>
        </div>
        
        <div class="text-center mt-4">
            <button onclick="window.location.reload()" class="btn btn-primary rounded-pill px-5 fw-bold">I have bound it, Refresh</button>
        </div>
    </div>
</body>
</html>`;
}