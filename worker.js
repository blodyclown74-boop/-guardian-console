const SCOPES = ['app_list','screen_time','location','web_filter','screen_stream','remote_control'];
const ELEVATED = new Set(['screen_stream','remote_control']);
const CONTROL_TTL_MS = 5 * 60 * 1000; // strict: 5-minute live/control sessions
const STREAM_TTL_MS = 5 * 60 * 1000;

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
});
const id = (p) => p + '_' + crypto.randomUUID().replace(/-/g, '');
const now = () => new Date().toISOString();
const inMs = (ms) => new Date(Date.now() + ms).toISOString();

async function body(req) {
  try { return await req.json(); } catch { return null; }
}

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' },
    key,
    256
  );
  return [...new Uint8Array(bits)].map((x) => x.toString(16).padStart(2, '0')).join('');
}

const random = (n = 24) => {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return btoa(String.fromCharCode(...a)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

async function auth(req, env) {
  const h = req.headers.get('authorization') || '';
  if (!h.startsWith('Bearer ')) return null;
  return await env.DB.prepare(
    'SELECT p.id,p.email,p.mfaEnabled,p.createdAt FROM sessions s JOIN parents p ON p.id=s.parentId WHERE s.token=? AND s.expiresAt>?'
  ).bind(h.slice(7), now()).first();
}

async function audit(env, parentId, action, detail = '') {
  await env.DB.prepare('INSERT INTO auditLog(id,parentId,action,detail,at) VALUES(?,?,?,?,?)')
    .bind(id('audit'), parentId, action, detail, now()).run();
}

async function ownedChild(env, parentId, childId) {
  return env.DB.prepare('SELECT * FROM children WHERE id=? AND parentId=?').bind(childId, parentId).first();
}

async function ownedDevice(env, parentId, deviceId) {
  return env.DB.prepare(
    'SELECT d.*,c.name childName FROM devices d JOIN children c ON c.id=d.childId WHERE d.id=? AND c.parentId=?'
  ).bind(deviceId, parentId).first();
}

async function devicesForChild(env, childId) {
  const { results = [] } = await env.DB.prepare('SELECT * FROM devices WHERE childId=?').bind(childId).all();
  return results.map((d) => ({ ...d, grantedScopes: JSON.parse(d.grantedScopes || '[]') }));
}

function hasScope(device, scope) {
  const scopes = Array.isArray(device.grantedScopes)
    ? device.grantedScopes
    : JSON.parse(device.grantedScopes || '[]');
  return scopes.includes(scope);
}

async function endExpiredSessions(env, deviceId) {
  await env.DB.prepare(
    "UPDATE controlSessions SET status='expired', endedAt=? WHERE deviceId=? AND status='active' AND expiresAt<?"
  ).bind(now(), deviceId, now()).run();
}

async function activeSession(env, deviceId, kind) {
  await endExpiredSessions(env, deviceId);
  return env.DB.prepare(
    "SELECT * FROM controlSessions WHERE deviceId=? AND kind=? AND status='active' AND expiresAt>? ORDER BY startedAt DESC LIMIT 1"
  ).bind(deviceId, kind, now()).first();
}

async function startSession(env, parentId, deviceId, kind, ttlMs) {
  await endExpiredSessions(env, deviceId);
  // strict: only one active session of each kind per device
  await env.DB.prepare(
    "UPDATE controlSessions SET status='ended', endedAt=? WHERE deviceId=? AND kind=? AND status='active'"
  ).bind(now(), deviceId, kind).run();
  const row = {
    id: id('csess'),
    deviceId,
    parentId,
    kind,
    status: 'active',
    startedAt: now(),
    expiresAt: inMs(ttlMs)
  };
  await env.DB.prepare(
    'INSERT INTO controlSessions(id,deviceId,parentId,kind,status,startedAt,expiresAt) VALUES(?,?,?,?,?,?,?)'
  ).bind(row.id, row.deviceId, row.parentId, row.kind, row.status, row.startedAt, row.expiresAt).run();
  return row;
}

async function endSession(env, sessionId, parentId) {
  const s = await env.DB.prepare('SELECT * FROM controlSessions WHERE id=? AND parentId=?').bind(sessionId, parentId).first();
  if (!s) return null;
  await env.DB.prepare("UPDATE controlSessions SET status='ended', endedAt=? WHERE id=?")
    .bind(now(), sessionId).run();
  return { ...s, status: 'ended', endedAt: now() };
}

function defaultPolicy() {
  return {
    weekdayLimitMin: 240,
    weekendLimitMin: 360,
    downtime: { start: '21:30', end: '07:00' },
    blockedApps: [],
    // stricter defaults for elevated features
    allowScreenStream: false,
    allowRemoteControl: false,
    requireReauthForElevated: true,
    maxStreamMinutes: 5,
    maxControlMinutes: 5,
    lockOnStreamEnd: false,
    notifyChildOnControl: true
  };
}

async function route(req, env) {
  const u = new URL(req.url);
  const p = u.pathname;
  const m = req.method;

  // ---- Auth ----
  if (p === '/api/auth/signup' && m === 'POST') {
    const b = await body(req);
    if (!b) return json({ error: 'invalid JSON body' }, 400);
    const email = (b.email || '').trim().toLowerCase();
    const password = b.password || '';
    if (!email || password.length < 8) return json({ error: 'email and an 8+ character password are required' }, 400);
    if (await env.DB.prepare('SELECT id FROM parents WHERE email=?').bind(email).first())
      return json({ error: 'an account with that email already exists' }, 409);
    const salt = random(16);
    const passwordHash = await hashPassword(password, salt);
    const parent = { id: id('parent'), email, salt, passwordHash, mfaEnabled: 0, createdAt: now() };
    await env.DB.prepare(
      'INSERT INTO parents(id,email,salt,passwordHash,mfaEnabled,createdAt) VALUES(?,?,?,?,?,?)'
    ).bind(parent.id, parent.email, parent.salt, parent.passwordHash, parent.mfaEnabled, parent.createdAt).run();
    const token = random(32);
    await env.DB.prepare('INSERT INTO sessions(token,parentId,expiresAt) VALUES(?,?,?)')
      .bind(token, parent.id, inMs(30 * 24 * 60 * 60 * 1000)).run();
    await audit(env, parent.id, 'account_created');
    return json({ token, parent: { id: parent.id, email: parent.email, mfaEnabled: false } }, 201);
  }

  if (p === '/api/auth/login' && m === 'POST') {
    const b = await body(req);
    if (!b) return json({ error: 'invalid JSON body' }, 400);
    const email = (b.email || '').trim().toLowerCase();
    const password = b.password || '';
    const parent = await env.DB.prepare('SELECT * FROM parents WHERE email=?').bind(email).first();
    if (!parent) return json({ error: 'invalid email or password' }, 401);
    const hash = await hashPassword(password, parent.salt);
    if (hash !== parent.passwordHash) return json({ error: 'invalid email or password' }, 401);
    const token = random(32);
    await env.DB.prepare('INSERT INTO sessions(token,parentId,expiresAt) VALUES(?,?,?)')
      .bind(token, parent.id, inMs(30 * 24 * 60 * 60 * 1000)).run();
    await audit(env, parent.id, 'login');
    return json({ token, parent: { id: parent.id, email: parent.email, mfaEnabled: !!parent.mfaEnabled } });
  }

  if (p === '/api/auth/logout' && m === 'POST') {
    const h = req.headers.get('authorization') || '';
    if (h.startsWith('Bearer ')) {
      await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(h.slice(7)).run();
    }
    return json({ ok: true });
  }

  // ---- Public enroll inspect ----
  let x = p.match(/^\/api\/enroll\/([^/]+)(\/confirm)?$/);
  if (x && m === 'GET' && !x[2]) {
    const t = await env.DB.prepare(
      'SELECT t.*,c.name childName,p.email parentEmail FROM enrollTokens t JOIN children c ON c.id=t.childId JOIN parents p ON p.id=t.createdByParentId WHERE t.token=?'
    ).bind(x[1]).first();
    if (!t) return json({ error: 'this link is invalid or has expired' }, 404);
    if (t.consumedAt || Date.parse(t.expiresAt) < Date.now()) return json({ error: 'this link has expired or already been used' }, 410);
    return json({ childName: t.childName, parentEmail: t.parentEmail, scopes: SCOPES, expiresAt: t.expiresAt });
  }

  if (x && m === 'POST' && x[2] === '/confirm') {
    const t = await env.DB.prepare('SELECT * FROM enrollTokens WHERE token=?').bind(x[1]).first();
    if (!t) return json({ error: 'this link is invalid or has expired' }, 404);
    if (t.consumedAt || Date.parse(t.expiresAt) < Date.now()) return json({ error: 'this link has expired or already been used' }, 410);
    const b = await body(req) || {};
    const platform = b.platform === 'ios' ? 'ios' : 'android';
    const scopes = Array.isArray(b.scopes) ? b.scopes.filter((s) => SCOPES.includes(s)) : SCOPES;
    const agentToken = random(32);
    const device = {
      id: id('device'),
      childId: t.childId,
      platform,
      managementMode: platform === 'android' ? 'family_link' : 'mdm_profile',
      status: 'active',
      lastSeenAt: now(),
      grantedScopes: JSON.stringify(scopes),
      agentToken
    };
    await env.DB.prepare(
      'INSERT INTO devices(id,childId,platform,managementMode,status,lastSeenAt,grantedScopes,agentToken) VALUES(?,?,?,?,?,?,?,?)'
    ).bind(device.id, device.childId, device.platform, device.managementMode, device.status, device.lastSeenAt, device.grantedScopes, device.agentToken).run();
    for (const s of scopes) {
      await env.DB.prepare('INSERT INTO consentRecords(id,deviceId,scope,grantedAt) VALUES(?,?,?,?)')
        .bind(id('consent'), device.id, s, now()).run();
    }
    // stricter: elevated features off by default until parent enables in policy
    const policy = defaultPolicy();
    await env.DB.prepare('INSERT INTO policies(deviceId,policy) VALUES(?,?)')
      .bind(device.id, JSON.stringify(policy)).run();
    await env.DB.prepare('UPDATE enrollTokens SET consumedAt=? WHERE token=?').bind(now(), x[1]).run();
    await audit(env, t.createdByParentId, 'device_enrolled', platform + ' device, scopes: ' + scopes.join(', '));
    return json({
      device: { id: device.id, childId: device.childId, platform: device.platform, status: device.status, grantedScopes: scopes },
      agentToken,
      agentApiBase: '/api/agent',
      note: 'Store agentToken on the device. It authenticates /api/agent/* calls. Parent console never sees this token again.'
    }, 201);
  }

  // ---- Device agent routes (Bearer = agentToken) ----
  async function agentAuth(req, env) {
    const h = req.headers.get('authorization') || '';
    if (!h.startsWith('Bearer ')) return null;
    return await env.DB.prepare(
      "SELECT * FROM devices WHERE agentToken=? AND status='active'"
    ).bind(h.slice(7)).first();
  }

  if (p.startsWith('/api/agent/')) {
    const device = await agentAuth(req, env);
    if (!device) return json({ error: 'unauthorized device' }, 401);
    const scopes = JSON.parse(device.grantedScopes || '[]');

    if (p === '/api/agent/heartbeat' && m === 'POST') {
      await env.DB.prepare('UPDATE devices SET lastSeenAt=? WHERE id=?').bind(now(), device.id).run();
      await endExpiredSessions(env, device.id);
      const stream = await activeSession(env, device.id, 'stream');
      const control = await activeSession(env, device.id, 'control');
      let row = await env.DB.prepare('SELECT policy FROM policies WHERE deviceId=?').bind(device.id).first();
      const policy = row ? { ...defaultPolicy(), ...JSON.parse(row.policy) } : defaultPolicy();
      return json({
        ok: true,
        serverTime: now(),
        scopes,
        policy: {
          allowScreenStream: !!policy.allowScreenStream && scopes.includes('screen_stream'),
          allowRemoteControl: !!policy.allowRemoteControl && scopes.includes('remote_control'),
          maxStreamMinutes: policy.maxStreamMinutes,
          maxControlMinutes: policy.maxControlMinutes,
          notifyChildOnControl: policy.notifyChildOnControl !== false
        },
        sessions: {
          stream: stream ? { id: stream.id, expiresAt: stream.expiresAt } : null,
          control: control ? { id: control.id, expiresAt: control.expiresAt } : null
        }
      });
    }

    if (p === '/api/agent/commands' && m === 'GET') {
      const { results = [] } = await env.DB.prepare(
        "SELECT id,command,payload,createdAt,sessionId FROM commandQueue WHERE deviceId=? AND status='pending' ORDER BY createdAt LIMIT 20"
      ).bind(device.id).all();
      if (results.length) {
        const ids = results.map((r) => r.id);
        // mark delivered
        for (const cid of ids) {
          await env.DB.prepare("UPDATE commandQueue SET status='delivered', deliveredAt=? WHERE id=?")
            .bind(now(), cid).run();
        }
      }
      return json({
        commands: results.map((r) => ({
          id: r.id,
          command: r.command,
          payload: r.payload ? JSON.parse(r.payload) : null,
          sessionId: r.sessionId,
          createdAt: r.createdAt
        }))
      });
    }

    if (p === '/api/agent/commands/result' && m === 'POST') {
      const b = await body(req) || {};
      if (!b.id) return json({ error: 'id required' }, 400);
      const row = await env.DB.prepare('SELECT * FROM commandQueue WHERE id=? AND deviceId=?').bind(b.id, device.id).first();
      if (!row) return json({ error: 'command not found' }, 404);
      await env.DB.prepare("UPDATE commandQueue SET status=?, result=? WHERE id=?")
        .bind(b.ok === false ? 'failed' : 'completed', JSON.stringify({ ok: b.ok !== false, message: b.message || '', at: now() }), b.id).run();
      return json({ ok: true });
    }

    if (p === '/api/agent/stream/signal' && m === 'POST') {
      // Agent reports it is ready to push frames / WebRTC offer (demo stores signal only)
      const b = await body(req) || {};
      const sess = await activeSession(env, device.id, 'stream');
      if (!sess) return json({ error: 'no active stream session' }, 403);
      if (!scopes.includes('screen_stream')) return json({ error: 'scope missing' }, 403);
      return json({
        ok: true,
        sessionId: sess.id,
        expiresAt: sess.expiresAt,
        mode: 'demo_or_webrtc',
        note: 'Parent console in this build does not terminate WebRTC; production would exchange SDP/ICE here.'
      });
    }

    return json({ error: 'no such agent endpoint' }, 404);
  }

  // ---- Authenticated parent routes ----
  const par = await auth(req, env);
  if (!par) return json({ error: 'unauthorized' }, 401);

  if (p === '/api/me' && m === 'GET') {
    return json({ parent: { id: par.id, email: par.email, mfaEnabled: !!par.mfaEnabled, createdAt: par.createdAt } });
  }

  if (p === '/api/children' && m === 'GET') {
    const { results = [] } = await env.DB.prepare('SELECT * FROM children WHERE parentId=? ORDER BY createdAt').bind(par.id).all();
    const out = [];
    for (const c of results) {
      out.push({ ...c, devices: await devicesForChild(env, c.id) });
    }
    return json({ children: out });
  }

  if (p === '/api/children' && m === 'POST') {
    const b = await body(req) || {};
    const name = (b.name || '').trim();
    if (!name) return json({ error: 'name is required' }, 400);
    const child = { id: id('child'), parentId: par.id, name, ageBand: b.ageBand || null, createdAt: now() };
    await env.DB.prepare('INSERT INTO children(id,parentId,name,ageBand,createdAt) VALUES(?,?,?,?,?)')
      .bind(child.id, child.parentId, child.name, child.ageBand, child.createdAt).run();
    await audit(env, par.id, 'child_created', name);
    return json({ child: { ...child, devices: [] } }, 201);
  }

  x = p.match(/^\/api\/children\/([^/]+)\/enroll-token$/);
  if (x && m === 'POST') {
    const c = await ownedChild(env, par.id, x[1]);
    if (!c) return json({ error: 'child not found' }, 404);
    const token = random(20);
    const expiresAt = inMs(15 * 60 * 1000);
    await env.DB.prepare(
      'INSERT INTO enrollTokens(id,token,childId,createdByParentId,expiresAt) VALUES(?,?,?,?,?)'
    ).bind(id('etok'), token, c.id, par.id, expiresAt).run();
    await audit(env, par.id, 'enrollment_token_issued', c.name);
    return json({ token, enrollUrl: '/enroll.html?token=' + token, expiresAt, scopes: SCOPES }, 201);
  }

  // Device sub-routes
  x = p.match(/^\/api\/devices\/([^/]+)\/(revoke|report|policy|consent|stream|control|sessions)$/);
  if (x) {
    const d = await ownedDevice(env, par.id, x[1]);
    if (!d) return json({ error: 'device not found' }, 404);
    const action = x[2];

    if (action === 'revoke' && m === 'POST') {
      await env.DB.prepare("UPDATE devices SET status='revoked' WHERE id=?").bind(d.id).run();
      await env.DB.prepare('UPDATE consentRecords SET revokedAt=? WHERE deviceId=? AND revokedAt IS NULL')
        .bind(now(), d.id).run();
      await env.DB.prepare(
        "UPDATE controlSessions SET status='ended', endedAt=? WHERE deviceId=? AND status='active'"
      ).bind(now(), d.id).run();
      await audit(env, par.id, 'device_revoked', d.childName);
      return json({ ok: true });
    }

    if (action === 'consent' && m === 'GET') {
      const { results = [] } = await env.DB.prepare('SELECT * FROM consentRecords WHERE deviceId=?').bind(d.id).all();
      return json({ consent: results });
    }

    if (action === 'report' && m === 'GET') {
      if (d.status !== 'active') return json({ sampleData: true, inactive: true });
      const seed = d.id.split('').reduce((a, c) => a + c.charCodeAt(0), 0);
      const rand = (n, i) => Math.floor((Math.sin(seed + i) * 0.5 + 0.5) * n);
      const week = Array.from({ length: 7 }, (_, i) => 60 + rand(240, i));
      return json({
        sampleData: true,
        screenMinutesToday: week[new Date().getDay()],
        weekMinutes: week,
        battery: 40 + rand(55, 9),
        online: true,
        apps: [
          { name: 'Messages', minutes: 10 + rand(30, 1), blocked: false },
          { name: 'YouTube Kids', minutes: 20 + rand(60, 2), blocked: false },
          { name: 'Roblox', minutes: 30 + rand(90, 3), blocked: false },
          { name: 'TikTok', minutes: 0, blocked: true },
          { name: 'Khan Academy', minutes: 5 + rand(20, 4), blocked: false }
        ],
        sites: [
          { site: 'Wikipedia', visits: 5 + rand(15, 5) },
          { site: 'YouTube', visits: 4 + rand(10, 6) },
          { site: 'Google Search', visits: 10 + rand(15, 7) }
        ]
      });
    }

    if (action === 'policy' && m === 'GET') {
      let row = await env.DB.prepare('SELECT policy FROM policies WHERE deviceId=?').bind(d.id).first();
      return json({ policy: row ? { ...defaultPolicy(), ...JSON.parse(row.policy) } : defaultPolicy() });
    }

    if (action === 'policy' && m === 'PUT') {
      const b = await body(req) || {};
      const row = await env.DB.prepare('SELECT policy FROM policies WHERE deviceId=?').bind(d.id).first();
      const prev = row ? JSON.parse(row.policy) : {};
      const policy = { ...defaultPolicy(), ...prev, ...b };
      // clamp strict limits
      policy.maxStreamMinutes = Math.min(15, Math.max(1, Number(policy.maxStreamMinutes) || 5));
      policy.maxControlMinutes = Math.min(15, Math.max(1, Number(policy.maxControlMinutes) || 5));
      // cannot enable elevated features without consent scopes
      if (policy.allowScreenStream && !hasScope(d, 'screen_stream')) policy.allowScreenStream = false;
      if (policy.allowRemoteControl && !hasScope(d, 'remote_control')) policy.allowRemoteControl = false;
      await env.DB.prepare(
        'INSERT INTO policies(deviceId,policy) VALUES(?,?) ON CONFLICT(deviceId) DO UPDATE SET policy=excluded.policy'
      ).bind(d.id, JSON.stringify(policy)).run();
      await audit(env, par.id, 'policy_updated', d.childName);
      return json({ policy });
    }

    // ---- Live screen stream ----
    if (action === 'stream') {
      if (m === 'GET') {
        const sess = await activeSession(env, d.id, 'stream');
        return json({
          hasScope: hasScope(d, 'screen_stream'),
          active: !!sess,
          session: sess || null,
          sampleData: true,
          note: 'Live frames require a consented device agent. This demo simulates session state only.'
        });
      }
      if (m === 'POST') {
        const b = await body(req) || {};
        if (b.action === 'stop') {
          const sess = await activeSession(env, d.id, 'stream');
          if (sess) await endSession(env, sess.id, par.id);
          await audit(env, par.id, 'stream_stopped', d.childName);
          return json({ ok: true, active: false });
        }
        // start
        if (d.status !== 'active') return json({ error: 'device is not active' }, 403);
        if (!hasScope(d, 'screen_stream'))
          return json({ error: 'screen_stream scope was not granted on enrollment' }, 403);
        let row = await env.DB.prepare('SELECT policy FROM policies WHERE deviceId=?').bind(d.id).first();
        const policy = row ? { ...defaultPolicy(), ...JSON.parse(row.policy) } : defaultPolicy();
        if (!policy.allowScreenStream)
          return json({ error: 'live screen streaming is disabled in device policy. Enable it under Settings first.' }, 403);
        if (b.confirm !== true)
          return json({ error: 'strict control: set confirm:true after reviewing the consent notice' }, 400);
        const ttl = Math.min(STREAM_TTL_MS, (policy.maxStreamMinutes || 5) * 60 * 1000);
        const sess = await startSession(env, par.id, d.id, 'stream', ttl);
        await audit(env, par.id, 'stream_started', d.childName + ' · expires ' + sess.expiresAt);
        return json({
          ok: true,
          session: sess,
          sampleData: true,
          frameHint: 'demo',
          message: 'Streaming session started (demo). Real pixels would come from the device agent over an encrypted channel.'
        }, 201);
      }
    }

    // ---- Remote control ----
    if (action === 'control') {
      if (m === 'GET') {
        const sess = await activeSession(env, d.id, 'control');
        return json({
          hasScope: hasScope(d, 'remote_control'),
          active: !!sess,
          session: sess || null,
          allowedCommands: ['lock', 'unlock', 'alert', 'mute', 'screenshot', 'open_settings'],
          sampleData: true
        });
      }
      if (m === 'POST') {
        const b = await body(req) || {};
        if (b.action === 'stop') {
          const sess = await activeSession(env, d.id, 'control');
          if (sess) await endSession(env, sess.id, par.id);
          await audit(env, par.id, 'control_session_ended', d.childName);
          return json({ ok: true, active: false });
        }
        if (b.action === 'start') {
          if (d.status !== 'active') return json({ error: 'device is not active' }, 403);
          if (!hasScope(d, 'remote_control'))
            return json({ error: 'remote_control scope was not granted on enrollment' }, 403);
          let row = await env.DB.prepare('SELECT policy FROM policies WHERE deviceId=?').bind(d.id).first();
          const policy = row ? { ...defaultPolicy(), ...JSON.parse(row.policy) } : defaultPolicy();
          if (!policy.allowRemoteControl)
            return json({ error: 'remote control is disabled in device policy. Enable it under Settings first.' }, 403);
          if (b.confirm !== true)
            return json({ error: 'strict control: set confirm:true after reviewing the consent notice' }, 400);
          const ttl = Math.min(CONTROL_TTL_MS, (policy.maxControlMinutes || 5) * 60 * 1000);
          const sess = await startSession(env, par.id, d.id, 'control', ttl);
          await audit(env, par.id, 'control_session_started', d.childName + ' · expires ' + sess.expiresAt);
          return json({ ok: true, session: sess, sampleData: true }, 201);
        }
        // command while session active
        const cmd = (b.command || '').toLowerCase();
        const allowed = ['lock', 'unlock', 'alert', 'mute', 'screenshot', 'open_settings'];
        if (!allowed.includes(cmd)) return json({ error: 'unknown command' }, 400);
        if (d.status !== 'active') return json({ error: 'device is not active' }, 403);
        if (!hasScope(d, 'remote_control')) return json({ error: 'remote_control scope missing' }, 403);
        let row = await env.DB.prepare('SELECT policy FROM policies WHERE deviceId=?').bind(d.id).first();
        const policy = row ? { ...defaultPolicy(), ...JSON.parse(row.policy) } : defaultPolicy();
        if (!policy.allowRemoteControl) return json({ error: 'remote control disabled by policy' }, 403);
        const sess = await activeSession(env, d.id, 'control');
        if (!sess) return json({ error: 'no active control session — start one first (strict mode)' }, 403);
        await audit(env, par.id, 'remote_command', d.childName + ' · ' + cmd + (b.message ? ' · ' + String(b.message).slice(0, 80) : ''));
        const payload = b.message ? { message: String(b.message).slice(0, 200) } : {};
        const qid = id('cmd');
        await env.DB.prepare(
          'INSERT INTO commandQueue(id,deviceId,sessionId,command,payload,status,createdAt) VALUES(?,?,?,?,?,?,?)'
        ).bind(qid, d.id, sess.id, cmd, JSON.stringify(payload), 'pending', now()).run();
        const responses = {
          lock: { queued: true, message: 'Lock queued for device agent.' },
          unlock: { queued: true, message: 'Unlock queued for device agent.' },
          alert: { queued: true, message: 'Alert queued: ' + (b.message || 'Please check in with a parent.') },
          mute: { queued: true, message: 'Mute queued for device agent.' },
          screenshot: { queued: true, message: 'Screenshot request queued.' },
          open_settings: { queued: true, message: 'Open-settings queued.' }
        };
        return json({
          ok: true,
          command: cmd,
          commandId: qid,
          result: responses[cmd],
          sessionExpiresAt: sess.expiresAt,
          delivery: 'queued_for_agent',
          sampleData: true
        });
      }
    }

    if (action === 'sessions' && m === 'GET') {
      await endExpiredSessions(env, d.id);
      const { results = [] } = await env.DB.prepare(
        'SELECT * FROM controlSessions WHERE deviceId=? ORDER BY startedAt DESC LIMIT 20'
      ).bind(d.id).all();
      return json({ sessions: results });
    }
  }

  if (p === '/api/audit' && m === 'GET') {
    const { results = [] } = await env.DB.prepare(
      'SELECT * FROM auditLog WHERE parentId=? ORDER BY at DESC LIMIT 100'
    ).bind(par.id).all();
    return json({ entries: results });
  }

  return json({ error: 'no such endpoint' }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      try {
        return await route(request, env);
      } catch (e) {
        console.error(e);
        return json({ error: 'internal error', detail: String(e && e.message || e) }, 500);
      }
    }
    if (request.method !== 'GET' && request.method !== 'HEAD')
      return new Response('Method not allowed', { status: 405 });
    let path = url.pathname === '/' ? '/login.html' : url.pathname;
    if (path.includes('..')) return new Response('Forbidden', { status: 403 });
    return env.ASSETS.fetch(new Request(new URL(path, request.url), request));
  }
};
