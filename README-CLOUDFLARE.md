# Guardian Console — Grand Final (Cloudflare Workers + D1)

Parent dashboard for consent-based family device management.

## What is complete

- Parent signup / login (PBKDF2 passwords, 30-day sessions)
- Children, enrollment links, device consent scopes
- Screen-time policy, sample activity report, audit log
- **Live screen streaming + remote control** with **strict controls**
- Device **agent API** + command queue (ready for a native agent)

## Strict elevated features

New scopes: `screen_stream`, `remote_control` (shown on `enroll.html`).

Rules:

1. Consent at enrollment  
2. Policy toggles **off by default** (Settings → Elevated access)  
3. Explicit confirm dialog before starting a session  
4. Sessions auto-expire (default 5 min, max 15) in `controlSessions`  
5. Commands go to `commandQueue` for the device agent  
6. Full audit trail  

## Demo vs production media

| Layer | Status |
|-------|--------|
| Console, D1, policy, sessions, queue, audit | **Production-ready backend** |
| Live pixels / lock / mute on a real phone | Needs **native agent** (see `AGENT.md`) |
| UI without agent | Shows DEMO mock screen + “queued” commands |

This web app **cannot** silently capture another device’s screen. That requires the child’s consented agent.

## Deploy

1. Push **all files at repo root** (not nested in an extra folder).  
2. Cloudflare Workers: bind D1 `guardian-console-db`, set `database_id` in `wrangler.jsonc`.  
3. Apply `migrations/0001_init.sql` (includes `controlSessions`, `commandQueue`, `agentToken`).  
4. `npx wrangler deploy`  
5. Open `/login.html` → account → child → enroll → enable elevated policy → **Live & control**.

CLI sketch:

```bash
npx wrangler d1 create guardian-console-db
# paste id into wrangler.jsonc
npx wrangler d1 migrations apply guardian-console-db --remote
npx wrangler deploy
```

## API map (parent Bearer session)

- `POST /api/auth/signup|login|logout`
- `GET /api/me`, `GET|POST /api/children`
- `POST /api/children/:id/enroll-token`
- `GET|POST /api/enroll/:token[/confirm]` — confirm returns `agentToken` once  
- `GET/POST /api/devices/:id/stream|control|policy|…`
- `GET /api/audit`

## API map (device agent Bearer agentToken)

Documented in **`AGENT.md`**:

- `POST /api/agent/heartbeat`
- `GET /api/agent/commands`
- `POST /api/agent/commands/result`
- `POST /api/agent/stream/signal`

## Files

- `worker.js` — all API routes  
- `Frontend/` — login, enroll, console (including Live & control)  
- `migrations/0001_init.sql`  
- `AGENT.md` — native agent contract  
- `wrangler.jsonc`
