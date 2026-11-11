# Guardian Console — Device Agent Contract (Grand Final)

The **parent console** (this repo) is complete. Real live screen and remote control need a small **native agent** on the child device. This document is the contract that agent must implement.

## Security model (strict)

1. Parent enables elevated features in policy (`allowScreenStream` / `allowRemoteControl`).
2. Child granted scopes at enrollment (`screen_stream`, `remote_control`).
3. Parent starts a short session (default 5 min) with explicit confirm → row in `controlSessions`.
4. Agent only acts while a session is active and policy allows it.
5. Every parent action is audited. Agent should show an on-device “Managed / Live view” banner.

## Enrollment

`POST /api/enroll/:token/confirm` returns once:

```json
{
  "device": { "id": "...", "platform": "android|ios", "grantedScopes": ["..."] },
  "agentToken": "<secret>",
  "agentApiBase": "/api/agent"
}
```

Store `agentToken` in the OS secure store. The parent UI never sees it again.

## Agent API (Authorization: Bearer \<agentToken\>)

### `POST /api/agent/heartbeat`

Call every 15–30s while the agent is running.

Response includes:

- `scopes`, `policy` (elevated flags + max minutes)
- `sessions.stream` / `sessions.control` — active session ids + `expiresAt`, or `null`

If `sessions.stream` is set and policy allows → start capture pipeline until expiry.  
If `sessions.control` is set → poll commands.

### `GET /api/agent/commands`

Returns pending commands and marks them delivered:

```json
{
  "commands": [
    { "id": "cmd_...", "command": "lock|unlock|alert|mute|screenshot|open_settings", "payload": {}, "sessionId": "csess_...", "createdAt": "..." }
  ]
}
```

### `POST /api/agent/commands/result`

```json
{ "id": "cmd_...", "ok": true, "message": "locked" }
```

### `POST /api/agent/stream/signal`

Optional WebRTC/signaling hook when a stream session is active. This console build does not terminate media; production would exchange SDP/ICE with the parent viewer.

## Parent console behavior (already implemented)

| Action | Behavior |
|--------|----------|
| Start live view | Creates `controlSessions` kind=`stream` after confirm + policy check |
| End live view | Ends session |
| Start control | Creates kind=`control` session |
| Command (lock, …) | Inserts `commandQueue` row for the agent + audit log |
| Policy toggles | `allowScreenStream` / `allowRemoteControl` default **false** |

## What this web demo does without an agent

- Full parent UX, consent, strict gates, sessions, queue, audit
- Animated **mock** phone screen in the Live panel
- Commands show as **queued** (not executed on a real phone)

## Minimal agent loop (pseudocode)

```
token = secureStorage.read("agentToken")
loop every 20s:
  state = POST /api/agent/heartbeat
  if state.sessions.stream: ensureStreamerRunning(until=expiresAt)
  else: stopStreamer()
  if state.sessions.control:
    cmds = GET /api/agent/commands
    for c in cmds: apply(c); POST result
```

Android: MediaProjection + Device Admin / Accessibility (with clear consent).  
iOS: ScreenCaptureKit / MDM where allowed; many control APIs are restricted — document platform limits honestly in the product UI.
