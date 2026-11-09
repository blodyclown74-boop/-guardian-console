# Guardian Console — Cloudflare deployment

This version adapts the supplied Node.js demo to Cloudflare Workers + D1. Static pages are served from `frontend/`; `/api/*` is handled by `worker.js`; persistent data lives in D1.

## Deploy (GitHub + Cloudflare dashboard)
1. Create a GitHub repository and upload **all contents** of this folder (not the enclosing folder).
2. In Cloudflare, open Workers & Pages → Create application → Pages/Workers Git integration (choose Workers, connect GitHub, select this repo).
3. Build command: `npx wrangler deploy`; root directory: `/`; deploy command as shown by Cloudflare. If the dashboard asks for a build command, use `npx wrangler deploy` as the deploy command and leave build empty.
4. Create a D1 database named `guardian-console-db` in Storage & databases → D1 SQL Database. Copy its database ID into `wrangler.jsonc` replacing `REPLACE_WITH_DATABASE_ID`.
5. In the D1 database console, execute the full contents of `migrations/0001_init.sql` once. Add binding `DB` to the Worker pointing to that database if not auto-created from wrangler config. Assets binding is `ASSETS`.
6. Deploy again. Open `/login.html`, create an account, and test login + child profile.

For CLI deployments, run `npx wrangler d1 create guardian-console-db`, copy the returned ID into `wrangler.jsonc`, then `npx wrangler d1 migrations apply guardian-console-db --remote` and `npx wrangler deploy`.

## Important limitations
- Dashboard report values are sample/demo data, not actual device telemetry. Real device monitoring requires a supported, consent-based Android/iOS integration; this web app cannot silently collect device activity.
- Sessions expire after 30 days. Passwords use PBKDF2-SHA-256 via Web Crypto.
- Keep the D1 database ID private-ish and never commit secrets or real user data. Use HTTPS (Cloudflare provides it).
