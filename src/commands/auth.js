/**
 * Auth commands: login, logout, whoami.
 */

import {
  clearStoredCredentials,
  getStoredCredentials,
  resolveAuth,
} from "../config.js";
import { loginFlow } from "../oauth.js";
import { deviceLoginFlow } from "../device-login.js";
import { apiRequest } from "../http.js";

export async function login({ flags, origin }) {
  const progress = (line) => process.stderr.write(`${line}\n`);
  // --device: approve from any device (phone, another computer). The
  // only path that works headless / on a remote box, where the loopback
  // browser flow can't (browser and CLI must share a machine there).
  if (flags.device) {
    const result = await deviceLoginFlow({
      origin,
      label: typeof flags.label === "string" ? flags.label : undefined,
      progress,
    });
    return { ok: true, ...result };
  }
  const result = await loginFlow({
    origin,
    signup: Boolean(flags.signup),
    noOpen: Boolean(flags["no-open"]),
    progress,
  });
  return { ok: true, ...result };
}

export async function logout({ origin }) {
  const removed = clearStoredCredentials(origin);
  return { ok: true, origin, removed_stored_login: removed };
}

export async function whoami({ origin }) {
  const auth = resolveAuth(origin);
  // Sequential on purpose: two parallel 401s would race the token
  // refresh. The second call rides the already-refreshed token.
  const subscription = await apiRequest(origin, "GET", "/subscription");
  const sites = await apiRequest(origin, "GET", "/sites", {
    query: { limit: 100 },
  });
  const stored = auth?.source === "stored" ? getStoredCredentials(origin) : null;
  return {
    origin,
    auth_source: auth?.source ?? null,
    scope: stored?.scope ?? null,
    subscription,
    sites: (sites?.data ?? []).map((s) => ({
      id: s.id,
      name: s.name,
      domain: s.domain,
      site_key: s.site_key,
    })),
  };
}
