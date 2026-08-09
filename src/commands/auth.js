/**
 * Auth commands: login, logout, whoami.
 */

import {
  clearStoredCredentials,
  getStoredCredentials,
  resolveAuth,
} from "../config.js";
import { loginFlow } from "../oauth.js";
import { apiRequest } from "../http.js";

export async function login({ flags, origin }) {
  const result = await loginFlow({
    origin,
    signup: Boolean(flags.signup),
    progress: (line) => process.stderr.write(`${line}\n`),
  });
  return { ok: true, ...result };
}

export async function logout({ origin }) {
  const removed = clearStoredCredentials(origin);
  return { ok: true, origin, removed_stored_login: removed };
}

export async function whoami({ origin }) {
  const auth = resolveAuth(origin);
  const [subscription, sites] = await Promise.all([
    apiRequest(origin, "GET", "/subscription"),
    apiRequest(origin, "GET", "/sites", { query: { limit: 100 } }),
  ]);
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
