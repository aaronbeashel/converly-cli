/**
 * Config + credential storage for the Converly CLI.
 *
 * Everything lives in ~/.converly/config.json (0600, dir 0700 — POSIX
 * modes; on Windows the file relies on the profile directory's ACLs).
 * Credentials are stored PER ORIGIN so a staging login and a production
 * login never collide:
 *
 * {
 *   "default_origin": "https://app.converly.io",
 *   "credentials": {
 *     "https://app.converly.io": {
 *       "access_token": "sk_live_...",
 *       "refresh_token": "...",
 *       "expires_at": 1760000000000,
 *       "client_id": "...",
 *       "scope": "openid ..."
 *     }
 *   }
 * }
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const PROD_ORIGIN = "https://app.converly.io";
export const STAGING_ORIGIN =
  "https://converly-frontend-staging.up.railway.app";

const CONFIG_DIR = path.join(os.homedir(), ".converly");
const CONFIG_PATH = path.join(CONFIG_DIR, "config.json");

export function configPath() {
  return CONFIG_PATH;
}

export function loadConfig() {
  try {
    const raw = fs.readFileSync(CONFIG_PATH, "utf8");
    const parsed = JSON.parse(raw);
    return typeof parsed === "object" && parsed !== null ? parsed : {};
  } catch {
    return {};
  }
}

export function saveConfig(cfg) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  // Atomic replace: a concurrent reader never sees a half-written file,
  // and a crash mid-write can't corrupt existing credentials.
  const tmp = path.join(
    CONFIG_DIR,
    `.config.${process.pid}.${Date.now()}.tmp`
  );
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, CONFIG_PATH);
  // Re-assert modes in case a pre-existing file/dir was more permissive.
  try {
    fs.chmodSync(CONFIG_DIR, 0o700);
    fs.chmodSync(CONFIG_PATH, 0o600);
  } catch {
    // Windows: chmod is a no-op / may fail — ACLs govern access there.
  }
}

function isLoopbackHost(hostname) {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname === "[::1]"
  );
}

/**
 * Normalize a user-supplied origin/URL to a bare origin.
 * Accepts "https://app.converly.io/api/v1", "app.converly.io", etc.
 * Refuses cleartext http for anything that isn't loopback — bearer
 * tokens must never travel unencrypted.
 */
export function normalizeOrigin(input) {
  let value = String(input).trim();
  if (!/^https?:\/\//i.test(value)) value = `https://${value}`;
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`Not a valid origin: ${input}`);
  }
  if (url.protocol === "http:" && !isLoopbackHost(url.hostname)) {
    throw new Error(
      `Refusing insecure origin ${url.origin} — use https (http is allowed only for localhost).`
    );
  }
  return url.origin;
}

/**
 * Resolve which Converly deployment to talk to.
 * Precedence: --api flag > CONVERLY_API_URL env > --staging flag >
 * config default_origin > production.
 */
export function resolveOrigin(flags = {}) {
  if (flags.api) return normalizeOrigin(flags.api);
  if (process.env.CONVERLY_API_URL) {
    return normalizeOrigin(process.env.CONVERLY_API_URL);
  }
  if (flags.staging) return STAGING_ORIGIN;
  const cfg = loadConfig();
  if (cfg.default_origin) return cfg.default_origin;
  return PROD_ORIGIN;
}

export function getStoredCredentials(origin) {
  const cfg = loadConfig();
  return cfg.credentials?.[origin] ?? null;
}

/**
 * Store credentials for an origin. Only a deliberate login should make
 * that origin the default deployment — a background token refresh must
 * not silently retarget future commands (pass makeDefault: false).
 */
export function setStoredCredentials(origin, creds, { makeDefault = true } = {}) {
  const cfg = loadConfig();
  cfg.credentials = cfg.credentials ?? {};
  cfg.credentials[origin] = creds;
  if (makeDefault) cfg.default_origin = origin;
  saveConfig(cfg);
}

export function clearStoredCredentials(origin) {
  const cfg = loadConfig();
  let changed = false;
  if (cfg.credentials?.[origin]) {
    delete cfg.credentials[origin];
    changed = true;
  }
  // Don't leave the default pointing at a deployment we just logged
  // out of — later commands would target it with no credentials.
  if (cfg.default_origin === origin) {
    delete cfg.default_origin;
    changed = true;
  }
  if (changed) saveConfig(cfg);
  return changed;
}

/**
 * Origins the CONVERLY_API_KEY environment credential may be sent to:
 * the known Converly deployments, plus an origin the user explicitly
 * configured via CONVERLY_API_URL. Never an arbitrary --api origin —
 * an induced `--api https://attacker.example` call must not become a
 * key-exfiltration channel.
 */
function envKeyAllowedOrigins() {
  const allowed = new Set([PROD_ORIGIN, STAGING_ORIGIN]);
  if (process.env.CONVERLY_API_URL) {
    try {
      allowed.add(normalizeOrigin(process.env.CONVERLY_API_URL));
    } catch {
      // Malformed CONVERLY_API_URL is reported where it's used.
    }
  }
  return allowed;
}

/**
 * Resolve the bearer token for API calls.
 * CONVERLY_API_KEY wins for the origins it is trusted for (headless
 * agents with a provisioned key); otherwise the stored OAuth token for
 * this origin. Returns { token, source } or null.
 */
export function resolveAuth(origin) {
  const envKey = process.env.CONVERLY_API_KEY;
  if (envKey && envKey.trim() && envKeyAllowedOrigins().has(origin)) {
    return { token: envKey.trim(), source: "env" };
  }
  const stored = getStoredCredentials(origin);
  if (stored?.access_token) {
    return { token: stored.access_token, source: "stored" };
  }
  return null;
}
