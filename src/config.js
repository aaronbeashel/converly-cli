/**
 * Config + credential storage for the Converly CLI.
 *
 * Everything lives in ~/.converly/config.json (0600, dir 0700).
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
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2) + "\n", {
    mode: 0o600,
  });
}

/**
 * Normalize a user-supplied origin/URL to a bare origin.
 * Accepts "https://app.converly.io/api/v1", "app.converly.io", etc.
 */
export function normalizeOrigin(input) {
  let value = String(input).trim();
  if (!/^https?:\/\//i.test(value)) value = `https://${value}`;
  const url = new URL(value);
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

export function setStoredCredentials(origin, creds) {
  const cfg = loadConfig();
  cfg.credentials = cfg.credentials ?? {};
  cfg.credentials[origin] = creds;
  cfg.default_origin = origin;
  saveConfig(cfg);
}

export function clearStoredCredentials(origin) {
  const cfg = loadConfig();
  if (cfg.credentials?.[origin]) {
    delete cfg.credentials[origin];
    saveConfig(cfg);
    return true;
  }
  return false;
}

/**
 * Resolve the bearer token for API calls.
 * CONVERLY_API_KEY always wins (headless agents with a provisioned key);
 * otherwise the stored OAuth token for this origin.
 * Returns { token, source } or null.
 */
export function resolveAuth(origin) {
  const envKey = process.env.CONVERLY_API_KEY;
  if (envKey && envKey.trim()) {
    return { token: envKey.trim(), source: "env" };
  }
  const stored = getStoredCredentials(origin);
  if (stored?.access_token) {
    return { token: stored.access_token, source: "stored" };
  }
  return null;
}
