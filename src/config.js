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
import crypto from "node:crypto";

export const PROD_ORIGIN = "https://app.converly.io";
export const STAGING_ORIGIN =
  "https://converly-frontend-staging.up.railway.app";

const CONFIG_DIR = path.join(os.homedir(), ".converly");
const CONFIG_PATH = path.join(CONFIG_DIR, "config.json");
const LOCK_PATH = path.join(CONFIG_DIR, "config.lock");
// The refresh lock is separate from the config lock: it's held ACROSS the
// network token refresh (so two processes can't refresh the same rotating
// token and trip reuse-revocation), whereas the config lock only ever
// wraps the sub-millisecond read-modify-write of the file.
const REFRESH_LOCK_PATH = path.join(CONFIG_DIR, "refresh.lock");
// How long to wait to acquire each lock. The config lock is held only for
// a sync file write, so 5s is ample. The refresh lock can be held across
// two 30s network calls (discovery + token), so a waiter must be patient.
const CONFIG_LOCK_WAIT_MS = 5000;
const REFRESH_LOCK_WAIT_MS = 65_000;

export function configPath() {
  return CONFIG_PATH;
}

function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const CORRUPT_HINT = `Fix or remove it, then run \`converly login\` again.`;

export function loadConfig() {
  let raw;
  try {
    raw = fs.readFileSync(CONFIG_PATH, "utf8");
  } catch (err) {
    // No config yet is the normal first-run state — start empty. Any
    // OTHER read failure (permissions, I/O) must NOT masquerade as
    // "logged out": returning {} here would let a later save overwrite a
    // config we simply couldn't read. Surface it instead.
    if (err?.code === "ENOENT") return {};
    throw new Error(`Could not read ${CONFIG_PATH}: ${err?.message ?? err}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // A corrupt file is recoverable by the user but must never be
    // silently clobbered — tell them exactly what to do.
    throw new Error(`Config at ${CONFIG_PATH} is not valid JSON. ${CORRUPT_HINT}`);
  }
  // Structure matters as much as syntax. An array or scalar passes
  // JSON.parse but would silently drop assigned properties on save (login
  // would report success and store nothing). A malformed `credentials`
  // block would do the same. Reject rather than accept-and-lose.
  if (!isPlainObject(parsed)) {
    throw new Error(`Config at ${CONFIG_PATH} must be a JSON object. ${CORRUPT_HINT}`);
  }
  if (parsed.credentials !== undefined && !isPlainObject(parsed.credentials)) {
    throw new Error(
      `Config at ${CONFIG_PATH} has an invalid "credentials" section. ${CORRUPT_HINT}`
    );
  }
  if (
    parsed.default_origin !== undefined &&
    typeof parsed.default_origin !== "string"
  ) {
    throw new Error(
      `Config at ${CONFIG_PATH} has an invalid "default_origin". ${CORRUPT_HINT}`
    );
  }
  return parsed;
}

// --- Cross-process file locks ---
//
// Atomic rename alone stops a torn FILE, but two processes that both read,
// mutate, and write still lose one update (or resurrect a logged-out
// credential). An exclusive lockfile serialises the whole transaction.
//
// Design (deliberately simple + provably safe rather than clever):
//   - ACQUIRE is ATOMIC: the stamp is written to a temp file which is then
//     hard-linked to the lock path. link() fails if the lock already
//     exists, so the lock is NEVER observed empty (no create-then-stamp
//     window a contender could misread).
//   - There is NO automatic stale-stealing. Stealing a lock from a live
//     holder — or racing two stealers — is exactly how mutual exclusion
//     breaks, so we don't. A lock is only ever removed by (a) its owner on
//     release, ownership-checked, or (b) our exit/interrupt cleanup, or (c)
//     the user, whom we tell precisely how, after a bounded timeout.
//   - Cleanup on process exit / Ctrl-C releases anything we still hold, so
//     an interrupted command doesn't strand a lock (only a hard kill can).

function sleepSync(ms) {
  // Real sleep with no busy-spin — safe in a short-lived CLI process.
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function lockStamp() {
  return `${process.pid}.${crypto.randomBytes(8).toString("hex")}`;
}

// Locks this process currently holds, released on exit / interrupt so a
// Ctrl-C'd command never strands one. Keyed by lock path → our stamp.
const heldLocks = new Map();
let cleanupInstalled = false;
function installCleanupOnce() {
  if (cleanupInstalled) return;
  cleanupInstalled = true;
  const releaseAll = () => {
    for (const [p, s] of heldLocks) releaseLock(p, s);
  };
  process.on("exit", releaseAll);
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
    process.on(sig, () => {
      releaseAll();
      // We overrode the default terminate, so exit explicitly with the
      // conventional 128+signal code.
      const code = sig === "SIGINT" ? 130 : sig === "SIGTERM" ? 143 : 129;
      process.exit(code);
    });
  }
}

// Atomically create the lock file already containing our stamp. Returns
// true if we got it, false if another holder has it. Never leaves an empty
// or half-written lock behind.
function tryCreateLock(lockPath, stamp) {
  const tmp = `${lockPath}.${process.pid}.${crypto.randomBytes(6).toString("hex")}`;
  try {
    // Write INSIDE the try so the finally always cleans the temp up, even
    // if the write itself fails after creating the file.
    fs.writeFileSync(tmp, stamp, { mode: 0o600 });
    fs.linkSync(tmp, lockPath); // atomic; fails EEXIST if already held
    return true;
  } catch (err) {
    if (err?.code === "EEXIST") return false;
    throw err;
  } finally {
    try {
      fs.rmSync(tmp, { force: true });
    } catch {
      // best effort
    }
  }
}

function releaseLock(lockPath, stamp) {
  // Ownership-checked: only remove the lock if it still holds OUR stamp, so
  // we can never delete a lock a successor acquired after ours was gone.
  try {
    if (fs.readFileSync(lockPath, "utf8") === stamp) {
      fs.rmSync(lockPath, { force: true });
    }
  } catch {
    // already gone / unreadable
  }
  heldLocks.delete(lockPath);
}

function acquireLockSync(lockPath, waitMs) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  installCleanupOnce();
  const stamp = lockStamp();
  const deadline = Date.now() + waitMs;
  for (;;) {
    if (tryCreateLock(lockPath, stamp)) {
      heldLocks.set(lockPath, stamp);
      return stamp;
    }
    if (Date.now() >= deadline) {
      const err = new Error(
        `Timed out waiting for the lock at ${lockPath}. Another converly ` +
          `process may be running; if not, delete that file and retry.`
      );
      err.code = "lock_timeout";
      throw err;
    }
    sleepSync(50);
  }
}

function withConfigLock(fn) {
  const stamp = acquireLockSync(LOCK_PATH, CONFIG_LOCK_WAIT_MS);
  try {
    return fn();
  } finally {
    releaseLock(LOCK_PATH, stamp);
  }
}

/**
 * Hold the cross-process REFRESH lock across an async token refresh, so two
 * processes can't refresh the same rotating refresh token simultaneously
 * (which some servers treat as token theft and revoke the whole family).
 * Uses async sleep between attempts — the lock spans real network calls.
 */
export async function withRefreshLock(asyncFn) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  installCleanupOnce();
  const stamp = lockStamp();
  const deadline = Date.now() + REFRESH_LOCK_WAIT_MS;
  for (;;) {
    if (tryCreateLock(REFRESH_LOCK_PATH, stamp)) {
      heldLocks.set(REFRESH_LOCK_PATH, stamp);
      try {
        return await asyncFn();
      } finally {
        releaseLock(REFRESH_LOCK_PATH, stamp);
      }
    }
    if (Date.now() >= deadline) {
      const err = new Error(
        `Timed out waiting for the refresh lock at ${REFRESH_LOCK_PATH}. ` +
          `Another converly process may be refreshing; if not, delete that file and retry.`
      );
      err.code = "lock_timeout";
      throw err;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}

export function saveConfig(cfg) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  // Atomic replace: a concurrent reader never sees a half-written file,
  // and a crash mid-write can't corrupt existing credentials.
  const tmp = path.join(
    CONFIG_DIR,
    `.config.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`
  );
  let renamed = false;
  try {
    fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
    fs.renameSync(tmp, CONFIG_PATH);
    renamed = true;
  } finally {
    // A failed write/rename must not leave a 0600 temp file holding tokens.
    if (!renamed) {
      try {
        fs.rmSync(tmp, { force: true });
      } catch {
        // best effort
      }
    }
  }
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
 * Precedence: --api flag > --staging flag > CONVERLY_API_URL env >
 * config default_origin > production. Explicit command-line selectors beat
 * the environment so `--staging` is never silently overridden by a stray
 * CONVERLY_API_URL.
 */
export function resolveOrigin(flags = {}) {
  // Two conflicting deployment selectors is always a mistake — refuse
  // rather than silently honouring one and ignoring the other.
  if (flags.api && flags.staging) {
    throw new Error(
      "Pass either --api or --staging, not both — they select different deployments."
    );
  }
  // Explicit command-line selectors beat the environment (same as --api),
  // which beats config, which beats the production default. An explicit
  // --staging must NOT be silently overridden by CONVERLY_API_URL —
  // otherwise `flows delete X --staging` could hit production.
  if (flags.api) return normalizeOrigin(flags.api);
  if (flags.staging) return STAGING_ORIGIN;
  if (process.env.CONVERLY_API_URL) {
    return normalizeOrigin(process.env.CONVERLY_API_URL);
  }
  const cfg = loadConfig();
  // Presence, NOT truthiness: an empty-string default_origin must not slip
  // through the `if` and silently fall back to production. If a default is
  // present at all, it must resolve to a valid origin or fail loudly —
  // otherwise a create / publish / delete could hit prod with prod creds.
  if (cfg.default_origin !== undefined) {
    try {
      return normalizeOrigin(cfg.default_origin);
    } catch {
      throw new Error(
        `Saved default deployment ${JSON.stringify(cfg.default_origin)} is not a valid origin. ` +
          `Run \`converly login\` again, or pass --api <origin> / --staging for this command.`
      );
    }
  }
  return PROD_ORIGIN;
}

/**
 * Is `urlString` on exactly the same origin we already trust (`origin`),
 * with no embedded credentials? Used to pin every OAuth-discovery endpoint
 * and every device-login URL to the deployment the user actually chose —
 * discovery metadata must never widen the trust boundary to another host
 * (which could exfiltrate a refresh token / PKCE verifier).
 */
export function isSameTrustedOrigin(urlString, origin) {
  try {
    const u = new URL(String(urlString));
    if (u.username || u.password) return false;
    return u.origin === origin;
  } catch {
    return false;
  }
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
  // Read-modify-write under the lock so a concurrent login/logout in
  // another process can't lose this update or resurrect a removed one.
  withConfigLock(() => {
    const cfg = loadConfig();
    cfg.credentials = cfg.credentials ?? {};
    cfg.credentials[origin] = creds;
    if (makeDefault) cfg.default_origin = origin;
    saveConfig(cfg);
  });
}

export function clearStoredCredentials(origin) {
  return withConfigLock(() => {
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
  });
}

/**
 * Commit refreshed credentials with a compare-and-swap, under the config
 * lock, so a token refresh that raced a logout, a login, or another refresh
 * can't clobber the winner:
 *   - returns { ok: false, current: null }  if the credential was cleared
 *     (a logout landed while we were on the network) — do NOT resurrect it;
 *   - returns { ok: false, current }         if ANY identifying field of
 *     the stored credential changed under us (another refresh rotated the
 *     token, or a login replaced it) — adopt THEIR result, don't overwrite;
 *   - returns { ok: true }                   and stores our creds otherwise.
 * `expected` is the credential we based this refresh on — we require the
 * stored access_token, refresh_token AND client_id to still match it, not
 * just the refresh token (a concurrent login could change the others while
 * keeping the same refresh token).
 */
export function commitRefreshedCredentials(origin, creds, expected) {
  return withConfigLock(() => {
    const cfg = loadConfig();
    const current = cfg.credentials?.[origin] ?? null;
    if (!current?.access_token) {
      return { ok: false, current: null };
    }
    const unchanged =
      current.access_token === expected?.access_token &&
      current.refresh_token === expected?.refresh_token &&
      current.client_id === expected?.client_id &&
      (current.login_generation ?? null) === (expected?.login_generation ?? null);
    if (!unchanged) {
      return { ok: false, current };
    }
    cfg.credentials = cfg.credentials ?? {};
    cfg.credentials[origin] = creds;
    // A refresh must never retarget the default deployment.
    saveConfig(cfg);
    return { ok: true };
  });
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
 * this origin. Returns { token, source, generation } or null.
 *
 * `generation` is the stored credential's login_generation, read from the
 * SAME snapshot as the token (null for the env key). Callers compare it
 * before replaying a request after a refresh, so token and generation must
 * come from one read — reading them separately reintroduces a race where a
 * concurrent login swaps the credential in between.
 */
export function resolveAuth(origin) {
  const envKey = process.env.CONVERLY_API_KEY;
  if (envKey && envKey.trim() && envKeyAllowedOrigins().has(origin)) {
    return { token: envKey.trim(), source: "env", generation: null };
  }
  const stored = getStoredCredentials(origin);
  if (stored?.access_token) {
    return {
      token: stored.access_token,
      source: "stored",
      generation: stored.login_generation ?? null,
    };
  }
  return null;
}
