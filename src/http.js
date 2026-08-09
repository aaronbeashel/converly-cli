/**
 * Thin HTTP client for the Converly /v1 API.
 *
 * - Adds the Bearer token and an idempotency key on POSTs. The key is
 *   generated ONCE per logical operation (not per attempt), so the
 *   internal refresh-retry after a 401 replays the same key and cannot
 *   double-create anything. Callers can pin a key across separate CLI
 *   invocations with --idempotency-key.
 * - Surfaces API errors as ApiError carrying the server's error body.
 * - On a 401 with stored OAuth credentials, refreshes the token once
 *   (single-flight per origin) and retries. A rejected CONVERLY_API_KEY
 *   is reported as exactly that — it is never silently substituted.
 * - Public catalogue endpoints are called WITHOUT credentials, so a
 *   stale token can't break an endpoint that needs no auth at all.
 * - Every request has a bounded timeout; nothing hangs forever.
 */

import crypto from "node:crypto";
import { createRequire } from "node:module";
import { resolveAuth, getStoredCredentials } from "./config.js";
import { refreshCredentials } from "./oauth.js";

const require = createRequire(import.meta.url);
const { version: VERSION } = require("../package.json");

const REQUEST_TIMEOUT_MS = 30_000;

export class ApiError extends Error {
  constructor(status, body) {
    const message =
      body?.error?.message ?? body?.error_description ?? `HTTP ${status}`;
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

export class AuthMissingError extends Error {
  constructor(origin) {
    super(
      `Not logged in to ${origin}. Run \`converly login\` (or set CONVERLY_API_KEY).`
    );
    this.name = "AuthMissingError";
  }
}

// Set once per CLI invocation from --idempotency-key, so retries of the
// same logical operation across separate invocations can share a key.
let defaultIdempotencyKey = null;
export function setDefaultIdempotencyKey(key) {
  defaultIdempotencyKey = key || null;
}

function buildUrl(origin, apiPath, query) {
  const url = new URL(`${origin}/api/v1${apiPath}`);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    }
  }
  return url;
}

async function parseBody(res) {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

/**
 * Perform one /v1 request.
 *
 * opts: { body, query, idempotencyKey, public }
 * `public: true` marks a no-auth catalogue endpoint — no credential is
 * attached and no login is required.
 */
export async function apiRequest(origin, method, apiPath, opts = {}) {
  const auth = opts.public ? null : resolveAuth(origin);

  // One key per logical operation — shared by every attempt below.
  const idempotencyKey =
    method === "POST"
      ? (opts.idempotencyKey ?? defaultIdempotencyKey ?? crypto.randomUUID())
      : null;

  const attempt = async (token) => {
    const headers = { "User-Agent": `converly-cli/${VERSION}` };
    if (token) headers.Authorization = `Bearer ${token}`;
    let payload;
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(opts.body);
    }
    if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
    let res;
    try {
      res = await fetch(buildUrl(origin, apiPath, opts.query), {
        method,
        headers,
        body: payload,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (cause) {
      if (cause?.name === "TimeoutError" || cause?.name === "AbortError") {
        throw new Error(
          `Request to ${origin} timed out after ${REQUEST_TIMEOUT_MS / 1000}s. ` +
            (idempotencyKey
              ? `Safe to retry with --idempotency-key ${idempotencyKey}.`
              : "Safe to retry.")
        );
      }
      throw cause;
    }
    return { res, parsed: await parseBody(res) };
  };

  let { res, parsed } = await attempt(auth?.token ?? null);

  if (res.status === 401) {
    if (!auth) throw new AuthMissingError(origin);

    if (auth.source === "env") {
      // Never mask a bad environment key by falling back to another
      // credential — say exactly what was rejected and how to fix it.
      const err = new ApiError(401, parsed);
      err.message = `CONVERLY_API_KEY was rejected by ${origin}. Unset it (to use \`converly login\`) or replace it with a valid key.`;
      throw err;
    }

    // Stored OAuth credential: refresh once (single-flight) and retry
    // with the SAME idempotency key.
    const stored = getStoredCredentials(origin);
    if (stored?.refresh_token) {
      let refreshed = null;
      try {
        refreshed = await refreshCredentials(origin);
      } catch {
        // Fall through to the reauth error below.
      }
      if (refreshed?.access_token) {
        ({ res, parsed } = await attempt(refreshed.access_token));
      }
    }
    if (res.status === 401) {
      const err = new ApiError(401, parsed);
      err.message = `Your login for ${origin} has expired and could not be refreshed. Run \`converly login\` again.`;
      err.code = "reauth_required";
      throw err;
    }
  }

  if (!res.ok) throw new ApiError(res.status, parsed);
  return parsed;
}
