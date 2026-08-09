/**
 * Thin HTTP client for the Converly /v1 API.
 *
 * - Adds the Bearer token and an auto-generated Idempotency-Key on POSTs.
 * - Surfaces API errors as ApiError carrying the server's error body.
 * - On a 401 with stored OAuth credentials, refreshes the token once and
 *   retries (env CONVERLY_API_KEY is never refreshed — it's not ours).
 */

import crypto from "node:crypto";
import { resolveAuth, getStoredCredentials } from "./config.js";
import { refreshCredentials } from "./oauth.js";

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
 * Perform one authenticated /v1 request.
 *
 * opts: { body, query, idempotencyKey }
 */
export async function apiRequest(origin, method, apiPath, opts = {}) {
  // No credentials: try unauthenticated (the catalogue endpoints are
  // public). A 401 then becomes the friendly "run converly login" error.
  const auth = resolveAuth(origin);

  const attempt = async (token) => {
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    let payload;
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(opts.body);
    }
    if (method === "POST") {
      headers["Idempotency-Key"] = opts.idempotencyKey ?? crypto.randomUUID();
    }
    const res = await fetch(buildUrl(origin, apiPath, opts.query), {
      method,
      headers,
      body: payload,
    });
    return { res, parsed: await parseBody(res) };
  };

  let { res, parsed } = await attempt(auth?.token ?? null);

  if (res.status === 401 && !auth) throw new AuthMissingError(origin);

  // One refresh-and-retry on 401 for stored OAuth credentials.
  if (res.status === 401 && auth.source === "stored") {
    const stored = getStoredCredentials(origin);
    if (stored?.refresh_token) {
      const refreshed = await refreshCredentials(origin).catch(() => null);
      if (refreshed?.access_token) {
        ({ res, parsed } = await attempt(refreshed.access_token));
      }
    }
  }

  if (!res.ok) throw new ApiError(res.status, parsed);
  return parsed;
}
