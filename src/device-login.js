/**
 * Device-code login for the CLI — the headless / remote sibling of the
 * loopback browser login in oauth.js.
 *
 * The loopback flow needs the browser and the CLI on the same machine.
 * That fails on a server, in CI, in a container, or when the human only
 * has their phone. Device login removes the constraint: the CLI shows a
 * short code + a URL, the human opens that URL on ANY device, signs in,
 * enters the code, and the CLI polls until a scoped API key comes back.
 *
 * The key is stored exactly like a browser-login token (per origin, in
 * ~/.converly/config.json) so every later command is authenticated the
 * same way. It has no refresh token — it's a long-lived key the user can
 * see and revoke in Settings → API keys (a device-login key is an
 * ordinary key row there).
 */

import os from "node:os";
import { setStoredCredentials } from "./config.js";

// Fallback only — the server-returned expires_at is the real deadline
// (see deviceLoginFlow). 30 min matches the server handoff TTL.
const POLL_TIMEOUT_MS = 30 * 60 * 1000;

function defaultLabel() {
  try {
    const host = os.hostname();
    return host ? host.slice(0, 64) : null;
  } catch {
    return null;
  }
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
    signal: AbortSignal.timeout(30_000),
  });
  const parsed = await res.json().catch(() => null);
  return { res, parsed };
}

/**
 * Run the device-code login against `origin`. progress() gets human
 * status lines (callers send them to stderr). Returns the stored
 * credentials summary, or throws with an actionable message.
 */
export async function deviceLoginFlow({ origin, label, progress = () => {} }) {
  const start = await postJson(`${origin}/api/public/device-login`, {
    label: label ?? defaultLabel() ?? undefined,
  });
  if (!start.res.ok || !start.parsed?.poll_token) {
    const detail =
      start.parsed?.message ?? start.parsed?.error ?? `HTTP ${start.res.status}`;
    throw new Error(`Could not start device login: ${detail}`);
  }
  const { user_code, verification_url, poll_token, poll_interval_ms, expires_at } =
    start.parsed;

  progress("To finish logging in, open this page on any device (your phone is fine):");
  progress(`\n  ${verification_url}\n`);
  progress(`and enter this code:  ${user_code}\n`);
  progress("Waiting for you to approve it...");

  const intervalMs = Math.max(2000, Number(poll_interval_ms) || 5000);
  // Poll until the SERVER's own expiry, so the CLI never stops listening
  // while the code is still approvable. A stale/absent value falls back to
  // the local cap. (Codex round 1: a 15-min CLI cap under a 30-min server
  // TTL left a window where the page could mint a key nobody was polling
  // for.)
  const serverDeadline = expires_at ? new Date(expires_at).getTime() : NaN;
  let deadline = Number.isFinite(serverDeadline)
    ? serverDeadline
    : Date.now() + POLL_TIMEOUT_MS;

  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, intervalMs));
    let poll;
    try {
      poll = await postJson(`${origin}/api/public/device-login/poll`, {
        poll_token,
      });
    } catch {
      continue; // transient — keep polling until the deadline
    }
    const status = poll.parsed?.status;
    if (status === "pending") {
      // The approval claim can EXTEND the server expiry (GREATEST) so a
      // near-deadline approval has time to settle the trial + mint. Track
      // the current expires_at so the CLI never stops listening while the
      // code is still completable (Codex round 3).
      const t = poll.parsed?.expires_at
        ? new Date(poll.parsed.expires_at).getTime()
        : NaN;
      if (Number.isFinite(t) && t > deadline) deadline = t;
      continue;
    }
    if (status === "denied") {
      throw new Error("The login was declined in the browser.");
    }
    if (status === "expired") {
      throw new Error(
        "The code expired before it was approved. Run `converly login --device` again for a fresh one."
      );
    }
    if (status === "complete" && poll.parsed.api_key) {
      // No refresh token — device-login mints a long-lived API key.
      setStoredCredentials(
        origin,
        {
          access_token: poll.parsed.api_key,
          refresh_token: null,
          expires_at: null,
          scope: null,
          client_id: null,
          obtained_at: new Date().toISOString(),
          source_kind: "device_login",
        },
        { makeDefault: true }
      );
      return { origin, via: "device_login" };
    }
    if (status === "already_claimed") {
      throw new Error(
        "This code was already used. Run `converly login --device` again."
      );
    }
    if (poll.res.status === 404) {
      throw new Error(
        "The login session wasn't found. Run `converly login --device` again."
      );
    }
    // Unknown status — keep waiting rather than aborting a live approval.
  }
  throw new Error(
    "The code expired before it was approved. Run `converly login --device` again when you're ready."
  );
}
