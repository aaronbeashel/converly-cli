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
import crypto from "node:crypto";
import { setStoredCredentials, isSameTrustedOrigin } from "./config.js";
import { readTextCapped } from "./net.js";

// Fallback only — the server-returned expires_at is the real deadline
// (see deviceLoginFlow). 30 min matches the server handoff TTL.
const POLL_TIMEOUT_MS = 30 * 60 * 1000;
// Hard ceiling on the whole poll window, no matter what expiry the origin
// declares. A hostile/misconfigured server can't make the CLI poll for
// hours by returning a far-future expires_at.
const MAX_POLL_WINDOW_MS = 60 * 60 * 1000;
const MIN_POLL_INTERVAL_MS = 2000;
const MAX_POLL_INTERVAL_MS = 60_000;
// Device-login responses are tiny; refuse anything that isn't.
const MAX_RESPONSE_BYTES = 1_000_000;

function defaultLabel() {
  try {
    const host = os.hostname();
    return host ? host.slice(0, 64) : null;
  } catch {
    return null;
  }
}

async function readJsonCapped(res) {
  // Streaming cap so an absent/lying Content-Length can't exhaust memory.
  const read = await readTextCapped(res, MAX_RESPONSE_BYTES);
  if (read.overLimit || read.unreadable || !read.text) return null;
  try {
    return JSON.parse(read.text);
  } catch {
    return null;
  }
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
    // "manual" (not "error"): a device-login endpoint never legitimately
    // redirects, but we want a 3xx to surface as a non-ok RESPONSE so the
    // poll loop fails fast on it — with "error" the fetch would throw and
    // the loop's transient-catch would poll for the full window instead.
    redirect: "manual",
    signal: AbortSignal.timeout(30_000),
  });
  const parsed = await readJsonCapped(res);
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
  if (
    !start.res.ok ||
    typeof start.parsed?.poll_token !== "string" ||
    !start.parsed.poll_token.trim()
  ) {
    const detail =
      start.parsed?.message ?? start.parsed?.error ?? `HTTP ${start.res.status}`;
    throw new Error(`Could not start device login: ${detail}`);
  }
  const { user_code, verification_url, poll_token, poll_interval_ms, expires_at } =
    start.parsed;

  // The origin is trusted (it's where we're logging in), but a malformed
  // response shouldn't print an empty code or a non-URL. Fail clearly.
  if (typeof user_code !== "string" || !user_code.trim()) {
    throw new Error("Device login response was missing a user code.");
  }
  // The verification page must live on the SAME deployment we're logging
  // in to — never send the human to a different host (a same-origin check
  // also guarantees https for the real deployments). This is the URL we
  // literally tell them to open, so it must be trustworthy.
  if (!isSameTrustedOrigin(verification_url, origin)) {
    throw new Error(
      `Device login returned a verification URL that isn't on ${origin}. Aborting.`
    );
  }
  // Print the canonical parsed form, not the raw string.
  const canonicalVerifyUrl = new URL(verification_url).href;

  progress("To finish logging in, open this page on any device (your phone is fine):");
  progress(`\n  ${canonicalVerifyUrl}\n`);
  progress(`and enter this code:  ${user_code}\n`);
  progress("Waiting for you to approve it...");

  // Clamp the interval both ways: a floor keeps us from hammering the
  // endpoint, a ceiling keeps a bad server value from stalling the poll.
  const intervalMs = Math.min(
    MAX_POLL_INTERVAL_MS,
    Math.max(MIN_POLL_INTERVAL_MS, Number(poll_interval_ms) || 5000)
  );
  // Poll until the SERVER's own expiry, so the CLI never stops listening
  // while the code is still approvable. A stale/absent value falls back to
  // the local cap. (Codex round 1: a 15-min CLI cap under a 30-min server
  // TTL left a window where the page could mint a key nobody was polling
  // for.) Bounded by a hard ceiling so a far-future expiry can't make us
  // poll indefinitely.
  const hardCeiling = Date.now() + MAX_POLL_WINDOW_MS;
  const serverDeadline = expires_at ? new Date(expires_at).getTime() : NaN;
  let deadline = Number.isFinite(serverDeadline)
    ? Math.min(serverDeadline, hardCeiling)
    : Date.now() + POLL_TIMEOUT_MS;

  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, intervalMs));
    let poll;
    try {
      poll = await postJson(`${origin}/api/public/device-login/poll`, {
        poll_token,
      });
    } catch {
      continue; // transient network error — keep polling until the deadline
    }
    // Only a 2xx is trustworthy. Retry a genuinely transient HTTP failure
    // (429 / 5xx); fail FAST on anything else so a permanent error (bad
    // token, revoked session, an unexpected redirect we refused) can't be
    // hammered for the full window. Critically, never read `api_key` from
    // a non-2xx body.
    if (!poll.res.ok) {
      if (poll.res.status === 429 || poll.res.status >= 500) {
        continue;
      }
      if (poll.res.status === 404) {
        throw new Error(
          "The login session wasn't found. Run `converly login --device` again."
        );
      }
      const detail =
        poll.parsed?.message ?? poll.parsed?.error ?? `HTTP ${poll.res.status}`;
      throw new Error(`Device login failed: ${detail}`);
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
      if (Number.isFinite(t) && t > deadline) {
        deadline = Math.min(t, hardCeiling);
      }
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
    if (status === "already_claimed") {
      throw new Error(
        "This code was already used. Run `converly login --device` again."
      );
    }
    if (status === "complete") {
      const apiKey = poll.parsed?.api_key;
      if (typeof apiKey !== "string" || !apiKey.trim()) {
        throw new Error(
          "Device login completed but returned no API key. Run `converly login --device` again."
        );
      }
      // No refresh token — device-login mints a long-lived API key.
      setStoredCredentials(
        origin,
        {
          access_token: apiKey,
          refresh_token: null,
          expires_at: null,
          scope: null,
          client_id: null,
          obtained_at: new Date().toISOString(),
          source_kind: "device_login",
          // Tag the login session (see oauth.js) so an in-flight request
          // can detect a concurrent login before replaying under it.
          login_generation: crypto.randomBytes(8).toString("hex"),
        },
        { makeDefault: true }
      );
      return { origin, via: "device_login" };
    }
    // A 2xx with a status this CLI version doesn't recognise — waiting for
    // it to change is futile. Tell the user to update rather than spin.
    throw new Error(
      `Device login returned an unexpected status "${status ?? "(none)"}". ` +
        "Update the CLI (npm install -g converly) and try again."
    );
  }
  throw new Error(
    "The code expired before it was approved. Run `converly login --device` again when you're ready."
  );
}
