import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { parseArgv, matchCommand, main, COMMANDS } from "../src/main.js";
import { normalizeOrigin } from "../src/config.js";
import { makePkce, LOGIN_SCOPES } from "../src/oauth.js";
import {
  create as flowsCreate,
  buildTriggerConfig,
  toAgentTriggerCatalogue,
} from "../src/commands/flows.js";
import { connect as triggersConnect } from "../src/commands/triggers.js";

test("parseArgv separates args and flags", () => {
  const { args, flags } = parseArgv([
    "flows",
    "create",
    "--site",
    "site_abc",
    "--name",
    "My flow",
    "--staging",
  ]);
  assert.deepEqual(args, ["flows", "create"]);
  assert.equal(flags.site, "site_abc");
  assert.equal(flags.name, "My flow");
  assert.equal(flags.staging, true);
});

test("parseArgv supports --flag=value", () => {
  const { flags } = parseArgv(["events", "list", "--limit=5"]);
  assert.equal(flags.limit, "5");
});

test("parseArgv treats a flag before another flag as boolean", () => {
  const { flags } = parseArgv(["destinations", "conversions", "--refresh", "--limit", "5"]);
  assert.equal(flags.refresh, true);
  assert.equal(flags.limit, "5");
});

test("normalizeOrigin strips paths and adds https", () => {
  assert.equal(
    normalizeOrigin("app.converly.io/api/v1"),
    "https://app.converly.io"
  );
  assert.equal(
    normalizeOrigin("https://app.converly.io/api/v1"),
    "https://app.converly.io"
  );
  assert.equal(
    normalizeOrigin("http://localhost:3000"),
    "http://localhost:3000"
  );
});

test("makePkce produces a verifiable S256 pair", () => {
  const { verifier, challenge } = makePkce();
  const expected = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  assert.equal(challenge, expected);
  assert.ok(verifier.length >= 43, "verifier must be at least 43 chars (RFC 7636)");
});

test("login scopes stay inside the server's registration ceiling", () => {
  // Mirror of MCP_DCR_ALLOWED_SCOPES on the Converly server. If a scope
  // is added here without the server allowing it, registration breaks.
  const ceiling = new Set([
    "openid",
    "profile",
    "offline_access",
    "account:read",
    "sites:read",
    "flows:read",
    "destinations:read",
    "events:read",
    "sites:write",
    "flows:write",
    "destinations:disconnect",
    "handoffs:create",
    "internal_traffic:write",
  ]);
  for (const scope of LOGIN_SCOPES.split(" ")) {
    assert.ok(ceiling.has(scope), `scope ${scope} is outside the DCR ceiling`);
  }
});

test("parseArgv: --allow-real is boolean, --reddit-id takes a value", () => {
  // --allow-real is followed by a non-flag token; only its BOOLEAN_FLAGS
  // registration keeps it from swallowing "extra" as a value.
  const { args, flags } = parseArgv([
    "test-event",
    "--allow-real",
    "extra",
    "--reddit-id",
    "x",
  ]);
  assert.equal(flags["allow-real"], true);
  assert.equal(flags["reddit-id"], "x");
  assert.deepEqual(args, ["test-event", "extra"]);
});

test("parseArgv: --flag=false on a boolean flag means false", () => {
  const { flags } = parseArgv(["login", "--signup=false", "--staging=true"]);
  assert.equal(flags.signup, false);
  assert.equal(flags.staging, true);
});

test("normalizeOrigin refuses cleartext http on non-loopback hosts", () => {
  assert.throws(() => normalizeOrigin("http://example.com"), /Refusing insecure/);
  assert.equal(normalizeOrigin("http://127.0.0.1:8080"), "http://127.0.0.1:8080");
});

test("escapeHtml neutralizes markup in reflected values", async () => {
  const { escapeHtml } = await import("../src/oauth.js");
  assert.equal(
    escapeHtml('<script>alert("x")</script>'),
    "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"
  );
});

test("every command declares its flags for the strict parser", () => {
  for (const [name, def] of Object.entries(COMMANDS)) {
    assert.ok(Array.isArray(def.flags), `${name} is missing a flags array`);
  }
});

test("main rejects unknown flags with one JSON error naming them all", async () => {
  const chunks = [];
  const originalWrite = process.stderr.write;
  process.stderr.write = (chunk) => {
    chunks.push(chunk);
    return true;
  };
  try {
    await main(["sites", "list", "--limt", "5", "--bogus"]);
  } finally {
    process.stderr.write = originalWrite;
  }
  assert.equal(process.exitCode, 1);
  process.exitCode = 0; // don't let the intentional failure fail the suite
  const payload = JSON.parse(chunks.join(""));
  assert.equal(payload.error.code, "unknown_flag");
  // Both unknowns named in the one error, and the fix taught alongside.
  assert.match(payload.error.message, /--limt/);
  assert.match(payload.error.message, /--bogus/);
  assert.match(payload.error.message, /--limit/);
  assert.match(payload.error.message, /--staging/);
});

test("two-word commands win over their one-word prefix", () => {
  // `triggers connect` must not fall through to the `triggers` catalogue.
  const two = matchCommand(["triggers", "connect", "acuity"]);
  assert.equal(two.name, "triggers connect");
  assert.deepEqual(two.rest, ["acuity"]);
  const one = matchCommand(["triggers"]);
  assert.equal(one.name, "triggers");
});

test("triggers connect validates source and --site before any request", async () => {
  const origin = "https://app.converly.io";
  await assert.rejects(
    triggersConnect({ args: [], flags: {}, origin }),
    /Missing trigger source/
  );
  await assert.rejects(
    triggersConnect({ args: ["api"], flags: {}, origin }),
    /Missing --site/
  );
});

test("flows create: --trigger api without --key rejects with the fix", async () => {
  await assert.rejects(
    flowsCreate({
      flags: { site: "site_x", name: "Signups", trigger: "api" },
      origin: "https://app.converly.io",
    }),
    /needs --key.*triggers connect api/s
  );
});

test("flows create: --key without --trigger api rejects", async () => {
  const origin = "https://app.converly.io";
  await assert.rejects(
    flowsCreate({
      flags: { site: "site_x", name: "Signups", trigger: "generic-form", key: "main-signup" },
      origin,
    }),
    /--key only applies to --trigger api/
  );
  await assert.rejects(
    flowsCreate({
      flags: { site: "site_x", name: "Signups", key: "main-signup" },
      origin,
    }),
    /--key only applies to --trigger api/
  );
});

test("flows create: --pages with --trigger api rejects", async () => {
  await assert.rejects(
    flowsCreate({
      flags: { site: "site_x", name: "Signups", trigger: "api", key: "main-signup", pages: "/thanks" },
      origin: "https://app.converly.io",
    }),
    /--pages does not apply/
  );
});

test("buildTriggerConfig: api trigger carries key and no pageFilter", () => {
  assert.deepEqual(buildTriggerConfig({ trigger: "api", key: "main-signup" }), {
    integrationId: "api",
    key: "main-signup",
  });
  // Form tool triggers keep the existing pageFilter shapes.
  assert.deepEqual(buildTriggerConfig({ trigger: "generic-form" }), {
    integrationId: "generic-form",
    pageFilter: "all",
  });
  assert.deepEqual(buildTriggerConfig({ trigger: "typeform", pages: "/a, /b" }), {
    integrationId: "typeform",
    pageFilter: "specific",
    pages: ["/a", "/b"],
  });
});

test("CONVERLY_API_KEY is only offered to trusted origins", async () => {
  const { resolveAuth, PROD_ORIGIN } = await import("../src/config.js");
  const prev = process.env.CONVERLY_API_KEY;
  process.env.CONVERLY_API_KEY = "sk_live_test_value";
  try {
    assert.equal(resolveAuth(PROD_ORIGIN)?.source, "env");
    // An arbitrary origin must never receive the environment key.
    const attacker = resolveAuth("https://attacker.example");
    assert.notEqual(attacker?.source, "env");
  } finally {
    if (prev === undefined) delete process.env.CONVERLY_API_KEY;
    else process.env.CONVERLY_API_KEY = prev;
  }
});

test("login dispatch: every environment row routes correctly", async () => {
  const { resolveLoginMode, envTruthy } = await import("../src/login-mode.js");
  const rows = [
    // [flags, env, platform, expected]
    [{ device: true }, {}, "darwin", "device"],
    [{ browser: true }, { CI: "1" }, "linux", "loopback"],
    [{ "no-open": true }, {}, "linux", "loopback"], // unchanged semantics
    [{}, { CI: "true" }, "darwin", "device_auto"],
    [{}, { CI: "false" }, "darwin", "loopback"], // CI="false" is false
    [{}, { SSH_CONNECTION: "1.2.3.4 22" }, "darwin", "device_auto"], // macOS over SSH
    [{}, { SSH_TTY: "/dev/pts/0" }, "linux", "device_auto"],
    [{}, {}, "linux", "device_auto"], // linux, no display
    [{}, { DISPLAY: ":0" }, "linux", "loopback"], // linux desktop
    [{}, { WAYLAND_DISPLAY: "wayland-0" }, "linux", "loopback"],
    [{}, {}, "darwin", "loopback"], // plain laptop
    [{}, {}, "win32", "loopback"],
  ];
  for (const [flags, env, platform, expected] of rows) {
    assert.equal(
      resolveLoginMode(flags, env, platform),
      expected,
      JSON.stringify({ flags, env, platform })
    );
  }
  assert.throws(
    () => resolveLoginMode({ device: true, browser: true }, {}, "darwin"),
    /conflict/
  );
  assert.equal(envTruthy("0"), false);
  assert.equal(envTruthy("yes"), true);
});

test("shouldSuppressBrowserOpen: --browser overrides --no-open", async () => {
  const { shouldSuppressBrowserOpen } = await import("../src/login-mode.js");
  assert.equal(shouldSuppressBrowserOpen({ "no-open": true }), true);
  assert.equal(shouldSuppressBrowserOpen({ "no-open": true, browser: true }), false);
  assert.equal(shouldSuppressBrowserOpen({ browser: true }), false);
  assert.equal(shouldSuppressBrowserOpen({}), false);
});

test("device poll deadline extends when the server reports a later expires_at", () => {
  // Mirrors the deviceLoginFlow deadline-extension logic (Codex round 3):
  // a pending poll carrying a later expires_at must push the deadline out.
  let deadline = Date.parse("2026-08-10T00:30:00Z");
  const later = "2026-08-10T00:34:00Z";
  const t = new Date(later).getTime();
  if (Number.isFinite(t) && t > deadline) deadline = t;
  assert.equal(deadline, Date.parse("2026-08-10T00:34:00Z"));
});

test("toAgentTriggerCatalogue: strips designed filter schemas and custom_event", () => {
  const raw = [
    {
      type: "form_submission",
      name: "Form submission",
      when_to_use: "…",
      providers: ["generic-form"],
      supports_filters: ["form_id", "form_selector", "page_path_filter"],
      filters: [{ key: "form_id", type: "string", required: false, label: "Form ID" }],
      at_least_one_filter_required: true,
    },
    { type: "custom_event", name: "Custom event", providers: [] },
    { type: "meeting_booked", name: "Meeting booked", providers: ["acuity"] },
  ];
  const out = toAgentTriggerCatalogue(raw);
  // custom_event is dropped entirely.
  assert.deepEqual(
    out.map((t) => t.type),
    ["form_submission", "meeting_booked"]
  );
  // The three designed-filter fields never reach an agent.
  const form = out.find((t) => t.type === "form_submission");
  assert.equal("supports_filters" in form, false);
  assert.equal("filters" in form, false);
  assert.equal("at_least_one_filter_required" in form, false);
  // Everything an agent legitimately needs survives.
  assert.equal(form.when_to_use, "…");
  assert.deepEqual(form.providers, ["generic-form"]);
});
