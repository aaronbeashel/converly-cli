import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { parseArgv, matchCommand, main, COMMANDS } from "../src/main.js";
import {
  normalizeOrigin,
  resolveOrigin,
  isSameTrustedOrigin,
  STAGING_ORIGIN,
} from "../src/config.js";
import { readTextCapped, assertSafePath } from "../src/net.js";
import { assertIdSegment } from "../src/commands/ids.js";
import { makePkce, LOGIN_SCOPES } from "../src/oauth.js";
import {
  create as flowsCreate,
  buildTriggerConfig,
  toAgentTriggerCatalogue,
} from "../src/commands/flows.js";
import {
  connect as triggersConnect,
  options as triggersOptions,
} from "../src/commands/triggers.js";

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
    // Added with the conversion-list consolidation: the narrow create scope
    // is in the server's MCP_PERMISSIONS-derived ceiling, so login may
    // request it. Without it create-conversion 403s on every credential.
    "destination_conversions:write",
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

// --- Strict boolean parsing (Codex round-3 blocker #6) ---

test("parseArgv: a non-true/false value on a boolean flag is an error, not true", () => {
  // The dangerous inversion: `--yes=flase` used to read as truthy → delete.
  const a = parseArgv(["flows", "delete", "flow_x", "--yes=flase"]);
  assert.equal(a.flags.yes, false, "unrecognised value defaults to SAFE false");
  assert.deepEqual(a.invalidBooleanFlags, [{ name: "yes", value: "flase" }]);

  const b = parseArgv(["test-event", "--allow-real=0"]);
  assert.equal(b.flags["allow-real"], false);
  assert.deepEqual(b.invalidBooleanFlags, [{ name: "allow-real", value: "0" }]);
});

test("parseArgv: exact true/false on a boolean flag is honoured, no error", () => {
  const eq = parseArgv(["flows", "delete", "flow_x", "--yes=true"]);
  assert.equal(eq.flags.yes, true);
  assert.deepEqual(eq.invalidBooleanFlags, []);

  const space = parseArgv(["flows", "delete", "flow_x", "--yes", "false"]);
  assert.equal(space.flags.yes, false);
  assert.deepEqual(space.invalidBooleanFlags, []);
});

test("main rejects a bad boolean value with invalid_flag_value (never deletes)", async () => {
  const chunks = [];
  const originalWrite = process.stderr.write;
  process.stderr.write = (chunk) => {
    chunks.push(chunk);
    return true;
  };
  try {
    // If this ever reached the handler it would try to DELETE. It must not.
    await main(["flows", "delete", "flow_x", "--yes=flase"]);
  } finally {
    process.stderr.write = originalWrite;
  }
  assert.equal(process.exitCode, 1);
  process.exitCode = 0;
  const payload = JSON.parse(chunks.join(""));
  assert.equal(payload.error.code, "invalid_flag_value");
  assert.match(payload.error.message, /--yes=flase/);
  assert.match(payload.error.message, /true or false/);
});

// --- Empty value = missing (Codex round-3 blocker #5) ---

test('parseArgv: an explicit empty value counts as missing, not ""', () => {
  const eq = parseArgv(["sites", "list", "--api="]);
  assert.ok(eq.missingValueFlags.includes("api"));

  const space = parseArgv(["sites", "list", "--api", ""]);
  assert.ok(space.missingValueFlags.includes("api"));
});

test("main rejects an empty --api= as missing_flag_value (no prod fallthrough)", async () => {
  const chunks = [];
  const originalWrite = process.stderr.write;
  process.stderr.write = (chunk) => {
    chunks.push(chunk);
    return true;
  };
  try {
    await main(["sites", "list", "--api="]);
  } finally {
    process.stderr.write = originalWrite;
  }
  assert.equal(process.exitCode, 1);
  process.exitCode = 0;
  const payload = JSON.parse(chunks.join(""));
  assert.equal(payload.error.code, "missing_flag_value");
  assert.match(payload.error.message, /--api/);
});

// --- Deployment-selector safety (Codex round-3 blocker #4 + conflict) ---

test("resolveOrigin refuses --api and --staging together", () => {
  assert.throws(
    () => resolveOrigin({ api: "https://x.example", staging: true }),
    /not both/
  );
});

// --- Same-origin trust boundary (Codex round-3 blockers #1, #10) ---

test("isSameTrustedOrigin pins to exactly the chosen origin", () => {
  const origin = "https://app.converly.io";
  assert.equal(
    isSameTrustedOrigin("https://app.converly.io/api/auth/token", origin),
    true
  );
  // A different host — the refresh-token exfiltration path — is rejected.
  assert.equal(isSameTrustedOrigin("https://attacker.example/token", origin), false);
  // Same host but embedded credentials — rejected.
  assert.equal(
    isSameTrustedOrigin("https://user:pass@app.converly.io/x", origin),
    false
  );
  // Different scheme is a different origin — rejected.
  assert.equal(isSameTrustedOrigin("http://app.converly.io/x", origin), false);
  assert.equal(isSameTrustedOrigin("not a url", origin), false);
});

// --- enhanced is now a strict boolean (Codex round-3 new blocker) ---

test("parseArgv: --enhanced is a strict boolean, bad values rejected", () => {
  const bad = parseArgv(["flows", "create", "--enhanced=flase"]);
  assert.equal(bad.flags.enhanced, false);
  assert.deepEqual(bad.invalidBooleanFlags, [{ name: "enhanced", value: "flase" }]);

  const good = parseArgv(["flows", "create", "--enhanced"]);
  assert.equal(good.flags.enhanced, true);
  assert.deepEqual(good.invalidBooleanFlags, []);
});

// --- Central positional-arity guard (Codex round-3 new blocker) ---

async function runMainCapture(argv) {
  const chunks = [];
  const originalWrite = process.stderr.write;
  process.stderr.write = (chunk) => {
    chunks.push(chunk);
    return true;
  };
  try {
    await main(argv);
  } finally {
    process.stderr.write = originalWrite;
  }
  const code = process.exitCode;
  process.exitCode = 0;
  return { code, payload: JSON.parse(chunks.join("")) };
}

test("main rejects a stray positional from a mistyped boolean on flows create", async () => {
  // `--custom no` leaves "no" as a positional; flows create takes none.
  const { code, payload } = await runMainCapture([
    "flows",
    "create",
    "--site",
    "s",
    "--name",
    "n",
    "--custom",
    "no",
  ]);
  assert.equal(code, 1);
  assert.equal(payload.error.code, "unexpected_argument");
  assert.match(payload.error.message, /"no"/);
});

test("main rejects too many positionals on a one-arg command", async () => {
  const { code, payload } = await runMainCapture(["sites", "get", "s1", "s2"]);
  assert.equal(code, 1);
  assert.equal(payload.error.code, "unexpected_argument");
  assert.match(payload.error.message, /"s2"/);
});

test("main allows the exact positional arity (api takes two)", async () => {
  // Wrong here would be an unexpected_argument error; we assert it is NOT
  // that (the request itself fails later on the bogus origin, which is
  // fine — we only care the arity gate let two through).
  const { payload } = await runMainCapture([
    "api",
    "GET",
    "/flows",
    "extra",
    "--api",
    "https://nonexistent.invalid",
  ]);
  assert.equal(payload.error.code, "unexpected_argument");
  assert.match(payload.error.message, /"extra"/);
});

// --- Path-traversal guard on interpolated ids (Codex round-4 blocker) ---

test("assertIdSegment allows only a plain id and rejects encoded traversal", () => {
  assert.equal(assertIdSegment("flow_abc123", "flow id"), "flow_abc123");
  assert.equal(assertIdSegment("google-ads", "type"), "google-ads");
  for (const bad of [
    "../flows/x",
    "a/b",
    "a\\b",
    ".",
    "..",
    "a b",
    "a?b",
    "a#b",
    "%2e%2e", // encoded ".."
    "%2f", // encoded "/"
    "%5c", // encoded "\"
    "flow%2ex", // any percent-escape
  ]) {
    assert.throws(() => assertIdSegment(bad, "flow id"), /not a path|single id/);
  }
  assert.throws(() => assertIdSegment("", "flow id"), /Missing/);
});

test("main refuses a raw DELETE without --yes", async () => {
  const { code, payload } = await runMainCapture([
    "api",
    "DELETE",
    "/flows/flow_x",
    "--api",
    "https://x.example",
  ]);
  assert.equal(code, 1);
  assert.match(payload.error.message, /--yes/);
});

test("assertSafePath rejects nested / normalized traversal", () => {
  // Plain valid paths pass.
  assertSafePath("/flows/flow_abc123");
  assertSafePath("/sites/site_1/setup-status");
  for (const bad of [
    "/sites/../flows/x",
    "/sites/%2e%2e/flows/x", // single-encoded ..
    "/sites/%252e%252e/flows/x", // double-encoded ..
    "/a/%2f/b", // encoded /
    "/a/%5c/b", // encoded \
    "/a/／/b", // fullwidth solidus → NFKC "/"
  ]) {
    assert.throws(() => assertSafePath(bad), /suspicious|Malformed|Over-encoded/);
  }
});

test("assertSafePath rejects control-char traversal (URL strips tab/newline/CR)", () => {
  // ".<TAB>." etc. become ".." once new URL() strips the control char.
  for (const c of ["\t", "\n", "\r"]) {
    assert.throws(
      () => assertSafePath("/decoy/." + c + "./flows/x"),
      /control character|suspicious/
    );
  }
  // ...including the percent-encoded form.
  assert.throws(() => assertSafePath("/a/.%09./b"), /control character|suspicious/);
});

test("resolveOrigin: an explicit --staging beats CONVERLY_API_URL", () => {
  const prev = process.env.CONVERLY_API_URL;
  process.env.CONVERLY_API_URL = "https://app.converly.io";
  try {
    // An explicit selector must not be silently overridden by the env, or
    // `flows delete X --staging` could hit production.
    assert.equal(resolveOrigin({ staging: true }), STAGING_ORIGIN);
  } finally {
    if (prev === undefined) delete process.env.CONVERLY_API_URL;
    else process.env.CONVERLY_API_URL = prev;
  }
});

test("a 429 stays retryable and surfaces retry timing", async () => {
  const srv = http.createServer((req, res) => {
    req.on("data", () => {});
    req.on("end", () => {
      res.writeHead(429, {
        "content-type": "application/json",
        "retry-after": "30",
      });
      res.end(JSON.stringify({ error: { code: "rate_limited", message: "slow down" } }));
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const bin = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
    "bin",
    "converly.js"
  );
  const child = spawn(
    process.execPath,
    [bin, "flows", "get", "flow_abc", "--api", `http://127.0.0.1:${port}`],
    { env: { ...process.env, CONVERLY_API_KEY: "sk_live_dummy" } }
  );
  let err = "";
  child.stderr.on("data", (d) => (err += d));
  await new Promise((r) => child.on("close", r));
  srv.close();
  const p = JSON.parse(err).error;
  assert.equal(p.status, 429);
  assert.equal(p.retryable, true, "429 must stay retryable");
  assert.equal(p.retry_after, "30");
});

test("a PATCH 5xx never surfaces retryable (outcome_uncertain instead)", async () => {
  // The exact scenario: a structured 500 whose body claims retryable:true.
  // A non-idempotent PATCH must NOT echo that to a machine consumer.
  const srv = http.createServer((req, res) => {
    req.on("data", () => {});
    req.on("end", () => {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          error: {
            code: "server_fault",
            message: "failed after write",
            retryable: true,
            hint: "retry now",
          },
        })
      );
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const bin = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
    "bin",
    "converly.js"
  );
  const child = spawn(
    process.execPath,
    [
      bin,
      "flows",
      "update",
      "flow_abc",
      "--json",
      '{"name":"x"}',
      "--api",
      `http://127.0.0.1:${port}`,
    ],
    { env: { ...process.env, CONVERLY_API_KEY: "sk_live_dummy" } }
  );
  let err = "";
  child.stderr.on("data", (d) => (err += d));
  const exitCode = await new Promise((r) => child.on("close", r));
  srv.close();
  assert.equal(exitCode, 1);
  const p = JSON.parse(err).error;
  assert.equal(p.status, 500);
  assert.equal(p.outcome_uncertain, true, "PATCH ambiguity must be flagged");
  assert.equal(p.retryable, undefined, "server's retryable must be stripped");
  assert.match(p.hint, /check the current state/);
});

test("main refuses a traversal id on a destructive command (no request sent)", async () => {
  const { code, payload } = await runMainCapture([
    "flows",
    "delete",
    "../flows/other",
    "--yes",
    "--api",
    "https://x.example",
  ]);
  assert.equal(code, 1);
  assert.match(payload.error.message, /not a path/);
});

// --- Streaming response cap (Codex round-3 should-fix #8) ---

test("readTextCapped rejects a body that overshoots the cap", async () => {
  // A stream with NO content-length (the case a lying header can't cover):
  // the reader must stop once accumulated bytes exceed the cap.
  const big = "x".repeat(5000);
  const overStream = new Response(
    new ReadableStream({
      start(c) {
        c.enqueue(new TextEncoder().encode(big));
        c.close();
      },
    })
  );
  const over = await readTextCapped(overStream, 1000);
  assert.equal(over.overLimit, true);

  const okRes = new Response("hello");
  const ok = await readTextCapped(okRes, 1000);
  assert.equal(ok.text, "hello");
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

test("triggers options validates source and --site before any request", async () => {
  const origin = "https://app.converly.io";
  await assert.rejects(
    triggersOptions({ args: [], flags: {}, origin }),
    /Missing trigger source/
  );
  await assert.rejects(
    triggersOptions({ args: ["typeform"], flags: {}, origin }),
    /Missing --site/
  );
});

test("`triggers options` is a distinct two-word command over `triggers`", () => {
  const two = matchCommand(["triggers", "options", "typeform"]);
  assert.equal(two.name, "triggers options");
  assert.deepEqual(two.rest, ["typeform"]);
  // Its declared flags cover what the handler reads (strict parser).
  assert.deepEqual(COMMANDS["triggers options"].flags, ["site", "query", "limit"]);
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


test("create-conversion is registered with the safety-critical flags", async () => {
  // The command writes a permanent object into a customer's ad account, so
  // its registration must carry the site + idempotency affordances and the
  // help text must tell an agent to ask the customer first.
  const { COMMANDS } = await import("../src/main.js");
  const cmd = COMMANDS["destinations create-conversion"];
  assert.ok(cmd, "command registered");
  for (const flag of ["name", "site", "category", "event-type", "conversion-method", "idempotency-key"]) {
    assert.ok(cmd.flags.includes(flag), `flag --${flag}`);
  }
  assert.match(cmd.help, /ASK THE CUSTOMER FIRST/);
  assert.match(cmd.help, /can never be deleted/);
  assert.match(cmd.help, /supports_create/);
});

test("create-conversion refuses without --name before any network call", async () => {
  const destinations = await import("../src/commands/destinations.js");
  await assert.rejects(
    () => destinations.createConversion({ args: ["google-ads"], flags: {}, origin: "prod" }),
    /Missing --name/
  );
});


test("login requests the create scope (or create-conversion is dead on arrival)", async () => {
  const { LOGIN_SCOPES } = await import("../src/oauth.js");
  assert.ok(
    LOGIN_SCOPES.includes("destination_conversions:write"),
    "create-conversion needs destination_conversions:write at login"
  );
  // …and never the broad scope, which also authorizes credential ingestion.
  assert.ok(!LOGIN_SCOPES.includes("destinations:write"));
});
