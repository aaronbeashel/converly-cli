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

// --- Google Tag Manager commands -----------------------------------------

import {
  assertPublishAllowed,
  PUBLISH_ENV_FLAG,
  shapeTag,
  shapeTrigger,
  flattenConditions,
  extractDestinationIds,
} from "../src/commands/gtm.js";
import { unwrapList, unwrapObject, isQuotaError } from "../src/gtm-api.js";
import { GTM_SCOPES, resolveClientId } from "../src/gtm-auth.js";
import { EXIT } from "../src/gtm-errors.js";

/**
 * The publish gate is the one behaviour here that must never regress:
 * publishing pushes a container to a live production site. Both conditions
 * are required, and the ENV one exists precisely because a model can pass
 * any flag it likes but cannot set the environment of a session a human
 * already started.
 */
test("gtm publish gate: refuses unless BOTH the env flag and --confirm are set", () => {
  const table = [
    // [env, flags, shouldPass]
    [{}, {}, false],
    [{}, { confirm: true }, false],
    [{ [PUBLISH_ENV_FLAG]: "true" }, {}, false],
    [{ [PUBLISH_ENV_FLAG]: "true" }, { confirm: true }, true],
  ];
  for (const [env, flags, shouldPass] of table) {
    const label = JSON.stringify({ env, flags });
    if (shouldPass) {
      assert.equal(assertPublishAllowed(flags, env), true, label);
    } else {
      assert.throws(() => assertPublishAllowed(flags, env), /Refusing to publish/, label);
    }
  }
});

test("gtm publish gate: the env flag must be exactly true, not merely truthy", () => {
  // envTruthy() elsewhere accepts "1"/"yes"/any non-empty string. That is
  // deliberately NOT reused here: a gate on a production deploy should not
  // open because someone exported the variable with a stray value.
  for (const value of ["1", "yes", "TRUE ", "True", "false", "0", "", "no", "y"]) {
    const env = { [PUBLISH_ENV_FLAG]: value };
    const allowed = ["true", "TRUE ", "True"].includes(value);
    if (allowed) {
      assert.equal(assertPublishAllowed({ confirm: true }, env), true, value);
    } else {
      assert.throws(
        () => assertPublishAllowed({ confirm: true }, env),
        /Refusing to publish/,
        `${JSON.stringify(value)} must NOT open the gate`
      );
    }
  }
});

test("gtm publish gate: a refusal is exit 5 and names which condition failed", () => {
  try {
    assertPublishAllowed({}, {});
    assert.fail("expected the gate to refuse");
  } catch (err) {
    assert.equal(err.code, "publish_gate");
    assert.equal(err.exitCode, EXIT.PUBLISH_GATE);
    assert.equal(err.exitCode, 5);
    // Machine-branchable, so a caller never has to parse the prose.
    assert.equal(err.gate.env_flag_satisfied, false);
    assert.equal(err.gate.confirm_flag_satisfied, false);
    assert.equal(err.gate.missing.length, 2);
  }
  try {
    assertPublishAllowed({ confirm: true }, {});
    assert.fail("expected the gate to refuse");
  } catch (err) {
    assert.equal(err.gate.confirm_flag_satisfied, true);
    assert.deepEqual(err.gate.missing, [`${PUBLISH_ENV_FLAG}=true in the environment`]);
  }
});

test("gtm publish gate holds end to end, and refuses BEFORE creating a version", async () => {
  const bin = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
    "bin",
    "converly.js"
  );
  const run = (env) =>
    new Promise((resolve) => {
      const child = spawn(
        process.execPath,
        [bin, "gtm", "publish", "--account", "1", "--container", "2", "--workspace", "3"],
        { env: { ...process.env, ...env } }
      );
      let err = "";
      child.stderr.on("data", (d) => (err += d));
      child.on("close", (code) => resolve({ code, err }));
    });

  // No env flag, no --confirm.
  const bare = await run({ [PUBLISH_ENV_FLAG]: "" });
  assert.equal(bare.code, 5);
  assert.equal(JSON.parse(bare.err).error.code, "publish_gate");

  // Env flag set but no --confirm: still refused.
  const envOnly = await run({ [PUBLISH_ENV_FLAG]: "true" });
  assert.equal(envOnly.code, 5);
  assert.equal(JSON.parse(envOnly.err).error.code, "publish_gate");
});

test("gtm exit codes are distinct and stable per failure kind", async () => {
  const bin = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
    "bin",
    "converly.js"
  );
  const run = (args) =>
    new Promise((resolve) => {
      const child = spawn(process.execPath, [bin, ...args], {
        // A blank HOME keeps the developer's real ~/.converly out of the test.
        env: { ...process.env, HOME: path.join(process.cwd(), ".test-home-nonexistent") },
      });
      let err = "";
      child.stderr.on("data", (d) => (err += d));
      child.on("close", (code) => resolve({ code, err }));
    });

  // 2 = usage: --workspace missing.
  const usage = await run(["gtm", "tags", "--account", "1", "--container", "2"]);
  assert.equal(usage.code, EXIT.USAGE);
  assert.equal(JSON.parse(usage.err).error.code, "missing_flag");

  // 3 = not authenticated: no Google login stored.
  const auth = await run(["gtm", "accounts"]);
  assert.equal(auth.code, EXIT.AUTH);
  assert.equal(JSON.parse(auth.err).error.code, "google_auth_required");

  // 5 = publish gate, never reused by anything else.
  const gate = await run(["gtm", "publish", "--account", "1", "--container", "2", "--version-id", "9"]);
  assert.equal(gate.code, EXIT.PUBLISH_GATE);

  // Pre-existing commands keep the untouched 0/1 contract.
  const legacy = await run(["flows", "get"]);
  assert.equal(legacy.code, 1);
});

test("gtm scopes are exactly the four needed, and never the delete scope", () => {
  assert.equal(GTM_SCOPES.length, 4);
  assert.deepEqual(
    [...GTM_SCOPES].sort(),
    [
      "https://www.googleapis.com/auth/tagmanager.edit.containerversions",
      "https://www.googleapis.com/auth/tagmanager.edit.containers",
      "https://www.googleapis.com/auth/tagmanager.manage.accounts",
      "https://www.googleapis.com/auth/tagmanager.publish",
    ].sort()
  );
  // Deliberately removed elsewhere in this project: it puts "delete your
  // containers" on the consent screen and nothing here deletes anything.
  assert.ok(
    !GTM_SCOPES.some((s) => s.includes("delete")),
    "no delete scope may ever be requested"
  );
});

test("gtm login fails with actionable guidance when no OAuth client is configured", () => {
  assert.throws(
    () => resolveClientId({}),
    (err) => {
      assert.equal(err.code, "no_oauth_client");
      assert.equal(err.exitCode, EXIT.USAGE);
      assert.match(err.message, /Desktop app/);
      return true;
    }
  );
  assert.equal(resolveClientId({ CONVERLY_GTM_CLIENT_ID: "abc.apps.googleusercontent.com" }), "abc.apps.googleusercontent.com");
});

test("shapeTag surfaces every silent failure mode EXPLICITLY, including when falsy", () => {
  // A tag that is fine in every visible respect but paused and blocked.
  const shaped = shapeTag({
    tagId: "12",
    name: "GA4 purchase",
    type: "gaawe",
    paused: true,
    firingTriggerId: ["7"],
    blockingTriggerId: ["9"],
    tagFiringOption: "oncePerLoad",
    consentSettings: {
      consentStatus: "needed",
      consentType: { type: "list", list: [{ value: "ad_storage" }, { value: "analytics_storage" }] },
    },
    parameter: [{ type: "template", key: "measurementId", value: "G-ABC123" }],
    path: "accounts/1/containers/2/workspaces/3/tags/12",
  });
  assert.equal(shaped.paused, true);
  assert.deepEqual(shaped.blockingTriggerId, ["9"]);
  assert.equal(shaped.tagFiringOption, "oncePerLoad");
  assert.deepEqual(shaped.consentSettings.consentTypes, ["ad_storage", "analytics_storage"]);
  assert.deepEqual(shaped.destination_ids, [
    { key: "measurementId", path: "measurementId", value: "G-ABC123", is_variable_reference: false },
  ]);
  // The raw parameter tree is returned verbatim alongside the extraction.
  assert.deepEqual(shaped.parameter, [
    { type: "template", key: "measurementId", value: "G-ABC123" },
  ]);

  // The critical case: an unpaused, unblocked tag must say so with real
  // `false` / `[]` values, not by omitting the keys. "The key wasn't there"
  // is exactly how a paused tag gets missed by a consumer.
  const plain = shapeTag({ tagId: "1", name: "x", type: "html" });
  assert.equal(plain.paused, false);
  assert.equal("paused" in plain, true);
  assert.deepEqual(plain.blockingTriggerId, []);
  assert.deepEqual(plain.firingTriggerId, []);
  assert.equal(plain.tagFiringOption, null);
  assert.equal(plain.consentSettings, null);
});

test("extractDestinationIds finds ids by key and by value shape, and flags variables", () => {
  const found = extractDestinationIds([
    { type: "template", key: "measurementId", value: "{{GA4 Measurement ID}}" },
    { type: "template", key: "somethingCustom", value: "AW-99887766" },
    { type: "template", key: "notAnId", value: "hello world" },
    {
      type: "list",
      key: "eventSettingsTable",
      list: [{ type: "map", map: [{ type: "template", key: "pixelId", value: "123456789" }] }],
    },
  ]);
  const byKey = Object.fromEntries(found.map((f) => [f.key, f]));
  // A variable reference is an id you CANNOT resolve from here, so it is
  // flagged rather than reported as if it were a real destination.
  assert.equal(byKey.measurementId.is_variable_reference, true);
  // Found by value pattern even though the key is not a known one.
  assert.equal(byKey.somethingCustom.value, "AW-99887766");
  // Found nested inside a list/map.
  assert.equal(byKey.pixelId.value, "123456789");
  assert.equal(byKey.pixelId.path, "eventSettingsTable.pixelId");
  // Ordinary copy is not mistaken for a destination id.
  assert.equal("notAnId" in byKey, false);
});

test("shapeTrigger returns conditions literally, without interpreting them", () => {
  const shaped = shapeTrigger({
    triggerId: "7",
    name: "purchase",
    type: "customEvent",
    customEventFilter: [
      {
        type: "equals",
        parameter: [
          { type: "template", key: "arg0", value: "{{_event}}" },
          { type: "template", key: "arg1", value: "purchase" },
        ],
      },
    ],
  });
  assert.deepEqual(shaped.conditions, [
    {
      source: "customEventFilter",
      type: "equals",
      negate: false,
      arg0: "{{_event}}",
      arg1: "purchase",
    },
  ]);
  // The raw array survives untouched next to the flattened form.
  assert.equal(shaped.customEventFilter.length, 1);
});

test("flattenConditions keeps negate and handles every filter source", () => {
  assert.deepEqual(
    flattenConditions(
      [{ type: "contains", negate: true, parameter: [{ key: "arg0", value: "{{Page URL}}" }] }],
      "filter"
    ),
    [{ source: "filter", type: "contains", negate: true, arg0: "{{Page URL}}" }]
  );
  assert.deepEqual(flattenConditions(undefined, "filter"), []);
});

test("unwrapList tells an EMPTY collection apart from a partial response", () => {
  // Raw REST shape.
  assert.deepEqual(unwrapList({ tag: [{ tagId: "1" }] }, "tag"), [{ tagId: "1" }]);
  // The `data` envelope Google's own clients add.
  assert.deepEqual(unwrapList({ data: { tag: [{ tagId: "2" }] } }, "tag"), [{ tagId: "2" }]);
  // A genuinely empty workspace: absent key means empty, which is normal.
  assert.deepEqual(unwrapList({}, "tag"), []);
  assert.deepEqual(unwrapList({ tag: null }, "tag"), []);
  // The dangerous case. Under quota pressure this API returns malformed
  // partials; reporting "no tags" for a container that HAS tags would send
  // someone rebuilding work that already exists. It must throw instead.
  assert.throws(() => unwrapList({ tag: "oops" }, "tag"), /Refusing to report this as empty/);
  assert.throws(() => unwrapList({ tag: { 0: "x" } }, "tag"), /Refusing to report this as empty/);
});

test("unwrapObject accepts either wrapper and the bare resource", () => {
  const version = { containerVersionId: "5", name: "v5" };
  // The live-version call wraps differently from the list calls.
  assert.deepEqual(unwrapObject({ containerVersion: version }, ["containerVersion"], "containerVersionId"), version);
  assert.deepEqual(unwrapObject({ data: { containerVersion: version } }, ["containerVersion"], "containerVersionId"), version);
  // Already unwrapped, identified by its marker field.
  assert.deepEqual(unwrapObject(version, ["containerVersion"], "containerVersionId"), version);
  // Something that is neither must not be mistaken for the resource.
  assert.equal(unwrapObject({ unrelated: true }, ["containerVersion"], "containerVersionId"), null);
});

test("quota exhaustion is a 403, and a plain 403 is NOT retried as quota", () => {
  // Google signals a spent quota with 403 + a rate-limit reason, not 429.
  assert.equal(
    isQuotaError(403, { error: { errors: [{ reason: "rateLimitExceeded" }] } }),
    true
  );
  assert.equal(
    isQuotaError(403, { error: { errors: [{ reason: "userRateLimitExceeded" }] } }),
    true
  );
  assert.equal(isQuotaError(403, { error: { message: "Quota exceeded for quota metric" } }), true);
  assert.equal(isQuotaError(429, {}), true);
  // A genuine permission failure must fail FAST, not be retried for a
  // minute as though it were transient.
  assert.equal(
    isQuotaError(403, { error: { errors: [{ reason: "forbidden" }], message: "Permission denied" } }),
    false
  );
  assert.equal(isQuotaError(404, {}), false);
  assert.equal(isQuotaError(403, null), false);
});

test("every gtm command is registered with the flags its handler reads", () => {
  const expected = {
    "gtm login": ["browser"],
    "gtm logout": [],
    "gtm status": [],
    "gtm accounts": [],
    "gtm containers": ["account"],
    "gtm workspaces": ["account", "container"],
    "gtm tags": ["account", "container", "workspace"],
    "gtm triggers": ["account", "container", "workspace"],
    "gtm variables": ["account", "container", "workspace"],
    "gtm builtins": ["account", "container", "workspace"],
    "gtm changes": ["account", "container", "workspace"],
    "gtm versions": ["account", "container"],
  };
  for (const [name, flags] of Object.entries(expected)) {
    assert.ok(COMMANDS[name], `${name} must be registered`);
    assert.deepEqual(COMMANDS[name].flags, flags, name);
    assert.equal(typeof COMMANDS[name].run, "function", name);
  }
  // publish must accept --confirm, or the gate could never be satisfied.
  assert.ok(COMMANDS["gtm publish"].flags.includes("confirm"));
  // The write commands take --json for the full resource body.
  for (const name of ["gtm create-tag", "gtm create-trigger", "gtm create-variable"]) {
    assert.ok(COMMANDS[name].flags.includes("json"), name);
  }
  // `gtm publish` help must state the gate, since that help is the only
  // place an agent learns why it was refused.
  assert.match(COMMANDS["gtm publish"].help, /CONVERLY_GTM_ALLOW_PUBLISH/);
  assert.match(COMMANDS["gtm publish"].help, /--confirm/);
});

test("--confirm is a strict boolean flag, so --confirm=0 cannot open the gate", () => {
  // Registered in BOOLEAN_FLAGS: a bare --confirm is true, an explicit
  // false disables it, and a junk value is rejected rather than coerced.
  assert.equal(parseArgv(["gtm", "publish", "--confirm"]).flags.confirm, true);
  assert.equal(parseArgv(["gtm", "publish", "--confirm=false"]).flags.confirm, false);
  const junk = parseArgv(["gtm", "publish", "--confirm=0"]);
  assert.equal(junk.flags.confirm, false, "a junk value must default to the SAFE false");
  assert.equal(junk.invalidBooleanFlags[0].name, "confirm");
  // And the gate itself only opens on a real boolean true.
  assert.throws(
    () => assertPublishAllowed({ confirm: "true" }, { [PUBLISH_ENV_FLAG]: "true" }),
    /Refusing to publish/
  );
});

test("no command declares a flag the entry point intercepts before the handler", () => {
  // `--version` and `--help` are handled in main() and RETURN before any
  // handler runs, so a command that declared `--version` as its own flag
  // would silently print the CLI version and exit 0 instead of doing its
  // job. `gtm publish --version <id>` hit exactly that and is why the
  // publish flag is spelled --version-id.
  const intercepted = ["version", "help"];
  for (const [name, def] of Object.entries(COMMANDS)) {
    for (const flag of def.flags) {
      assert.ok(
        !intercepted.includes(flag),
        `\`converly ${name}\` declares --${flag}, which main() intercepts before the handler runs`
      );
    }
  }
});

test("gtm publish --version-id reaches the gate instead of printing the CLI version", () => {
  const { flags, args } = parseArgv([
    "gtm", "publish", "--account", "1", "--container", "2", "--version-id", "9",
  ]);
  assert.equal(flags["version-id"], "9");
  assert.equal(flags.version, undefined, "must not trip the global --version flag");
  assert.deepEqual(args, ["gtm", "publish"]);
});

/**
 * The transport behaviours that matter most on this API cannot be checked by
 * inspecting pure functions: they only appear across a SEQUENCE of responses.
 * These run the real gtmRequest in a child process with a stubbed fetch and a
 * throwaway HOME holding a fake credential, so no network and no real
 * ~/.converly are involved.
 */
async function runWithStubbedFetch(responses, call) {
  const os = await import("node:os");
  const fs = await import("node:fs");
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "converly-gtm-test-"));
  fs.mkdirSync(path.join(home, ".converly"), { recursive: true });
  fs.writeFileSync(
    path.join(home, ".converly", "config.json"),
    JSON.stringify({
      google: {
        access_token: "ya29.fake",
        refresh_token: "1//fake",
        // Far future so no refresh is attempted.
        expires_at: Date.now() + 3600_000,
        client_id: "test.apps.googleusercontent.com",
        scope: "",
      },
    })
  );
  const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const script = `
    const queue = ${JSON.stringify(responses)};
    let calls = 0;
    globalThis.fetch = async () => {
      const r = queue[Math.min(calls++, queue.length - 1)];
      return new Response(r.body, {
        status: r.status,
        headers: { "content-type": "application/json" },
      });
    };
    const { gtmRequest, unwrapList } = await import(${JSON.stringify(
      path.join(root, "src", "gtm-api.js")
    )});
    try {
      const out = await (${call});
      console.log(JSON.stringify({ ok: true, out, calls }));
    } catch (err) {
      console.log(JSON.stringify({ ok: false, code: err.code, message: err.message, calls }));
    }
  `;
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
      env: {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        // Keep the retry ladder fast enough for a test.
        CONVERLY_GTM_BACKOFF_MS: "5",
      },
    });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.on("close", () => {
      fs.rmSync(home, { recursive: true, force: true });
      resolve(JSON.parse(out.trim().split("\n").pop()));
    });
  });
}

test("a truncated 200 is retried rather than trusted (the documented quota symptom)", async () => {
  const result = await runWithStubbedFetch(
    [
      // Exactly what quota pressure looks like here: HTTP 200 carrying a
      // half-written body instead of a clean error.
      { status: 200, body: '{"tag":[{"tagId":"1"' },
      { status: 200, body: '{"tag":[{"tagId":"1","name":"ok"}]}' },
    ],
    'gtmRequest("GET", "/accounts/1/containers/2/workspaces/3/tags")'
  );
  assert.equal(result.ok, true, result.message);
  assert.equal(result.calls, 2, "the malformed response must be retried");
  assert.deepEqual(result.out.tag, [{ tagId: "1", name: "ok" }]);
});

test("a 403 carrying a rate-limit reason is retried; a plain 403 fails immediately", async () => {
  const quota = await runWithStubbedFetch(
    [
      { status: 403, body: '{"error":{"errors":[{"reason":"rateLimitExceeded"}],"message":"Rate Limit Exceeded"}}' },
      { status: 200, body: '{"account":[]}' },
    ],
    'gtmRequest("GET", "/accounts")'
  );
  assert.equal(quota.ok, true, quota.message);
  assert.equal(quota.calls, 2, "a quota 403 must be retried, not surfaced");

  const denied = await runWithStubbedFetch(
    [{ status: 403, body: '{"error":{"errors":[{"reason":"forbidden"}],"message":"Permission denied"}}' }],
    'gtmRequest("GET", "/accounts")'
  );
  assert.equal(denied.ok, false);
  assert.equal(denied.code, "permission_denied");
  assert.equal(denied.calls, 1, "a genuine permission failure must NOT be retried");
});

test("exhausted quota reports quota_exhausted, not a generic failure", async () => {
  const result = await runWithStubbedFetch(
    [{ status: 403, body: '{"error":{"errors":[{"reason":"rateLimitExceeded"}],"message":"Rate Limit Exceeded"}}' }],
    'gtmRequest("GET", "/accounts")'
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, "quota_exhausted");
  assert.match(result.message, /25 requests per 100 seconds/);
  assert.ok(result.calls > 1, "it should have retried before giving up");
});

test("a 200 that is an array rather than an object is refused as a partial response", async () => {
  const result = await runWithStubbedFetch(
    [{ status: 200, body: "[]" }],
    'gtmRequest("GET", "/accounts")'
  );
  assert.equal(result.ok, false);
  assert.match(result.message, /partial response/);
});

test("a write is NOT retried on a transport failure, and says the outcome is uncertain", async () => {
  // A POST that may or may not have landed must never be silently repeated.
  const result = await runWithStubbedFetch(
    [{ status: 500, body: '{"error":{"message":"boom"}}' }],
    'gtmRequest("POST", "/accounts/1/containers/2/workspaces/3/tags", { body: { name: "x" } })'
  );
  assert.equal(result.ok, false);
  assert.equal(result.calls, 1, "a failed write must not be retried automatically");
});

test("404 explains that workspace IDs are not guessable", async () => {
  const result = await runWithStubbedFetch(
    [{ status: 404, body: '{"error":{"message":"Not found"}}' }],
    'gtmRequest("GET", "/accounts/1/containers/2/workspaces/1/tags")'
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, "not_found");
  assert.match(result.message, /NOT predictable/i);
});

test("a 401 that survives the refresh is an auth failure, not a generic API error", async () => {
  const result = await runWithStubbedFetch(
    [{ status: 401, body: '{"error":{"message":"Invalid Credentials"}}' }],
    'gtmRequest("GET", "/accounts")'
  );
  assert.equal(result.ok, false);
  // Exit 3, so a caller is told to log in rather than retrying forever.
  assert.equal(result.code, "google_auth_required");
  assert.match(result.message, /converly gtm login/);
});
