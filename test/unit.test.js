import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { parseArgv } from "../src/main.js";
import { normalizeOrigin } from "../src/config.js";
import { makePkce, LOGIN_SCOPES } from "../src/oauth.js";

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
