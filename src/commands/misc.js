/**
 * Everything else: subscription, usage, internal-traffic rules, and the
 * raw API escape hatch.
 */

import { apiRequest } from "../http.js";
import { assertSafePath } from "../net.js";

export async function subscription({ origin }) {
  return apiRequest(origin, "GET", "/subscription");
}

export async function usage({ origin }) {
  return apiRequest(origin, "GET", "/usage");
}

export async function rulesList({ origin }) {
  return apiRequest(origin, "GET", "/internal-traffic-rules");
}

export async function rulesCreate({ flags, origin }) {
  // Exactly one selector — passing several is contradictory input, not a
  // "first one wins" situation.
  const selectors = ["ip", "cidr", "email-pattern"].filter(
    (k) => flags[k] !== undefined
  );
  if (selectors.length > 1) {
    throw new Error(
      `Pass only one of --ip, --cidr, --email-pattern (got ${selectors
        .map((k) => `--${k}`)
        .join(", ")}).`
    );
  }
  let ruleType;
  let ruleValue;
  if (flags.ip !== undefined) {
    ruleType = "ip";
    ruleValue = flags.ip;
  } else if (flags.cidr !== undefined) {
    ruleType = "ip_cidr";
    ruleValue = flags.cidr;
  } else if (flags["email-pattern"] !== undefined) {
    ruleType = "email_pattern";
    ruleValue = flags["email-pattern"];
  } else {
    throw new Error(
      "Pass one of --ip <address>, --cidr <range>, --email-pattern <pattern like *@yourcompany.com>."
    );
  }
  return apiRequest(origin, "POST", "/internal-traffic-rules", {
    body: {
      rule_type: ruleType,
      rule_value: ruleValue,
      ...(flags.description !== undefined && {
        description: flags.description,
      }),
    },
  });
}

/**
 * Raw escape hatch: `converly api GET /flows?limit=5` or
 * `converly api POST /flows --json '{...}'`. Covers any endpoint the
 * named commands don't.
 */
export async function api({ args, flags, origin }) {
  const method = String(args[0] ?? "").toUpperCase();
  const path = args[1];
  if (!["GET", "POST", "PATCH", "DELETE"].includes(method) || !path) {
    throw new Error(
      "Usage: converly api <GET|POST|PATCH|DELETE> <path relative to /api/v1, e.g. /flows?limit=5> [--json '<body>'] (DELETE also needs --yes)"
    );
  }
  // A raw DELETE is irreversible — mirror the confirmation the named
  // destructive commands (e.g. `flows delete`) enforce, so the escape hatch
  // can't quietly become an unguarded delete.
  if (method === "DELETE" && flags.yes !== true) {
    throw new Error(
      "Raw DELETE is destructive and irreversible — re-run with --yes to confirm."
    );
  }
  // GET/HEAD can't carry a body — reject --json here with a clear message
  // rather than letting fetch throw a local error that gets mislabelled as
  // a retryable transport failure.
  if ((method === "GET" || method === "HEAD") && flags.json !== undefined) {
    throw new Error(`${method} requests can't send a --json body.`);
  }
  let body;
  if (flags.json !== undefined) {
    try {
      body = JSON.parse(flags.json);
    } catch (cause) {
      throw new Error(`--json is not valid JSON: ${cause.message}`);
    }
  }
  const normalized = path.startsWith("/") ? path : `/${path}`;
  if (/^\/v1(\/|$)/.test(normalized)) {
    throw new Error(
      "Pass the path relative to /api/v1 — write /flows, not /v1/flows."
    );
  }
  // Keep the escape hatch inside /api/v1. A `..` segment or backslash could
  // climb out and hit another app route with your token attached — in
  // literal, percent-encoded, or double-encoded form. Same shared guard the
  // URL builder uses, so the two can't drift apart.
  const pathPart = normalized.split(/[?#]/, 1)[0];
  assertSafePath(pathPart);
  return apiRequest(origin, method, normalized, { body });
}
