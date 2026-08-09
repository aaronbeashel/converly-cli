/**
 * Everything else: subscription, usage, internal-traffic rules, and the
 * raw API escape hatch.
 */

import { apiRequest } from "../http.js";

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
      "Usage: converly api <GET|POST|PATCH|DELETE> </v1-path> [--json '<body>']"
    );
  }
  let body;
  if (flags.json !== undefined) {
    try {
      body = JSON.parse(flags.json);
    } catch (cause) {
      throw new Error(`--json is not valid JSON: ${cause.message}`);
    }
  }
  return apiRequest(origin, method, path.startsWith("/") ? path : `/${path}`, {
    body,
  });
}
