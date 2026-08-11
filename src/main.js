/**
 * Converly CLI entry point.
 *
 * Contract with callers (humans and AI agents):
 * - stdout is ALWAYS a single JSON document (the result).
 * - Human-facing progress goes to stderr.
 * - Exit 0 on success, 1 on any failure, with a JSON error on stderr.
 */

import { createRequire } from "node:module";
import { resolveOrigin } from "./config.js";
import { ApiError, AuthMissingError, setDefaultIdempotencyKey } from "./http.js";
import * as auth from "./commands/auth.js";
import * as sites from "./commands/sites.js";
import * as destinations from "./commands/destinations.js";
import * as flows from "./commands/flows.js";
import * as triggers from "./commands/triggers.js";
import * as events from "./commands/events.js";
import * as misc from "./commands/misc.js";

const require = createRequire(import.meta.url);
const { version: VERSION } = require("../package.json");

/** Flags that never take a value. */
const BOOLEAN_FLAGS = new Set([
  "staging",
  "signup",
  "refresh",
  "custom",
  "help",
  "version",
  "no-open",
  "yes",
  "allow-real",
  "device",
  "browser",
]);

export function parseArgv(argv) {
  const args = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token.startsWith("--")) {
      const eq = token.indexOf("=");
      if (eq !== -1) {
        const name = token.slice(2, eq);
        const value = token.slice(eq + 1);
        // `--signup=false` must mean false, not truthy-string true.
        flags[name] = BOOLEAN_FLAGS.has(name) ? value !== "false" : value;
      } else {
        const name = token.slice(2);
        const next = argv[i + 1];
        if (BOOLEAN_FLAGS.has(name) || next === undefined || next.startsWith("--")) {
          flags[name] = true;
        } else {
          flags[name] = next;
          i++;
        }
      }
    } else {
      args.push(token);
    }
  }
  return { args, flags };
}

/**
 * Flags every command accepts: deployment targeting (--staging, --api),
 * help/version, and plumbing the entry point reads before the handler.
 */
const GLOBAL_FLAGS = new Set([
  "staging",
  "api",
  "help",
  "version",
  "idempotency-key",
  "no-open",
  "yes",
]);

/**
 * Registry: "group verb" (or a single word) → handler + usage line +
 * the flags the handler reads (anything else is rejected — see the
 * strict check in main()). Usage lines double as the agent-facing
 * documentation, so they carry the flags and an example where the
 * shape isn't obvious.
 */
export const COMMANDS = {
  "login": {
    run: auth.login,
    usage: "converly login [--signup] [--device] [--browser] [--staging] [--no-open]",
    flags: ["signup", "no-open", "device", "browser", "label"],
    help: "Log in. Default: opens a browser ON THIS MACHINE (the redirect hands the credential back here, so a phone or another computer can't complete it). --device instead shows a short code and a URL you approve from ANY device, which is the way to log in on a server, in CI, or from a headless agent. --signup sends new users to account creation (free trial starts automatically). --no-open prints the browser URL instead of launching it. --label names the device-login key shown in Settings. On CI/SSH/headless machines the default automatically uses device login; --browser forces the local browser flow instead. Credentials are stored in ~/.converly/config.json.",
  },
  "logout": {
    run: auth.logout,
    usage: "converly logout [--staging]",
    flags: [],
    help: "Forget the stored login for this deployment.",
  },
  "whoami": {
    run: auth.whoami,
    usage: "converly whoami",
    flags: [],
    help: "Show the current account: subscription state and sites.",
  },
  "status": {
    run: sites.status,
    usage: "converly status [--site <site_id>]",
    flags: ["site"],
    help: "The ordered setup checklist for a site: what's done, what needs action (with the exact command), what to ask the user, and what only a human can verify. Run this FIRST. Defaults to the account's only site.",
  },
  "sites list": {
    run: sites.list,
    usage: "converly sites list [--limit N]",
    flags: ["limit", "starting-after"],
    help: "List the account's sites.",
  },
  "sites get": {
    run: sites.get,
    usage: "converly sites get <site_id>",
    flags: [],
    help: "Fetch one site.",
  },
  "sites create": {
    run: sites.create,
    usage: "converly sites create [--name X] [--domain example.com] [--timezone Z]",
    flags: ["name", "domain", "timezone"],
    help: "Create a site. Most accounts already have a default site — prefer `sites update` on it.",
  },
  "sites update": {
    run: sites.update,
    usage: "converly sites update <site_id> [--name X] [--domain example.com] [--timezone Z]",
    flags: ["name", "domain", "timezone"],
    help: "Update a site. Setting --domain is REQUIRED before tracking works (events from unknown domains are rejected).",
  },
  "install snippet": {
    run: sites.snippet,
    usage: "converly install snippet <site_id>",
    flags: [],
    help: "Get the <script> tag to add to the website's <head>.",
  },
  "install status": {
    run: sites.installStatus,
    usage: "converly install status <site_id>",
    flags: [],
    help: 'Check whether tracking is live. detection "confirmed" = proven; "never_seen" = no conversions captured yet (NOT proof the snippet is missing).',
  },
  "destinations types": {
    run: destinations.types,
    usage: "converly destinations types",
    flags: [],
    help: "Catalogue of ad platforms Converly can send conversions to.",
  },
  "destinations list": {
    run: destinations.list,
    usage: "converly destinations list",
    flags: [],
    help: "The account's destinations and whether each is connected.",
  },
  "destinations get": {
    run: destinations.get,
    usage: "converly destinations get <type>   (e.g. google-ads)",
    flags: [],
    help: "One destination's connection state.",
  },
  "destinations connect": {
    run: destinations.connect,
    usage: "converly destinations connect <type> --site <site_id>",
    flags: ["site", "return-url"],
    help: "Create a connect link for an ad platform. A HUMAN must open the returned url in a browser to authorize; then `converly handoffs wait <id>`.",
  },
  "destinations conversions": {
    run: destinations.conversions,
    usage: "converly destinations conversions <type> [--refresh]",
    flags: ["refresh"],
    help: "List the conversion actions / pixel events available in a connected destination (the picker for flow configs).",
  },
  "handoffs get": {
    run: destinations.handoffGet,
    usage: "converly handoffs get <handoff_id>",
    flags: [],
    help: "Check a connect link's status once.",
  },
  "handoffs wait": {
    run: destinations.handoffWait,
    usage: "converly handoffs wait <handoff_id> [--timeout seconds]",
    flags: ["timeout"],
    help: "Poll a connect link until it completes (default timeout 600s). Exits non-zero if it expires or is cancelled.",
  },
  "triggers": {
    run: flows.triggerTypes,
    usage: "converly triggers [--platform webflow|wordpress|wix|framer]",
    flags: ["platform"],
    help: "Catalogue of trigger types and form-tool provider slugs. Use a slug from providers[] as the flow's trigger integrationId.",
  },
  "triggers connect": {
    run: triggers.connect,
    usage: "converly triggers connect <source> --site <site_id>   (e.g. api)",
    flags: ["site"],
    help: "Create a connect link for a trigger source that needs setup outside the CLI. For most sources a HUMAN opens the returned url and signs in to the platform there. For the api source the page shows the site's webhook URL + secret, which the human hands to whoever maintains the backend. Then `converly handoffs wait <id>`.",
  },
  "triggers options": {
    run: triggers.options,
    usage: "converly triggers options <source> --site <site_id> [--query <text>] [--limit N]   (e.g. typeform)",
    flags: ["site", "query", "limit"],
    help: "List a CONNECTED platform's filter options — the account's REAL forms / event types (with ids + names) — so you can offer the user a specific one instead of inventing values. Only requires_connection providers (Typeform, Calendly, Acuity, Jotform); connect first with `triggers connect`. Then narrow the flow by writing trigger_config.conditions, e.g. `converly flows update <flow_id> --json '{\"trigger_config\":{\"conditions\":{\"form\":{\"ids\":[\"...\"],\"names\":[\"...\"]}}}}'`. --query filters value names (case-insensitive); --limit caps values per field (default 50). Browser-detected form tools narrow by page instead (`flows create --pages`).",
  },
  "actions": {
    run: flows.actionTypes,
    usage: "converly actions <destination_type>   (e.g. google-ads)",
    flags: [],
    help: "The action config schema + example for one destination. Read this before building a flow's actions_config.",
  },
  "flows list": {
    run: flows.list,
    usage: "converly flows list [--site <site_id>] [--limit N]",
    flags: ["site", "limit", "starting-after"],
    help: "List flows.",
  },
  "flows get": {
    run: flows.get,
    usage: "converly flows get <flow_id>",
    flags: [],
    help: "Fetch one flow.",
  },
  "flows create": {
    run: flows.create,
    usage: "converly flows create --site <id> --name <name> --trigger <slug> --destination <slug> [--conversion-id <id> | --event-name <name>] [--value N --currency USD] [--pages /a,/b] | --json '<body>'   (api trigger: --trigger api --key <webhook-key>, no --pages)",
    flags: ["json", "site", "name", "description", "trigger", "key", "pages", "destination", "conversion-id", "event-name", "custom", "value", "currency", "enhanced"],
    help: "Create a draft flow. Simple form covers one trigger + one destination; --json takes the full flow body for anything richer. --pages is OPTIONAL: omit it and the form trigger fires on every page (the common case); pass it to restrict to specific paths, e.g. --pages /contact,/demo. No filter is required. The api (webhook) trigger takes --key, the webhook identifier, instead of --pages.",
  },
  "flows update": {
    run: flows.update,
    usage: "converly flows update <flow_id> --json '{\"name\":\"...\"}'",
    flags: ["json"],
    help: "Update flow fields. Never pass status here — use publish/unpublish.",
  },
  "flows delete": {
    run: flows.remove,
    usage: "converly flows delete <flow_id> --yes",
    flags: ["yes"],
    help: "Delete a flow permanently. Requires --yes. Unpublish first if it's published.",
  },
  "flows validate": {
    run: flows.validate,
    usage: "converly flows validate <flow_id>",
    flags: [],
    help: "Non-mutating publish-readiness check. Returns problems[] (blockers) and warnings[] (site not ready — e.g. domain missing).",
  },
  "flows publish": {
    run: flows.publish,
    usage: "converly flows publish <flow_id>",
    flags: [],
    help: "Publish a flow live. Also returns warnings[] about site readiness.",
  },
  "flows unpublish": {
    run: flows.unpublish,
    usage: "converly flows unpublish <flow_id>",
    flags: [],
    help: "Take a flow offline.",
  },
  "test-event": {
    run: flows.testEvent,
    usage: "converly test-event --flow <flow_id> [--action-id act-1] [--meta-code TEST123] [--reddit-id t2_xxx] [--tiktok-code TEST123] [--allow-real]",
    flags: ["flow", "action-id", "action-json", "meta-code", "reddit-id", "tiktok-code", "allow-real"],
    help: "Fire a test conversion through a flow's action to the real ad platform. Defaults to the flow's first action. Sandbox codes come from each platform's test tools. Pass --meta-code (Meta Events Manager test events), --reddit-id (Reddit) or --tiktok-code (TikTok) to keep the test out of real data. Destinations with no sandbox mode (Google Ads, GA4, LinkedIn, ChatGPT Ads) require --allow-real, which reports a REAL conversion, so the user must explicitly agree first.",
  },
  "events list": {
    run: events.list,
    usage: "converly events list [--site <id>] [--flow <id>] [--email x@y.com] [--status completed|failed] [--since ISO] [--until ISO] [--limit N]",
    flags: ["site", "flow", "email", "status", "since", "until", "limit"],
    help: "Recent conversion events (bounded snapshot, max 100 — narrow with filters, there is no paging).",
  },
  "events get": {
    run: events.get,
    usage: "converly events get <event_id>",
    flags: [],
    help: "One event with per-destination delivery status and any pipeline notices.",
  },
  "rules list": {
    run: misc.rulesList,
    usage: "converly rules list",
    flags: [],
    help: "List internal-traffic rules (submissions matching them are ignored).",
  },
  "rules create": {
    run: misc.rulesCreate,
    usage: "converly rules create --ip 1.2.3.4 | --cidr 10.0.0.0/24 | --email-pattern '*@yourcompany.com' [--description X]",
    flags: ["ip", "cidr", "email-pattern", "description"],
    help: "Exclude the team's own traffic so testing doesn't pollute conversions.",
  },
  "subscription": {
    run: misc.subscription,
    usage: "converly subscription",
    flags: [],
    help: "Plan, trial and billing state.",
  },
  "usage": {
    run: misc.usage,
    usage: "converly usage",
    flags: [],
    help: "Current usage against plan limits.",
  },
  "api": {
    run: misc.api,
    usage: "converly api <GET|POST|PATCH|DELETE> <path relative to /api/v1> [--json '<body>']",
    flags: ["json"],
    help: "Raw API request for anything not covered by a named command. Write /flows, not /v1/flows.",
  },
};

function overviewHelp() {
  const lines = [
    `Converly CLI v${VERSION} — conversion tracking for ad platforms.`,
    "",
    "Every data command prints one JSON document to stdout (help and",
    "version print text). Global flags: --staging (staging deployment),",
    "--api <origin> (custom deployment), --idempotency-key <key> (pin the",
    "key for a POST so an explicit retry can't double-create).",
    "Auth: `converly login`, or set CONVERLY_API_KEY for headless use.",
    "",
    "Before building, get three facts from the user (or the repo): the",
    "website's address, which tool renders the form, and what should count",
    "as the conversion (the submission itself, or something after it).",
    "`converly status` tells you what's missing and what to run next.",
    "",
    "Typical setup sequence (one command per line):",
    "  converly login --signup",
    "  converly status                                  # the ordered checklist — run this first",
    "  converly sites update <site> --domain example.com",
    "  converly install snippet <site>                  # add tag to the website",
    "  converly destinations connect google-ads --site <site>",
    "  converly handoffs wait <handoff_id>              # human authorizes in browser",
    "  converly triggers                                # find the form tool slug + its setup block",
    "  converly triggers connect typeform --site <site> # ONLY for requires_connection providers, then handoffs wait",
    "  converly destinations conversions google-ads     # pick a conversion",
    "  converly flows create --site <site> --name \"Leads\" --trigger generic-form --destination google-ads --conversion-id <id>",
    "  converly flows validate <flow>                   # act on warnings — they name what won't capture",
    "  converly flows publish <flow>",
    "  converly test-event --flow <flow>                # verify destination delivery",
    "  converly events list --limit 10                  # watch real conversions",
    "",
    "Commands:",
  ];
  for (const [name, def] of Object.entries(COMMANDS)) {
    const summary = def.help.split(". ")[0].replace(/\.$/, "");
    lines.push(`  ${name.padEnd(26)} ${summary}.`);
  }
  lines.push("", "Run `converly help <command>` for usage, e.g. `converly help flows create`.");
  return lines.join("\n");
}

function commandHelp(name, def) {
  return [`Usage: ${def.usage}`, "", def.help].join("\n");
}

/** Longest-prefix match of argv words against the registry. */
export function matchCommand(args) {
  for (const wordCount of [2, 1]) {
    if (args.length >= wordCount) {
      const name = args.slice(0, wordCount).join(" ");
      if (COMMANDS[name]) {
        return { def: COMMANDS[name], rest: args.slice(wordCount), name };
      }
    }
  }
  return null;
}

export async function main(argv) {
  const { args, flags } = parseArgv(argv);

  if (flags.version || args[0] === "version") {
    process.stdout.write(`${VERSION}\n`);
    return;
  }

  if (flags.help || args.length === 0 || args[0] === "help") {
    const helpTarget = args[0] === "help" ? args.slice(1) : args;
    const match = matchCommand(helpTarget);
    process.stdout.write(
      (match ? commandHelp(match.name, match.def) : overviewHelp()) + "\n"
    );
    return;
  }

  const match = matchCommand(args);
  if (!match) {
    process.stderr.write(
      JSON.stringify(
        {
          error: {
            code: "unknown_command",
            message: `Unknown command: ${args.join(" ")}. Run \`converly help\`.`,
          },
        },
        null,
        2
      ) + "\n"
    );
    process.exitCode = 1;
    return;
  }

  // Strict flag check: a mistyped flag must fail loudly here, not
  // silently vanish and change what the command does downstream.
  const allowed = new Set([...match.def.flags, ...GLOBAL_FLAGS]);
  const unknown = Object.keys(flags).filter((name) => !allowed.has(name));
  if (unknown.length > 0) {
    const globalList = [...GLOBAL_FLAGS].map((n) => `--${n}`).join(", ");
    const valid =
      match.def.flags.length > 0
        ? `Valid flags for \`converly ${match.name}\` are ${match.def.flags
            .map((n) => `--${n}`)
            .join(", ")}, plus the global ${globalList}.`
        : `\`converly ${match.name}\` takes no flags of its own, just the global ${globalList}.`;
    process.stderr.write(
      JSON.stringify(
        {
          error: {
            code: "unknown_flag",
            message: `Unknown flag${unknown.length > 1 ? "s" : ""}: ${unknown
              .map((n) => `--${n}`)
              .join(", ")}. ${valid}`,
          },
        },
        null,
        2
      ) + "\n"
    );
    process.exitCode = 1;
    return;
  }

  try {
    // Inside the error boundary: a malformed --api value must produce a
    // JSON error, not a raw stack trace.
    const origin = resolveOrigin(flags);
    if (typeof flags["idempotency-key"] === "string") {
      setDefaultIdempotencyKey(flags["idempotency-key"]);
    }
    const result = await match.def.run({ args: match.rest, flags, origin });
    process.stdout.write(JSON.stringify(result ?? { ok: true }, null, 2) + "\n");
  } catch (err) {
    // Two upstream error shapes exist: the /v1 envelope ({error: {code,
    // message, …}}) and delivery pass-throughs where `error` is a bare
    // STRING code with user_message/hint as siblings (e.g. the Google Ads
    // conversions proxy). Spreading a string produces {"0":"g","1":"o"…}
    // and silently DROPS the helpful copy — found live in the Google Ads
    // cosplay round.
    let error;
    if (err instanceof ApiError) {
      const body = err.body ?? {};
      const apiErr = body.error;
      if (apiErr && typeof apiErr === "object") {
        error = { status: err.status, ...apiErr };
      } else {
        error = {
          status: err.status,
          code: typeof apiErr === "string" ? apiErr : "api_error",
          message: body.user_message ?? body.message ?? err.message,
        };
      }
      if (body.user_message && !error.user_message && error.message !== body.user_message) {
        error.user_message = body.user_message;
      }
      if (body.hint && !error.hint) error.hint = body.hint;
    } else {
      error = {
        code: err instanceof AuthMissingError ? "not_logged_in" : "cli_error",
        message: err.message,
      };
    }
    const payload = { error };
    if (err.handoff) payload.handoff = err.handoff;
    process.stderr.write(JSON.stringify(payload, null, 2) + "\n");
    process.exitCode = 1;
  }
}
