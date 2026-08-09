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
import { ApiError, AuthMissingError } from "./http.js";
import * as auth from "./commands/auth.js";
import * as sites from "./commands/sites.js";
import * as destinations from "./commands/destinations.js";
import * as flows from "./commands/flows.js";
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
]);

export function parseArgv(argv) {
  const args = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token.startsWith("--")) {
      const eq = token.indexOf("=");
      if (eq !== -1) {
        flags[token.slice(2, eq)] = token.slice(eq + 1);
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
 * Registry: "group verb" (or a single word) → handler + usage line.
 * Usage lines double as the agent-facing documentation, so they carry
 * the flags and an example where the shape isn't obvious.
 */
const COMMANDS = {
  "login": {
    run: auth.login,
    usage: "converly login [--signup] [--staging]",
    help: "Log in via the browser. --signup sends new users to account creation (free trial starts automatically). Credentials are stored in ~/.converly/config.json.",
  },
  "logout": {
    run: auth.logout,
    usage: "converly logout [--staging]",
    help: "Forget the stored login for this deployment.",
  },
  "whoami": {
    run: auth.whoami,
    usage: "converly whoami",
    help: "Show the current account: subscription state and sites.",
  },
  "sites list": {
    run: sites.list,
    usage: "converly sites list [--limit N]",
    help: "List the account's sites.",
  },
  "sites get": {
    run: sites.get,
    usage: "converly sites get <site_id>",
    help: "Fetch one site.",
  },
  "sites create": {
    run: sites.create,
    usage: "converly sites create [--name X] [--domain example.com] [--timezone Z]",
    help: "Create a site. Most accounts already have a default site — prefer `sites update` on it.",
  },
  "sites update": {
    run: sites.update,
    usage: "converly sites update <site_id> [--name X] [--domain example.com] [--timezone Z]",
    help: "Update a site. Setting --domain is REQUIRED before tracking works (events from unknown domains are rejected).",
  },
  "install snippet": {
    run: sites.snippet,
    usage: "converly install snippet <site_id>",
    help: "Get the <script> tag to add to the website's <head>.",
  },
  "install status": {
    run: sites.installStatus,
    usage: "converly install status <site_id>",
    help: 'Check whether tracking is live. detection "confirmed" = proven; "never_seen" = no conversions captured yet (NOT proof the snippet is missing).',
  },
  "destinations types": {
    run: destinations.types,
    usage: "converly destinations types",
    help: "Catalogue of ad platforms Converly can send conversions to.",
  },
  "destinations list": {
    run: destinations.list,
    usage: "converly destinations list",
    help: "The account's destinations and whether each is connected.",
  },
  "destinations get": {
    run: destinations.get,
    usage: "converly destinations get <type>   (e.g. google-ads)",
    help: "One destination's connection state.",
  },
  "destinations connect": {
    run: destinations.connect,
    usage: "converly destinations connect <type> --site <site_id>",
    help: "Create a connect link for an ad platform. A HUMAN must open the returned url in a browser to authorize; then `converly handoffs wait <id>`.",
  },
  "destinations conversions": {
    run: destinations.conversions,
    usage: "converly destinations conversions <type> [--refresh]",
    help: "List the conversion actions / pixel events available in a connected destination (the picker for flow configs).",
  },
  "handoffs get": {
    run: destinations.handoffGet,
    usage: "converly handoffs get <handoff_id>",
    help: "Check a connect link's status once.",
  },
  "handoffs wait": {
    run: destinations.handoffWait,
    usage: "converly handoffs wait <handoff_id> [--timeout seconds]",
    help: "Poll a connect link until it completes (default timeout 600s). Exits non-zero if it expires or is cancelled.",
  },
  "triggers": {
    run: flows.triggerTypes,
    usage: "converly triggers [--platform webflow|wordpress|wix|framer]",
    help: "Catalogue of trigger types and form-tool provider slugs. Use a slug from providers[] as the flow's trigger integrationId.",
  },
  "actions": {
    run: flows.actionTypes,
    usage: "converly actions <destination_type>   (e.g. google-ads)",
    help: "The action config schema + example for one destination. Read this before building a flow's actions_config.",
  },
  "flows list": {
    run: flows.list,
    usage: "converly flows list [--site <site_id>] [--limit N]",
    help: "List flows.",
  },
  "flows get": {
    run: flows.get,
    usage: "converly flows get <flow_id>",
    help: "Fetch one flow.",
  },
  "flows create": {
    run: flows.create,
    usage: "converly flows create --site <id> --name <name> --trigger <slug> --destination <slug> [--conversion-id <id> | --event-name <name>] [--value N --currency USD] [--pages /a,/b] | --json '<body>'",
    help: "Create a draft flow. Simple form covers one trigger + one destination; --json takes the full flow body for anything richer.",
  },
  "flows update": {
    run: flows.update,
    usage: "converly flows update <flow_id> --json '{\"name\":\"...\"}'",
    help: "Update flow fields. Never pass status here — use publish/unpublish.",
  },
  "flows delete": {
    run: flows.remove,
    usage: "converly flows delete <flow_id>",
    help: "Delete a flow. Unpublish first if it's published.",
  },
  "flows validate": {
    run: flows.validate,
    usage: "converly flows validate <flow_id>",
    help: "Non-mutating publish-readiness check. Returns problems[] (blockers) and warnings[] (site not ready — e.g. domain missing).",
  },
  "flows publish": {
    run: flows.publish,
    usage: "converly flows publish <flow_id>",
    help: "Publish a flow live. Also returns warnings[] about site readiness.",
  },
  "flows unpublish": {
    run: flows.unpublish,
    usage: "converly flows unpublish <flow_id>",
    help: "Take a flow offline.",
  },
  "test-event": {
    run: flows.testEvent,
    usage: "converly test-event --flow <flow_id> [--action-id act-1] [--meta-code TEST123]",
    help: "Fire a test conversion through a flow's action to the real ad platform. Defaults to the flow's first action.",
  },
  "events list": {
    run: events.list,
    usage: "converly events list [--site <id>] [--flow <id>] [--email x@y.com] [--status completed|failed] [--since ISO] [--until ISO] [--limit N]",
    help: "Recent conversion events (bounded snapshot, max 100 — narrow with filters, there is no paging).",
  },
  "events get": {
    run: events.get,
    usage: "converly events get <event_id>",
    help: "One event with per-destination delivery status and any pipeline notices.",
  },
  "rules list": {
    run: misc.rulesList,
    usage: "converly rules list",
    help: "List internal-traffic rules (submissions matching them are ignored).",
  },
  "rules create": {
    run: misc.rulesCreate,
    usage: "converly rules create --ip 1.2.3.4 | --cidr 10.0.0.0/24 | --email-pattern '*@yourcompany.com' [--description X]",
    help: "Exclude the team's own traffic so testing doesn't pollute conversions.",
  },
  "subscription": {
    run: misc.subscription,
    usage: "converly subscription",
    help: "Plan, trial and billing state.",
  },
  "usage": {
    run: misc.usage,
    usage: "converly usage",
    help: "Current usage against plan limits.",
  },
  "api": {
    run: misc.api,
    usage: "converly api <GET|POST|PATCH|DELETE> </v1-path> [--json '<body>']",
    help: "Raw /v1 request for anything not covered by a named command.",
  },
};

function overviewHelp() {
  const lines = [
    `Converly CLI v${VERSION} — conversion tracking for ad platforms.`,
    "",
    "Every command prints JSON to stdout. Global flags: --staging (use the",
    "staging deployment), --api <origin> (custom deployment).",
    "Auth: `converly login`, or set CONVERLY_API_KEY for headless use.",
    "",
    "Typical setup sequence:",
    "  1. converly login --signup",
    "  2. converly sites list                          # find the site id",
    "  3. converly sites update <site> --domain example.com",
    "  4. converly install snippet <site>              # add tag to the website",
    "  5. converly destinations connect google-ads --site <site>",
    "     converly handoffs wait <handoff_id>          # human authorizes in browser",
    "  6. converly triggers  /  converly actions google-ads",
    "     converly destinations conversions google-ads # pick a conversion",
    "     converly flows create --site <site> --name \"Leads\" --trigger html-form \\",
    "       --destination google-ads --conversion-id <id>",
    "  7. converly flows validate <flow> && converly flows publish <flow>",
    "  8. converly test-event --flow <flow>            # prove delivery end to end",
    "  9. converly events list --limit 10              # watch real conversions",
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
function matchCommand(args) {
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

  const origin = resolveOrigin(flags);

  try {
    const result = await match.def.run({ args: match.rest, flags, origin });
    process.stdout.write(JSON.stringify(result ?? { ok: true }, null, 2) + "\n");
  } catch (err) {
    const error =
      err instanceof ApiError
        ? { status: err.status, ...(err.body?.error ?? { message: err.message }) }
        : {
            code:
              err instanceof AuthMissingError ? "not_logged_in" : "cli_error",
            message: err.message,
          };
    const payload = { error };
    if (err.handoff) payload.handoff = err.handoff;
    process.stderr.write(JSON.stringify(payload, null, 2) + "\n");
    process.exitCode = 1;
  }
}
