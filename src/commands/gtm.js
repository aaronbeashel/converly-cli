/**
 * Google Tag Manager commands.
 *
 * These exist to answer questions that static analysis of a page CANNOT:
 * whether a tag is paused, whether it is blocked by a trigger, what its
 * trigger conditions literally are, whether the built-in variable a trigger
 * depends on was ever switched on, and — most valuable of all — whether the
 * work is sitting unpublished in a workspace. From outside the container all
 * of those look identical to "there is no tag".
 *
 * Output contract: one JSON document on stdout, diagnostics on stderr,
 * documented exit codes (see src/gtm-errors.js). No table formatting — the
 * consumer is an agent. The shared entry point already pretty-prints the
 * JSON, so there is no --pretty flag to add.
 */

import { gtmRequest, unwrapList, unwrapObject } from "../gtm-api.js";
import {
  googleLoginFlow,
  revokeGoogleToken,
  tokenInfo,
  getGoogleAccessToken,
  GTM_SCOPES,
} from "../gtm-auth.js";
import { getGoogleCredentials, clearGoogleCredentials } from "../config.js";
import { shouldSuppressBrowserOpen } from "../login-mode.js";
import { usageError, publishGateError } from "../gtm-errors.js";
import { assertIdSegment } from "./ids.js";

// --- Shared flag handling ------------------------------------------------

function requireFlag(flags, name, hint) {
  const value = flags[name];
  if (typeof value !== "string" || value.trim() === "") {
    throw usageError(
      "missing_flag",
      `--${name} is required.${hint ? ` ${hint}` : ""}`
    );
  }
  return assertIdSegmentOrThrow(value.trim(), name);
}

function assertIdSegmentOrThrow(value, name) {
  try {
    return assertIdSegment(value, `--${name} value`);
  } catch (cause) {
    throw usageError("invalid_flag_value", cause.message);
  }
}

function parseJsonFlag(value, flagName) {
  try {
    const parsed = JSON.parse(value);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("expected a JSON object");
    }
    return parsed;
  } catch (cause) {
    throw usageError(
      "invalid_json",
      `--${flagName} is not a valid JSON object: ${cause.message}`
    );
  }
}

/** account + container, the pair almost every command needs. */
function containerScope(flags) {
  const account = requireFlag(
    flags,
    "account",
    "Run `converly gtm accounts` to list them."
  );
  const container = requireFlag(
    flags,
    "container",
    "Run `converly gtm containers --account <id>` to list them."
  );
  return { account, container };
}

/**
 * account + container + workspace. Workspace IDs are NOT predictable and are
 * rarely 1, so the error points at the listing command rather than letting
 * someone guess.
 */
function workspaceScope(flags) {
  const { account, container } = containerScope(flags);
  const workspace = requireFlag(
    flags,
    "workspace",
    "Workspace IDs are not predictable (they are rarely 1). Run " +
      "`converly gtm workspaces --account <id> --container <id>` to find the real one."
  );
  return { account, container, workspace };
}

const workspacePath = ({ account, container, workspace }) =>
  `/accounts/${account}/containers/${container}/workspaces/${workspace}`;

/**
 * The scope echoed back in every response. Named consistently with the
 * API's own field names (accountId, not account) so a caller can pass a
 * value straight from one command's output into the next command's flags
 * without renaming anything.
 */
const scopeIds = ({ account, container, workspace }) => ({
  accountId: account,
  containerId: container,
  ...(workspace !== undefined && { workspaceId: workspace }),
});

// --- Auth commands -------------------------------------------------------

export async function login({ flags }) {
  const progress = (line) => process.stderr.write(`${line}\n`);
  const result = await googleLoginFlow({
    noOpen: shouldSuppressBrowserOpen(flags),
    progress,
  });
  return { ok: true, provider: "google", ...result };
}

export async function logout() {
  const creds = getGoogleCredentials();
  // Revoke at Google BEFORE clearing locally: if revocation is attempted
  // after the credential is gone there is nothing left to revoke, and the
  // token would stay valid at Google for its full lifetime.
  const revoked = await revokeGoogleToken(creds?.refresh_token ?? creds?.access_token);
  const removed = clearGoogleCredentials();
  return {
    ok: true,
    provider: "google",
    removed_stored_login: removed,
    revoked_at_google: revoked,
    ...(!revoked &&
      removed && {
        note:
          "The local credential was removed but Google did not confirm revocation. " +
          "Revoke access manually at https://myaccount.google.com/permissions if that matters.",
      }),
  };
}

export async function status() {
  const creds = getGoogleCredentials();
  if (!creds) {
    return {
      connected: false,
      next_step: "Run `converly gtm login` to connect a Google account.",
    };
  }

  const base = {
    connected: true,
    obtained_at: creds.obtained_at ?? null,
    expires_at: creds.expires_at ?? null,
    has_refresh_token: Boolean(creds.refresh_token),
    stored_scope: creds.scope ?? null,
  };

  // Prove the token actually works rather than just reporting that a file
  // exists. A stored credential Google has revoked looks identical on disk.
  let token;
  try {
    token = await getGoogleAccessToken();
  } catch (err) {
    return {
      ...base,
      token_valid: false,
      error: err.message,
      next_step: "Run `converly gtm login` again.",
    };
  }

  const info = await tokenInfo(token);
  const granted = String(info?.scope ?? creds.scope ?? "")
    .split(/\s+/)
    .filter(Boolean);
  const missing = GTM_SCOPES.filter((s) => !granted.includes(s));

  let accounts = null;
  let accountsError = null;
  try {
    const body = await gtmRequest("GET", "/accounts");
    accounts = unwrapList(body, "account").map((a) => ({
      accountId: a?.accountId ?? null,
      name: a?.name ?? null,
    }));
  } catch (err) {
    accountsError = err.message;
  }

  return {
    ...base,
    token_valid: true,
    // No email/profile scope is requested, so Google's stable subject id is
    // the only account identifier available. Saying which field this is
    // matters more than pretending an email is unavailable by accident.
    google_user_id: info?.sub ?? null,
    google_email: info?.email ?? null,
    account_identity_note:
      "The email address is not shown because this CLI deliberately does not " +
      "request an email or profile scope. `sub` is Google's stable ID for the " +
      "signed-in account; the accessible GTM accounts below are usually the " +
      "more useful identifier.",
    granted_scopes: granted,
    ...(missing.length > 0 && {
      missing_scopes: missing,
      warning:
        "Scopes were requested but not granted. Commands needing them fail with " +
        "permission_denied. Re-run `converly gtm login` and approve every checkbox.",
    }),
    ...(accounts ? { gtm_accounts: accounts } : { gtm_accounts_error: accountsError }),
  };
}

// --- Read commands -------------------------------------------------------

export async function accounts() {
  const body = await gtmRequest("GET", "/accounts");
  const rows = unwrapList(body, "account");
  return {
    accounts: rows.map((a) => ({
      accountId: a?.accountId ?? null,
      name: a?.name ?? null,
      path: a?.path ?? null,
    })),
    count: rows.length,
  };
}

export async function containers({ flags }) {
  const account = requireFlag(
    flags,
    "account",
    "Run `converly gtm accounts` to list them."
  );
  const body = await gtmRequest("GET", `/accounts/${account}/containers`);
  const rows = unwrapList(body, "container");
  return {
    accountId: account,
    containers: rows.map((c) => ({
      containerId: c?.containerId ?? null,
      name: c?.name ?? null,
      // publicId is the GTM-XXXXXX the snippet on the page carries — the
      // only id you can match against a live site.
      publicId: c?.publicId ?? null,
      usageContext: c?.usageContext ?? [],
      domainName: c?.domainName ?? [],
      path: c?.path ?? null,
    })),
    count: rows.length,
  };
}

export async function workspaces({ flags }) {
  const { account, container } = containerScope(flags);
  const body = await gtmRequest(
    "GET",
    `/accounts/${account}/containers/${container}/workspaces`
  );
  const rows = unwrapList(body, "workspace");
  return {
    accountId: account,
    containerId: container,
    workspaces: rows.map((w) => ({
      workspaceId: w?.workspaceId ?? null,
      name: w?.name ?? null,
      description: w?.description ?? null,
      path: w?.path ?? null,
    })),
    count: rows.length,
    note:
      "Workspace IDs are assigned by GTM and are not predictable, so do not assume 1. " +
      "Unpublished work can sit in ANY of these, so check them all with `converly gtm changes`.",
  };
}

// Keys whose value identifies where a tag sends data. Matching on the key
// name is the reliable signal; the value patterns below catch destination
// ids sitting under a key we don't know about (custom templates invent
// their own names constantly).
const DESTINATION_KEYS = new Set([
  "measurementid",
  "measurementidoverride",
  "tagid",
  "trackingid",
  "conversionid",
  "conversionlabel",
  "awconversionid",
  "pixelid",
  "streamid",
  "advertiserid",
  "destinationid",
  "containerid",
  "servercontainerurl",
  "propertyid",
  "accountid",
]);

// G-XXXX (GA4), AW-XXXX (Google Ads), GT-/GTM-XXXX (tag/container),
// UA-XXXX (Universal Analytics), DC-XXXX (Floodlight), MC-XXXX.
const DESTINATION_VALUE_RE = /^(G|AW|GT|GTM|UA|DC|MC)-[A-Z0-9-]+$/i;

/**
 * Walk a GTM parameter tree and pull out the identifiers that say WHERE a
 * tag sends data. A tag pointed at the wrong property is indistinguishable
 * from a working one unless you read these, so they are lifted to the top
 * level of the output rather than left buried in `parameter`.
 */
export function extractDestinationIds(parameter) {
  const found = [];
  const seen = new Set();

  const visit = (node, path) => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const item of node) visit(item, path);
      return;
    }
    const key = typeof node.key === "string" ? node.key : null;
    const here = key ? [...path, key] : path;
    const value = node.value;
    if (typeof value === "string" && value.trim()) {
      const keyMatches = key && DESTINATION_KEYS.has(key.toLowerCase());
      const valueMatches = DESTINATION_VALUE_RE.test(value.trim());
      if (keyMatches || valueMatches) {
        const dedupe = `${here.join(".")}=${value}`;
        if (!seen.has(dedupe)) {
          seen.add(dedupe);
          found.push({
            key: key ?? here[here.length - 1] ?? null,
            path: here.join("."),
            value,
            // A value like "{{GA4 Measurement ID}}" is a variable reference,
            // not an id. You cannot tell what it resolves to without reading
            // the variable, and it may resolve to nothing at runtime.
            is_variable_reference: /^\{\{.*\}\}$/.test(value.trim()),
          });
        }
      }
    }
    if (Array.isArray(node.list)) visit(node.list, here);
    if (Array.isArray(node.map)) visit(node.map, here);
  };

  visit(parameter, []);
  return found;
}

/**
 * Normalise a tag for agent consumption. Every field the brief calls a
 * "silent failure mode" is emitted EXPLICITLY, including when it is falsy:
 * an absent `paused` key and `paused: false` read the same to a human but
 * not to a program, and "the key wasn't there" is exactly how a paused tag
 * gets missed.
 */
export function shapeTag(t) {
  const parameter = Array.isArray(t?.parameter) ? t.parameter : [];
  const consent = t?.consentSettings ?? null;
  return {
    tagId: t?.tagId ?? null,
    name: t?.name ?? null,
    type: t?.type ?? null,
    // Explicitly false rather than omitted — a paused tag is live-looking
    // in every other respect.
    paused: t?.paused === true,
    firingTriggerId: Array.isArray(t?.firingTriggerId) ? t.firingTriggerId : [],
    // A blocking trigger silently suppresses an otherwise correct tag.
    blockingTriggerId: Array.isArray(t?.blockingTriggerId)
      ? t.blockingTriggerId
      : [],
    // Lowercase enum: unlimited | oncePerEvent | oncePerLoad. oncePerLoad on
    // a tag expected to fire per event is a classic under-counting bug.
    tagFiringOption: t?.tagFiringOption ?? null,
    consentSettings: consent
      ? {
          consentStatus: consent.consentStatus ?? null,
          consentTypes: Array.isArray(consent.consentType?.list)
            ? consent.consentType.list
                .map((p) => p?.value)
                .filter((v) => typeof v === "string")
            : [],
        }
      : null,
    setupTag: Array.isArray(t?.setupTag) ? t.setupTag : [],
    teardownTag: Array.isArray(t?.teardownTag) ? t.teardownTag : [],
    parentFolderId: t?.parentFolderId ?? null,
    notes: t?.notes ?? null,
    destination_ids: extractDestinationIds(parameter),
    // Returned verbatim: resolving a parameter tree is the caller's job and
    // any summary here would eventually lie about some tag type.
    parameter,
    path: t?.path ?? null,
    fingerprint: t?.fingerprint ?? null,
  };
}

export async function tags({ flags }) {
  const scope = workspaceScope(flags);
  const body = await gtmRequest("GET", `${workspacePath(scope)}/tags`);
  const rows = unwrapList(body, "tag");
  const shaped = rows.map(shapeTag);
  return {
    ...scopeIds(scope),
    tags: shaped,
    count: shaped.length,
    summary: {
      paused: shaped.filter((t) => t.paused).length,
      with_blocking_triggers: shaped.filter(
        (t) => t.blockingTriggerId.length > 0
      ).length,
      without_firing_triggers: shaped.filter(
        (t) => t.firingTriggerId.length === 0
      ).length,
    },
    note:
      "paused, blockingTriggerId, tagFiringOption and consentSettings are the " +
      "reasons a correctly-configured tag does not fire. A tag with no " +
      "firingTriggerId never fires at all.",
  };
}

/**
 * Flatten a GTM condition into the literal form it has in the container.
 * Deliberately NOT interpreted: `equals {arg0: "{{_event}}", arg1: "purchase"}`
 * is the fact. What `{{_event}}` resolves to at runtime is precisely what
 * cannot be known from here, so no attempt is made to guess.
 */
export function flattenConditions(list, source) {
  if (!Array.isArray(list)) return [];
  return list.map((c) => {
    const params = Array.isArray(c?.parameter) ? c.parameter : [];
    const args = {};
    for (const p of params) {
      if (p && typeof p.key === "string") args[p.key] = p.value ?? null;
    }
    return {
      source,
      type: c?.type ?? null,
      negate: c?.negate === true,
      ...args,
    };
  });
}

export function shapeTrigger(t) {
  const conditions = [
    ...flattenConditions(t?.filter, "filter"),
    ...flattenConditions(t?.customEventFilter, "customEventFilter"),
    ...flattenConditions(t?.autoEventFilter, "autoEventFilter"),
  ];
  return {
    triggerId: t?.triggerId ?? null,
    name: t?.name ?? null,
    type: t?.type ?? null,
    // The literal conditions, flattened for reading.
    conditions,
    // ...and the raw arrays, unmodified, for anything the flattening loses.
    filter: Array.isArray(t?.filter) ? t.filter : [],
    customEventFilter: Array.isArray(t?.customEventFilter)
      ? t.customEventFilter
      : [],
    autoEventFilter: Array.isArray(t?.autoEventFilter) ? t.autoEventFilter : [],
    eventName: t?.eventName ?? null,
    parameter: Array.isArray(t?.parameter) ? t.parameter : [],
    parentFolderId: t?.parentFolderId ?? null,
    notes: t?.notes ?? null,
    path: t?.path ?? null,
    fingerprint: t?.fingerprint ?? null,
  };
}

export async function triggers({ flags }) {
  const scope = workspaceScope(flags);
  const body = await gtmRequest("GET", `${workspacePath(scope)}/triggers`);
  const rows = unwrapList(body, "trigger");
  return {
    ...scopeIds(scope),
    triggers: rows.map(shapeTrigger),
    count: rows.length,
    note:
      "Conditions are returned literally, e.g. equals {arg0: \"{{_event}}\", " +
      "arg1: \"purchase\"}. Whether {{_event}} ever takes that value on the live " +
      "site cannot be determined from the container. That needs Preview mode " +
      "or a real page load.",
  };
}

export async function variables({ flags }) {
  const scope = workspaceScope(flags);
  const body = await gtmRequest("GET", `${workspacePath(scope)}/variables`);
  const rows = unwrapList(body, "variable");
  return {
    ...scopeIds(scope),
    variables: rows.map((v) => ({
      variableId: v?.variableId ?? null,
      name: v?.name ?? null,
      type: v?.type ?? null,
      parameter: Array.isArray(v?.parameter) ? v.parameter : [],
      parentFolderId: v?.parentFolderId ?? null,
      notes: v?.notes ?? null,
      path: v?.path ?? null,
      fingerprint: v?.fingerprint ?? null,
    })),
    count: rows.length,
    note:
      "These are USER-DEFINED variables only. Built-in variables are a separate " +
      "list. Run `converly gtm builtins`.",
  };
}

/**
 * Built-in variables that triggers most often depend on. If a trigger
 * references one of these and it was never enabled, the trigger is
 * permanently dead — and nothing about the tag, the trigger or the page
 * reveals it. That is why the disabled ones are reported, not just the
 * enabled ones.
 */
const TRIGGER_CRITICAL_BUILTINS = [
  "clickClasses",
  "clickElement",
  "clickId",
  "clickTarget",
  "clickText",
  "clickUrl",
  "formClasses",
  "formElement",
  "formId",
  "formTarget",
  "formText",
  "formUrl",
  "historyFragment",
  "historySource",
  "newHistoryFragment",
  "oldHistoryFragment",
  "pageHostname",
  "pagePath",
  "pageUrl",
  "referrer",
  "scrollDepthThreshold",
  "scrollDepthUnits",
  "scrollDirection",
  "videoStatus",
  "videoTitle",
  "videoUrl",
];

export async function builtins({ flags }) {
  const scope = workspaceScope(flags);
  const body = await gtmRequest(
    "GET",
    `${workspacePath(scope)}/built_in_variables`
  );
  const rows = unwrapList(body, "builtInVariable");
  const enabledTypes = new Set(
    rows.map((v) => v?.type).filter((t) => typeof t === "string")
  );
  const disabled = TRIGGER_CRITICAL_BUILTINS.filter((t) => !enabledTypes.has(t));
  return {
    ...scopeIds(scope),
    enabled: rows.map((v) => ({
      type: v?.type ?? null,
      name: v?.name ?? null,
      path: v?.path ?? null,
    })),
    enabled_count: rows.length,
    // Not "every built-in that is off" — only the ones triggers commonly key
    // on, so the list stays actionable rather than becoming noise.
    commonly_needed_but_disabled: disabled,
    note:
      "A trigger that references a built-in variable which was never enabled " +
      "NEVER fires, and nothing on the live page reveals it. If a trigger below " +
      "keys on something in commonly_needed_but_disabled, that is the bug. " +
      "Enable built-ins in the GTM UI under Variables > Configure.",
  };
}

/** One entity inside a workspace change, flattened to a readable row. */
function shapeChange(change) {
  const entityKeys = [
    "tag",
    "trigger",
    "variable",
    "builtInVariable",
    "folder",
    "client",
    "transformation",
    "zone",
    "customTemplate",
    "gtagConfig",
  ];
  for (const key of entityKeys) {
    const entity = change?.[key];
    if (entity && typeof entity === "object") {
      const row = {
        entity: key,
        changeStatus: change?.changeStatus ?? null,
        name: entity.name ?? null,
        id:
          entity.tagId ??
          entity.triggerId ??
          entity.variableId ??
          entity.folderId ??
          entity.clientId ??
          entity.transformationId ??
          entity.zoneId ??
          entity.templateId ??
          entity.type ??
          null,
        type: entity.type ?? null,
      };
      // For a tag, the whole question is usually "would this even work once
      // published" — so carry the fields that decide that.
      if (key === "tag") {
        row.paused = entity.paused === true;
        row.firingTriggerId = Array.isArray(entity.firingTriggerId)
          ? entity.firingTriggerId
          : [];
        row.blockingTriggerId = Array.isArray(entity.blockingTriggerId)
          ? entity.blockingTriggerId
          : [];
        row.destination_ids = extractDestinationIds(entity.parameter);
      }
      return row;
    }
  }
  return {
    entity: "unknown",
    changeStatus: change?.changeStatus ?? null,
    name: null,
    id: null,
    type: null,
  };
}

/**
 * Unpublished changes, across EVERY workspace unless one is named.
 *
 * This is the command that separates "you have no tag" from "your tag is
 * built and just needs publishing". Those two states are identical from
 * outside the container and lead to completely opposite advice, and work
 * routinely sits in a non-default workspace nobody thought to look at.
 */
export async function changes({ flags }) {
  const { account, container } = containerScope(flags);

  let targets;
  if (typeof flags.workspace === "string" && flags.workspace.trim() !== "") {
    targets = [
      {
        workspaceId: assertIdSegmentOrThrow(flags.workspace.trim(), "workspace"),
        name: null,
      },
    ];
  } else {
    const body = await gtmRequest(
      "GET",
      `/accounts/${account}/containers/${container}/workspaces`
    );
    targets = unwrapList(body, "workspace").map((w) => ({
      workspaceId: w?.workspaceId ?? null,
      name: w?.name ?? null,
    }));
  }

  const results = [];
  for (const target of targets) {
    if (!target.workspaceId) continue;
    const scope = {
      account,
      container,
      workspace: String(target.workspaceId),
    };
    try {
      const body = await gtmRequest("GET", `${workspacePath(scope)}/status`);
      const changeRows = unwrapList(body, "workspaceChange");
      const conflicts = unwrapList(body, "mergeConflict");
      results.push({
        workspaceId: target.workspaceId,
        name: target.name,
        has_changes: changeRows.length > 0,
        change_count: changeRows.length,
        conflict_count: conflicts.length,
        changes: changeRows.map(shapeChange),
        ...(conflicts.length > 0 && {
          merge_conflicts: conflicts.length,
          conflict_note:
            "This workspace conflicts with the live container and cannot be " +
            "versioned until the conflicts are resolved in the GTM UI.",
        }),
      });
    } catch (err) {
      // One unreadable workspace must not hide the others — partial results
      // with an explicit error beat a single failed command.
      results.push({
        workspaceId: target.workspaceId,
        name: target.name,
        error: err.message,
      });
    }
  }

  const totalChanges = results.reduce((n, r) => n + (r.change_count ?? 0), 0);
  const withChanges = results.filter((r) => r.has_changes);

  return {
    accountId: account,
    containerId: container,
    workspaces_checked: results.length,
    total_unpublished_changes: totalChanges,
    workspaces_with_changes: withChanges.map((r) => r.workspaceId),
    workspaces: results,
    interpretation:
      totalChanges > 0
        ? "There ARE unpublished changes. Work exists in a workspace but is not " +
          "live. From outside the container this is indistinguishable from having " +
          "no tag at all. Publishing is what makes it real."
        : "No unpublished changes in any workspace. Whatever is live is all there " +
          "is, so a missing tag is genuinely missing rather than merely unpublished.",
  };
}

/**
 * GTM fingerprints are millisecond epoch timestamps. They are the only date
 * the version endpoints expose, so they are what you use to line a breakage
 * up against a container change.
 */
function fingerprintTime(fingerprint) {
  const ms = Number(fingerprint);
  if (!Number.isFinite(ms) || ms <= 0) return null;
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

export async function versions({ flags }) {
  const { account, container } = containerScope(flags);

  // includeDeleted is NOT optional on this endpoint — omitting it errors
  // rather than defaulting, which is why it is always sent explicitly.
  const body = await gtmRequest(
    "GET",
    `/accounts/${account}/containers/${container}/version_headers`,
    { query: { includeDeleted: "false" } }
  );
  const rows = unwrapList(body, "containerVersionHeader");

  // Which one is actually live. This call wraps its result differently from
  // the list calls, so it is unwrapped by marker rather than by envelope.
  let live = null;
  let liveError = null;
  try {
    const liveBody = await gtmRequest(
      "GET",
      `/accounts/${account}/containers/${container}/versions:live`
    );
    const version = unwrapObject(
      liveBody,
      ["containerVersion", "version"],
      "containerVersionId"
    );
    if (version) {
      live = {
        containerVersionId: version.containerVersionId ?? null,
        name: version.name ?? null,
        fingerprint: version.fingerprint ?? null,
        last_modified: fingerprintTime(version.fingerprint),
      };
    }
  } catch (err) {
    liveError = err.message;
  }

  return {
    accountId: account,
    containerId: container,
    live_version: live,
    ...(liveError && { live_version_error: liveError }),
    versions: rows.map((v) => ({
      containerVersionId: v?.containerVersionId ?? null,
      name: v?.name ?? null,
      deleted: v?.deleted === true,
      is_live:
        live?.containerVersionId != null &&
        v?.containerVersionId === live.containerVersionId,
      numTags: v?.numTags ?? null,
      numTriggers: v?.numTriggers ?? null,
      numVariables: v?.numVariables ?? null,
      numCustomTemplates: v?.numCustomTemplates ?? null,
      path: v?.path ?? null,
    })),
    count: rows.length,
    note:
      "Version headers carry no publish timestamp, because the Tag Manager API does not " +
      "expose one. live_version.last_modified is derived from the version " +
      "fingerprint, which is its storage time, so it dates the last change to the " +
      "live container rather than the publish action itself. Treat it as " +
      "approximate when dating a breakage.",
  };
}

// --- Write commands ------------------------------------------------------
//
// Creating and updating inside a WORKSPACE is safe: nothing reaches the live
// site until a version is published. So these are ungated, and only
// `publish` carries the gate.

const TAG_FIRING_OPTIONS = new Set(["unlimited", "oncePerEvent", "oncePerLoad"]);

/**
 * Build a resource body from convenience flags, then merge --json over the
 * top so --json always wins and can express anything the flags cannot.
 */
function buildResourceBody(flags, { requireType = true } = {}) {
  const body = {};
  if (typeof flags.name === "string" && flags.name !== "") body.name = flags.name;
  if (typeof flags.type === "string" && flags.type !== "") body.type = flags.type;
  if (typeof flags.notes === "string") body.notes = flags.notes;

  if (flags.json !== undefined) {
    Object.assign(body, parseJsonFlag(flags.json, "json"));
  }

  if (typeof body.name !== "string" || body.name.trim() === "") {
    throw usageError(
      "missing_flag",
      "A name is required. Pass --name, or include \"name\" in --json."
    );
  }
  if (requireType && (typeof body.type !== "string" || body.type.trim() === "")) {
    throw usageError(
      "missing_flag",
      "A type is required. Pass --type, or include \"type\" in --json. " +
        "Copy the exact type string from an existing resource " +
        "(`converly gtm tags ...`) rather than guessing it."
    );
  }
  return body;
}

export async function createTag({ flags }) {
  const scope = workspaceScope(flags);
  const body = buildResourceBody(flags);

  // --trigger is the common case; --json can still set firingTriggerId.
  if (typeof flags.trigger === "string" && flags.trigger !== "") {
    const ids = flags.trigger
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .map((id) => assertIdSegmentOrThrow(id, "trigger"));
    if (body.firingTriggerId === undefined) body.firingTriggerId = ids;
  }

  if (body.tagFiringOption !== undefined) {
    // The enum is lowercase-initial: unlimited | oncePerEvent | oncePerLoad.
    // "ONCE_PER_EVENT" is rejected by the API with an unhelpful message, so
    // it is caught here where the fix can be spelled out.
    if (!TAG_FIRING_OPTIONS.has(body.tagFiringOption)) {
      throw usageError(
        "invalid_json",
        `tagFiringOption must be one of ${[...TAG_FIRING_OPTIONS].join(", ")} ` +
          `(exact case). Got ${JSON.stringify(body.tagFiringOption)}.`
      );
    }
  }

  if (
    body.firingTriggerId === undefined ||
    (Array.isArray(body.firingTriggerId) && body.firingTriggerId.length === 0)
  ) {
    process.stderr.write(
      "Warning: this tag has no firing trigger, so it will never fire. " +
        "Pass --trigger <triggerId> or set firingTriggerId in --json.\n"
    );
  }

  const created = await gtmRequest("POST", `${workspacePath(scope)}/tags`, {
    body,
  });
  return {
    ok: true,
    ...scopeIds(scope),
    tag: shapeTag(unwrapObject(created, ["tag"], "tagId") ?? created),
    note:
      "Created in the workspace only. Nothing is live until a version is created " +
      "and published. See `converly gtm publish`.",
  };
}

export async function createTrigger({ flags }) {
  const scope = workspaceScope(flags);
  const body = buildResourceBody(flags);
  const created = await gtmRequest("POST", `${workspacePath(scope)}/triggers`, {
    body,
  });
  return {
    ok: true,
    ...scopeIds(scope),
    trigger: shapeTrigger(
      unwrapObject(created, ["trigger"], "triggerId") ?? created
    ),
    note: "Created in the workspace only. Publish to make it live.",
  };
}

export async function createVariable({ flags }) {
  const scope = workspaceScope(flags);
  const body = buildResourceBody(flags);
  const created = await gtmRequest("POST", `${workspacePath(scope)}/variables`, {
    body,
  });
  const v = unwrapObject(created, ["variable"], "variableId") ?? created;
  return {
    ok: true,
    ...scopeIds(scope),
    variable: {
      variableId: v?.variableId ?? null,
      name: v?.name ?? null,
      type: v?.type ?? null,
      parameter: Array.isArray(v?.parameter) ? v.parameter : [],
      path: v?.path ?? null,
    },
    note: "Created in the workspace only. Publish to make it live.",
  };
}

// --- Publish (gated) -----------------------------------------------------

export const PUBLISH_ENV_FLAG = "CONVERLY_GTM_ALLOW_PUBLISH";

/**
 * The publish gate.
 *
 * Publishing pushes a container version to the LIVE site — every visitor,
 * immediately. Two independent conditions must hold, and they are
 * deliberately of different kinds:
 *
 *   1. CONVERLY_GTM_ALLOW_PUBLISH=true in the environment. This is the
 *      OPERATOR's gate. A model driving this CLI cannot set the environment
 *      of an invocation a human already launched, so this is the condition
 *      it cannot satisfy on its own.
 *   2. --confirm on the command line. This is the CALLER's gate: it makes
 *      publishing an explicit act rather than something that happens as a
 *      side effect of a plan.
 *
 * A flag alone is not protection, because a model can pass any flag it likes.
 * That is the whole reason for condition 1.
 *
 * The env var must be exactly "true" (case-insensitive, trimmed). The looser
 * envTruthy() used elsewhere accepts "1"/"yes"/any non-empty string, which is
 * fine for choosing a login mode and much too generous for a gate on a
 * production deploy — a stray "0"-vs-"" mistake should not publish anything.
 *
 * Exported for direct unit testing: this is the one behaviour in the group
 * that must never regress.
 */
export function assertPublishAllowed(flags, env = process.env) {
  const raw = env[PUBLISH_ENV_FLAG];
  const envAllows = String(raw ?? "").trim().toLowerCase() === "true";
  const confirmed = flags?.confirm === true;

  if (envAllows && confirmed) return true;

  const missing = [];
  if (!envAllows) missing.push(`${PUBLISH_ENV_FLAG}=true in the environment`);
  if (!confirmed) missing.push("--confirm on the command line");

  throw publishGateError(
    `Refusing to publish. Publishing pushes the container to the LIVE site for ` +
      `every visitor immediately. It requires BOTH ${PUBLISH_ENV_FLAG}=true and ` +
      `--confirm; missing: ${missing.join(" and ")}. ` +
      `${PUBLISH_ENV_FLAG} is an operator decision and is not something an agent ` +
      `should set on the user's behalf. Ask the person who owns the site. ` +
      `Building tags inside a workspace needs no gate and is safe to continue.`,
    {
      gate: {
        env_flag: PUBLISH_ENV_FLAG,
        env_flag_satisfied: envAllows,
        confirm_flag_satisfied: confirmed,
        missing,
      },
    }
  );
}

export async function publish({ flags }) {
  const { account, container } = containerScope(flags);

  const hasVersion =
    typeof flags["version-id"] === "string" && flags["version-id"].trim() !== "";
  const hasWorkspace =
    typeof flags.workspace === "string" && flags.workspace.trim() !== "";

  if (hasVersion && hasWorkspace) {
    throw usageError(
      "conflicting_flags",
      "Pass either --workspace (create a version from it, then publish that) or " +
        "--version-id (publish an existing version), not both."
    );
  }
  if (!hasVersion && !hasWorkspace) {
    throw usageError(
      "missing_flag",
      "Pass --workspace <id> to version and publish a workspace's changes, or " +
        "--version-id <id> to publish an existing version. " +
        "Run `converly gtm changes --account <id> --container <id>` first to see " +
        "what would go live."
    );
  }

  // Gate BEFORE any mutation. Creating a version is itself a change to the
  // container, so it must not happen on a run that will then refuse.
  assertPublishAllowed(flags);

  let versionId;
  let createdVersion = null;

  if (hasWorkspace) {
    const workspace = assertIdSegmentOrThrow(flags.workspace.trim(), "workspace");
    const created = await gtmRequest(
      "POST",
      `${workspacePath({ account, container, workspace })}:create_version`,
      {
        body: {
          ...(typeof flags.name === "string" && flags.name !== "" && {
            name: flags.name,
          }),
          ...(typeof flags.notes === "string" && { notes: flags.notes }),
        },
      }
    );
    const version = unwrapObject(
      created,
      ["containerVersion"],
      "containerVersionId"
    );
    if (!version?.containerVersionId) {
      // GTM returns success with no version when there is nothing to version.
      const err = usageError(
        "no_changes_to_publish",
        `Workspace ${workspace} has no changes to version, so there is nothing to ` +
          `publish. Run \`converly gtm changes --account ${account} --container ` +
          `${container}\`, because the changes may be in a different workspace.`
      );
      err.compilerError = created?.compilerError ?? null;
      throw err;
    }
    versionId = String(version.containerVersionId);
    createdVersion = {
      containerVersionId: versionId,
      name: version.name ?? null,
      path: version.path ?? null,
    };
  } else {
    versionId = assertIdSegmentOrThrow(flags["version-id"].trim(), "version-id");
  }

  const published = await gtmRequest(
    "POST",
    `/accounts/${account}/containers/${container}/versions/${versionId}:publish`
  );
  const version = unwrapObject(
    published,
    ["containerVersion"],
    "containerVersionId"
  );

  return {
    ok: true,
    accountId: account,
    containerId: container,
    ...(createdVersion && { created_version: createdVersion }),
    published_version: {
      containerVersionId: version?.containerVersionId ?? versionId,
      name: version?.name ?? null,
      path: version?.path ?? null,
    },
    ...(published?.compilerError && { compiler_error: published.compilerError }),
    live: true,
    note:
      "This container is now LIVE for every visitor. To roll back, publish the " +
      "previous version id from `converly gtm versions`.",
  };
}
