/**
 * The `converly gtm` failure contract.
 *
 * The consumer of these commands is an AI agent, not a person reading a
 * table, so each failure has to be branchable WITHOUT parsing prose. Two
 * signals carry that:
 *
 *   - the `code` string in the JSON error on stderr (fine-grained), and
 *   - the process exit code (coarse, for shell-level control flow).
 *
 * Exit codes are additive: the rest of the CLI keeps its 0/1 contract
 * untouched, because errors that don't set `exitCode` still exit 1
 * (see the catch block in main.js). These codes apply to the gtm group.
 *
 *   0  success
 *   1  unclassified failure (also every shared argv-parsing error)
 *   2  usage — a flag is missing, malformed, or contradictory. Deterministic:
 *      retrying the identical command produces the identical failure.
 *   3  not authenticated — no Google login, or it expired and could not be
 *      refreshed. Fix with `converly gtm login`.
 *   4  refused by Google — permission denied, or quota exhausted after the
 *      client already retried. NOT a bad command; the same command may
 *      succeed later (quota) or for a different user (permission).
 *   5  publish gate refused. Never returned by any other command.
 */

export const EXIT = {
  OK: 0,
  ERROR: 1,
  USAGE: 2,
  AUTH: 3,
  REFUSED: 4,
  PUBLISH_GATE: 5,
};

function build(code, message, exitCode, extra = {}) {
  const err = new Error(message);
  err.code = code;
  err.exitCode = exitCode;
  Object.assign(err, extra);
  return err;
}

/** A malformed or incomplete command line. Retrying verbatim won't help. */
export function usageError(code, message, extra = {}) {
  return build(code, message, EXIT.USAGE, extra);
}

/** No usable Google login. */
export function authError(message, extra = {}) {
  return build("google_auth_required", message, EXIT.AUTH, extra);
}

/** Google refused the call: permission or quota. */
export function refusedError(code, message, extra = {}) {
  return build(code, message, EXIT.REFUSED, extra);
}

/** The publish safety gate said no. */
export function publishGateError(message, extra = {}) {
  return build("publish_gate", message, EXIT.PUBLISH_GATE, extra);
}
