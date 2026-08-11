/**
 * Validate that a value is a single id SEGMENT, not a path. Ids are
 * interpolated straight into request paths, so a value containing `/`,
 * `\`, `?`, `#`, whitespace, or a `.`/`..` segment could climb to a
 * different resource (e.g. `sites update ../flows/x`). The URL builder
 * rejects such paths as a last line of defence, but validating here gives
 * a clear, early error at the command boundary.
 */
export function assertIdSegment(value, label = "id") {
  const v = String(value ?? "");
  if (!v) throw new Error(`Missing ${label}.`);
  // Strict allowlist: a real id / slug is letters, digits, underscore, or
  // hyphen. This rejects path separators AND their percent-encodings
  // (`%2e` → `.`, `%2f` → `/`, `%5c` → `\`) that `new URL()` would later
  // decode into a traversal — a plain "no dots/slashes" check would miss
  // the encoded form.
  if (!/^[A-Za-z0-9_-]+$/.test(v)) {
    throw new Error(
      `Invalid ${label} ${JSON.stringify(value)} — expected a single id (letters, digits, _ or -), not a path.`
    );
  }
  return v;
}
