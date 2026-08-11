/**
 * Small network helpers shared by the API client, the OAuth flow, and
 * device login. The point of centralising them is that every credential-
 * bearing call reads its response the SAME safe way.
 */

// True if the string contains any C0 control character (U+0000–U+001F) or
// DEL (U+007F). WHATWG `new URL()` STRIPS tab/newline/CR from anywhere in a
// URL before parsing, so a segment like ".<TAB>." would otherwise pass a
// naive dot check here and then become ".." — a traversal. Checked via
// char codes so the source carries no literal control bytes.
function hasControlChar(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c <= 0x1f || c === 0x7f) return true;
  }
  return false;
}

/**
 * Reject a request path whose any segment is (or could decode/normalize to)
 * a traversal or a separator. ONE implementation so the URL builder and the
 * raw `api` command can't diverge. Guards:
 *   - literal `.`/`..`, `/`, `\`;
 *   - control characters new URL() would strip (turning ".<TAB>." into "..");
 *   - percent-encoded forms, decoded REPEATEDLY until stable (catches
 *     double-encoding like `%252e%252e` a downstream decoder could unwrap);
 *   - unicode that NFKC-normalizes to a separator (e.g. fullwidth solidus);
 *   - malformed or bottomlessly-nested percent-escapes.
 */
function checkSegment(seg, value, label) {
  if (hasControlChar(value)) {
    throw new Error(
      `Refusing path segment ${JSON.stringify(seg)} — control character (${label}).`
    );
  }
  if (
    value === "." ||
    value === ".." ||
    value.includes("/") ||
    value.includes("\\")
  ) {
    throw new Error(
      `Refusing suspicious path segment ${JSON.stringify(seg)} (${label}).`
    );
  }
}

export function assertSafePathSegment(seg) {
  checkSegment(seg, seg, "literal");
  let cur = seg;
  for (let i = 0; i < 6; i++) {
    let next;
    try {
      next = decodeURIComponent(cur);
    } catch {
      throw new Error(
        `Malformed percent-encoding in path segment ${JSON.stringify(seg)}.`
      );
    }
    checkSegment(seg, next, "decoded");
    checkSegment(seg, next.normalize("NFKC"), "normalized");
    if (next === cur) return;
    cur = next;
  }
  throw new Error(`Over-encoded path segment ${JSON.stringify(seg)}.`);
}

export function assertSafePath(rawPath) {
  for (const seg of String(rawPath).split("/")) assertSafePathSegment(seg);
}

/**
 * Read a response body as text with a HARD byte ceiling, streaming so an
 * absent or lying Content-Length can't make us buffer an unbounded body
 * into memory. Returns one of:
 *   { text }            — the decoded body (may be "")
 *   { overLimit: true } — declared or actual size exceeded maxBytes
 *   { unreadable: true }— the stream errored mid-body (connection reset)
 *
 * Never throws — callers decide what each outcome means for their context
 * (a mid-body reset on a POST is ambiguous; on a GET it's just a failure).
 */
export async function readTextCapped(res, maxBytes) {
  // Fast reject on an honestly-declared oversize body — don't even start.
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    try {
      await res.body?.cancel?.();
    } catch {
      // best effort
    }
    return { overLimit: true };
  }

  // No web stream available (very old runtime / mocked response) — fall
  // back to text() but still enforce the cap by real byte length.
  if (!res.body || typeof res.body.getReader !== "function") {
    let text;
    try {
      text = await res.text();
    } catch {
      return { unreadable: true };
    }
    if (Buffer.byteLength(text, "utf8") > maxBytes) return { overLimit: true };
    return { text };
  }

  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        try {
          await reader.cancel();
        } catch {
          // best effort
        }
        return { overLimit: true };
      }
      chunks.push(Buffer.from(value));
    }
  } catch {
    return { unreadable: true };
  } finally {
    try {
      reader.releaseLock?.();
    } catch {
      // best effort
    }
  }
  return { text: Buffer.concat(chunks).toString("utf8") };
}
