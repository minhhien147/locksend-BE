/**
 * Safe labels for untrusted profile fields (display_name, etc.).
 * React already escapes text nodes, but long XSS PoC strings still break table layouts.
 */

const HTMLISH =
  /<|>|`|javascript:|data:text\/html|on(?:error|load|click|mouse\w+)\s*=/i;

export function looksLikeUnsafeLabel(value: string | null | undefined): boolean {
  if (!value) return false;
  return HTMLISH.test(value);
}

/** Strip markup-ish chars and truncate for table cells / avatars. */
export function safeLabel(
  value: string | null | undefined,
  fallback = "—",
  maxLen = 64
): string {
  if (!value) return fallback;
  const stripped = value
    .replace(/<[^>]*>/g, "")
    .replace(/[<>`'"]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  if (!stripped || looksLikeUnsafeLabel(value)) {
    return fallback;
  }
  if (stripped.length <= maxLen) return stripped;
  return `${stripped.slice(0, maxLen)}…`;
}

export function safeInitial(value: string | null | undefined, fallback = "U"): string {
  const label = safeLabel(value, fallback, 8);
  const ch = label.charAt(0);
  return /[a-z0-9]/i.test(ch) ? ch.toUpperCase() : fallback;
}
