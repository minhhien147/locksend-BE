/** Extensions that should not be opened before reputation / AV checks. */
const HIGH_RISK_EXT = new Set([
  "exe",
  "msi",
  "bat",
  "cmd",
  "com",
  "scr",
  "ps1",
  "vbs",
  "js",
  "jse",
  "wsf",
  "wsh",
  "jar",
  "dll",
  "sys",
  "apk",
  "dmg",
  "pkg",
  "sh",
  "docm",
  "xlsm",
  "pptm",
]);

export function fileExtension(fileName: string | null | undefined): string {
  if (!fileName) return "";
  const base = fileName.split(/[/\\]/).pop() ?? fileName;
  const i = base.lastIndexOf(".");
  if (i <= 0 || i === base.length - 1) return "";
  return base.slice(i + 1).toLowerCase();
}

export function isHighRiskFilename(fileName: string | null | undefined): boolean {
  return HIGH_RISK_EXT.has(fileExtension(fileName));
}

/** Best-effort wipe of plaintext bytes still held in a TypedArray. */
export function wipeBytes(data: Uint8Array | null | undefined): void {
  if (!data) return;
  data.fill(0);
}
