export interface TransferStats {
  elapsedSec: number;
  etaSec: number | null;
  speedBps: number | null;
  bytesDone: number;
  bytesTotal: number;
}

export function formatDuration(totalSec: number): string {
  const sec = Math.max(0, Math.floor(totalSec));
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (h > 0) {
    return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  }
  return `${m}:${String(s).padStart(2, "0")}`;
}

export function formatSpeed(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return `${Math.round(bytesPerSec)} B/s`;
  if (bytesPerSec < 1024 * 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${(bytesPerSec / (1024 * 1024)).toFixed(1)} MB/s`;
}

export function computeTransferStats(
  bytesDone: number,
  bytesTotal: number,
  startedAtMs: number | null,
  /** Bumps on timer tick so callers recompute elapsed/speed. */
  _tick = 0
): TransferStats | null {
  void _tick;
  if (startedAtMs === null) return null;

  const elapsedMs = Math.max(0, Date.now() - startedAtMs);
  const elapsedSec = Math.floor(elapsedMs / 1000);
  const speedBps =
    elapsedMs >= 800 && bytesDone > 0 ? bytesDone / (elapsedMs / 1000) : null;
  const etaSec =
    speedBps !== null && bytesTotal > 0 && bytesDone < bytesTotal
      ? Math.ceil((bytesTotal - bytesDone) / speedBps)
      : null;

  return {
    elapsedSec,
    etaSec,
    speedBps,
    bytesDone,
    bytesTotal,
  };
}
