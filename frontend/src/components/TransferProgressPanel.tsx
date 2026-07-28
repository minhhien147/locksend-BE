import Card from "./ui/Card";
import { text } from "../styles/theme";
import {
  computeTransferStats,
  formatDuration,
  formatSpeed,
  type TransferStats,
} from "../utils/transferStats";
import { useT } from "../i18n/context";

export interface TransferProgressPanelProps {
  stats: TransferStats | null;
  /** Optional label above the bar (e.g. "Upload ciphertext"). */
  label?: string;
  /** Show network speed (download / upload phases). */
  showSpeed?: boolean;
  /** Show percent + progress bar when bytesTotal > 0. */
  showBar?: boolean;
  /** Accent for the progress bar. */
  barClassName?: string;
}

export default function TransferProgressPanel({
  stats,
  label,
  showSpeed = true,
  showBar = true,
  barClassName = "bg-blue-700 dark:bg-blue-600",
}: TransferProgressPanelProps) {
  const t = useT();
  if (!stats) return null;

  const pct =
    stats.bytesTotal > 0
      ? Math.min(100, Math.round((stats.bytesDone / stats.bytesTotal) * 100))
      : 0;

  return (
    <Card padding="sm" className="space-y-2">
      {(label || showBar) && (
        <div className={`flex items-center justify-between text-xs ${text.muted}`}>
          {label ? <span>{label}</span> : <span />}
          {showBar && stats.bytesTotal > 0 && (
            <span className="font-medium text-indigo-600 dark:text-indigo-400">
              {pct}%
            </span>
          )}
        </div>
      )}

      {showBar && stats.bytesTotal > 0 && (
        <div className="w-full bg-slate-200 dark:bg-slate-800 rounded-full h-1.5 overflow-hidden">
          <div
            className={`h-1.5 rounded-full transition-all duration-300 ${barClassName}`}
            style={{ width: `${pct}%` }}
          />
        </div>
      )}

      <div className={`flex flex-wrap gap-x-4 gap-y-1 text-xs tabular-nums ${text.muted}`}>
        <span>
          {t("transfer.elapsed")}: {formatDuration(stats.elapsedSec)}
        </span>
        <span>
          {t("transfer.remaining")}:{" "}
          {stats.etaSec !== null ? formatDuration(stats.etaSec) : "—"}
        </span>
        {showSpeed && (
          <span>
            {t("transfer.speed")}:{" "}
            {stats.speedBps !== null ? formatSpeed(stats.speedBps) : "—"}
          </span>
        )}
      </div>
    </Card>
  );
}

/** Helper when stats are computed inline from timer + bytes. */
export function buildPanelStats(
  bytesDone: number,
  bytesTotal: number,
  startedAt: number | null,
  tick: number
): TransferStats | null {
  return computeTransferStats(bytesDone, bytesTotal, startedAt, tick);
}
