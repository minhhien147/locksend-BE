import { useCallback, useEffect, useRef, useState } from "react";
import api from "../utils/api";
import { LoadingSpinner } from "../components/LoadingSpinner";
import { admin, badge, btn, inputBase, surfaceCard, text } from "../styles/theme";
import { useT } from "../i18n/context";
import { safeLabel } from "../utils/safeLabel";

// ── Types ─────────────────────────────────────────────────────────────────────

type ActivityType = "all" | "upload" | "download" | "api";

interface ActivityItem {
  id: string;
  type: "upload" | "download" | "api";
  user_id: string | null;
  user_email: string | null;
  user_display_name: string | null;
  detail: string;
  ip_address: string | null;
  user_agent: string | null;
  status_code: number | null;
  size_bytes: number | null;
  created_at: string;
}

interface ActivityResponse {
  items: ActivityItem[];
  total: number;
  page: number;
  pages: number;
  has_next: boolean;
  has_prev: boolean;
}

interface UserSummary {
  user_id: string;
  user_email: string | null;
  user_display_name: string | null;
  total_uploads: number;
  total_downloads: number;
  total_api_calls: number;
  last_upload_at: string | null;
  last_download_at: string | null;
  last_api_at: string | null;
  total_bytes_uploaded: number;
  total_bytes_downloaded: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtBytes(bytes: number | null): string {
  if (bytes === null || bytes === 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function fmtTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString("vi-VN", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function fmtTimeShort(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString("vi-VN", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function typeBadge(type: ActivityItem["type"]): string {
  switch (type) {
    case "upload":
      return badge.info;
    case "download":
      return badge.success;
    case "api":
      return badge.neutral;
  }
}

function statusBadge(code: number | null): string {
  if (code === null) return "";
  if (code < 300) return badge.success;
  if (code < 400) return badge.warning;
  return badge.danger;
}

function exportToCsv(items: ActivityItem[]): void {
  const header = ["Time", "User", "Type", "Detail", "IP", "Status", "Size (bytes)"];
  const rows = items.map((i) => [
    i.created_at,
    i.user_email ?? "",
    i.type,
    `"${i.detail.replace(/"/g, '""')}"`,
    i.ip_address ?? "",
    i.status_code?.toString() ?? "",
    i.size_bytes?.toString() ?? "",
  ]);
  const csv = [header, ...rows].map((r) => r.join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `activity_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Main component ────────────────────────────────────────────────────────────

export default function AdminActivityPage() {
  const t = useT();

  // Filters
  const [typeFilter, setTypeFilter] = useState<ActivityType>("all");
  const [emailSearch, setEmailSearch] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");

  // Data
  const [data, setData] = useState<ActivityResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);

  // User summary panel
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [summary, setSummary] = useState<UserSummary | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(false);

  // Auto-refresh
  const [autoRefresh, setAutoRefresh] = useState(false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchData = useCallback(async (p = page) => {
    try {
      setLoading(true);
      setError(null);
      const params = new URLSearchParams();
      params.set("type", typeFilter);
      params.set("page", String(p));
      params.set("limit", "50");
      if (emailSearch.trim()) params.set("q", emailSearch.trim());
      if (dateFrom) params.set("date_from", new Date(dateFrom).toISOString());
      if (dateTo) {
        const d = new Date(dateTo);
        d.setHours(23, 59, 59, 999);
        params.set("date_to", d.toISOString());
      }
      const res = await api.get<ActivityResponse>(`/auth/admin/activity?${params}`);
      setData(res.data);
    } catch {
      setError(t("admin.activity.loadFailed"));
    } finally {
      setLoading(false);
    }
  }, [typeFilter, emailSearch, dateFrom, dateTo, page, t]);

  // Refetch when filters change, reset page
  useEffect(() => {
    setPage(1);
    fetchData(1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [typeFilter, emailSearch, dateFrom, dateTo]);

  // Refetch when page changes
  useEffect(() => {
    fetchData(page);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page]);

  // Auto-refresh interval
  useEffect(() => {
    if (autoRefresh) {
      timerRef.current = setInterval(() => fetchData(page), 30_000);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [autoRefresh, fetchData, page]);

  const fetchSummary = async (userId: string) => {
    if (selectedUserId === userId) {
      setSelectedUserId(null);
      setSummary(null);
      return;
    }
    setSelectedUserId(userId);
    setSummary(null);
    setSummaryLoading(true);
    try {
      const res = await api.get<UserSummary>(`/auth/admin/activity/users/${userId}/summary`);
      setSummary(res.data);
    } catch {
      setSummary(null);
    } finally {
      setSummaryLoading(false);
    }
  };

  const TYPE_OPTIONS: { value: ActivityType; label: string }[] = [
    { value: "all", label: t("admin.activity.filterAll") },
    { value: "upload", label: t("admin.activity.filterUpload") },
    { value: "download", label: t("admin.activity.filterDownload") },
    { value: "api", label: t("admin.activity.filterApi") },
  ];

  return (
    <div className="space-y-5">
      {/* Header */}
      <div>
        <h2 className={admin.title}>{t("admin.activity.title")}</h2>
        <p className={admin.desc}>{t("admin.activity.desc")}</p>
      </div>

      {/* Filter bar */}
      <div className={`${surfaceCard} p-4 flex flex-wrap gap-3 items-end`}>
        {/* Type filter */}
        <div className="flex flex-col gap-1">
          <span className={`text-[10px] font-semibold uppercase tracking-wider ${text.muted}`}>
            {t("admin.activity.filterType")}
          </span>
          <div className="flex gap-1">
            {TYPE_OPTIONS.map((o) => (
              <button
                key={o.value}
                onClick={() => setTypeFilter(o.value)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition ${
                  typeFilter === o.value
                    ? "bg-slate-900 text-white dark:bg-white/10 dark:text-white"
                    : "border border-slate-200 text-slate-600 hover:bg-slate-50 dark:border-white/10 dark:text-slate-400 dark:hover:bg-white/[0.04]"
                }`}
              >
                {o.label}
              </button>
            ))}
          </div>
        </div>

        {/* Email search */}
        <div className="flex flex-col gap-1 min-w-[180px]">
          <span className={`text-[10px] font-semibold uppercase tracking-wider ${text.muted}`}>
            {t("admin.activity.filterUser")}
          </span>
          <input
            type="text"
            value={emailSearch}
            onChange={(e) => setEmailSearch(e.target.value)}
            placeholder={t("admin.activity.searchPlaceholder")}
            className={inputBase}
          />
        </div>

        {/* Date from */}
        <div className="flex flex-col gap-1">
          <span className={`text-[10px] font-semibold uppercase tracking-wider ${text.muted}`}>
            {t("admin.activity.filterDateFrom")}
          </span>
          <input
            type="date"
            value={dateFrom}
            onChange={(e) => setDateFrom(e.target.value)}
            className={inputBase + " w-36"}
          />
        </div>

        {/* Date to */}
        <div className="flex flex-col gap-1">
          <span className={`text-[10px] font-semibold uppercase tracking-wider ${text.muted}`}>
            {t("admin.activity.filterDateTo")}
          </span>
          <input
            type="date"
            value={dateTo}
            onChange={(e) => setDateTo(e.target.value)}
            className={inputBase + " w-36"}
          />
        </div>

        {/* Spacer */}
        <div className="flex-1" />

        {/* Auto-refresh toggle */}
        <button
          onClick={() => setAutoRefresh((v) => !v)}
          className={`${btn.secondary} text-xs h-9 ${
            autoRefresh
              ? "border-emerald-400 text-emerald-700 dark:border-emerald-500/40 dark:text-emerald-300"
              : ""
          }`}
        >
          <span
            className={`inline-block w-2 h-2 rounded-full mr-1 ${
              autoRefresh ? "bg-emerald-500 animate-pulse" : "bg-slate-300 dark:bg-slate-600"
            }`}
          />
          {t("admin.activity.autoRefresh")}
        </button>

        {/* Refresh */}
        <button
          onClick={() => fetchData(page)}
          disabled={loading}
          className={`${btn.secondary} h-9 text-xs`}
        >
          {t("admin.refresh")}
        </button>

        {/* Export CSV */}
        {data && data.items.length > 0 && (
          <button
            onClick={() => exportToCsv(data.items)}
            className={`${btn.ghost} h-9 text-xs`}
          >
            {t("admin.activity.exportCsv")}
          </button>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="rounded-md border border-rose-200/90 bg-rose-50 px-4 py-3 text-sm text-rose-800 dark:border-rose-500/25 dark:bg-rose-500/[0.08] dark:text-rose-300">
          {error}
        </div>
      )}

      {/* User summary panel */}
      {selectedUserId && (
        <div className={`${surfaceCard} p-4`}>
          {summaryLoading ? (
            <div className="flex justify-center py-4">
              <LoadingSpinner size="sm" />
            </div>
          ) : summary ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className={`font-semibold ${text.primary}`}>
                  {t("admin.activity.userSummary")} —{" "}
                  <span className="font-mono text-sm text-blue-600 dark:text-blue-400">
                    {summary.user_email ?? summary.user_id}
                  </span>
                </h3>
                <button
                  onClick={() => { setSelectedUserId(null); setSummary(null); }}
                  className={`${btn.ghost} h-7 text-xs`}
                >
                  {t("admin.close")}
                </button>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                <StatCard label={t("admin.activity.summaryUploads")} value={String(summary.total_uploads)} />
                <StatCard label={t("admin.activity.summaryDownloads")} value={String(summary.total_downloads)} />
                <StatCard label={t("admin.activity.summaryApi")} value={String(summary.total_api_calls)} />
                <StatCard label={t("admin.activity.summaryBytesUp")} value={fmtBytes(summary.total_bytes_uploaded)} />
                <StatCard label={t("admin.activity.summaryBytesDown")} value={fmtBytes(summary.total_bytes_downloaded)} />
                <div className="col-span-2 sm:col-span-3 lg:col-span-1 space-y-1">
                  <p className={`text-[10px] font-semibold uppercase tracking-wider ${text.muted}`}>
                    {t("admin.activity.summaryLastUpload")}
                  </p>
                  <p className={`text-xs ${text.secondary}`}>{fmtTimeShort(summary.last_upload_at) || t("admin.activity.never")}</p>
                  <p className={`text-[10px] font-semibold uppercase tracking-wider ${text.muted}`}>
                    {t("admin.activity.summaryLastDownload")}
                  </p>
                  <p className={`text-xs ${text.secondary}`}>{fmtTimeShort(summary.last_download_at) || t("admin.activity.never")}</p>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      )}

      {/* Table */}
      <div className={`${surfaceCard} overflow-x-auto`}>
        {loading ? (
          <div className="flex justify-center py-12">
            <LoadingSpinner size="md" />
          </div>
        ) : data && data.items.length === 0 ? (
          <p className={`text-center py-10 text-sm ${text.muted}`}>{t("admin.activity.empty")}</p>
        ) : (
          <table className="w-full text-sm border-collapse min-w-[960px]">
              <thead>
                <tr className={admin.tableHead}>
                  <th className="px-4 py-3 font-semibold tracking-wider text-[10px] uppercase whitespace-nowrap text-left">
                    {t("admin.activity.colTime")}
                  </th>
                  <th className="px-4 py-3 font-semibold tracking-wider text-[10px] uppercase text-left w-[22%]">
                    {t("admin.activity.colUser")}
                  </th>
                  <th className="px-4 py-3 font-semibold tracking-wider text-[10px] uppercase text-left">
                    {t("admin.activity.colType")}
                  </th>
                  <th className="px-4 py-3 font-semibold tracking-wider text-[10px] uppercase text-left">
                    {t("admin.activity.colDetail")}
                  </th>
                  <th className="px-4 py-3 font-semibold tracking-wider text-[10px] uppercase whitespace-nowrap text-left">
                    {t("admin.activity.colIp")}
                  </th>
                  <th className="px-4 py-3 font-semibold tracking-wider text-[10px] uppercase whitespace-nowrap text-left">
                    {t("admin.activity.colSize")}
                  </th>
                  <th className="px-4 py-3 font-semibold tracking-wider text-[10px] uppercase text-left">
                    {t("admin.activity.colStatus")}
                  </th>
                </tr>
              </thead>
              <tbody className={admin.tableDivide}>
                {data?.items.map((item) => {
                  const displayName = safeLabel(
                    item.user_display_name,
                    "",
                    48
                  );
                  const showDisplay =
                    Boolean(displayName) &&
                    displayName !== "—" &&
                    displayName !== (item.user_email ?? "");
                  return (
                  <tr key={item.id} className={admin.rowHover}>
                    {/* Time */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={admin.cellMeta}>{fmtTime(item.created_at)}</span>
                    </td>
                    {/* User */}
                    <td className="px-4 py-3 max-w-[240px]">
                      {item.user_id ? (
                        <button
                          onClick={() => item.user_id && fetchSummary(item.user_id)}
                          className="text-left group min-w-0 w-full"
                          title="Xem tóm tắt user"
                        >
                          <p className={`${admin.cellName} group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors truncate`}>
                            {item.user_email ?? item.user_id}
                          </p>
                          {showDisplay && (
                            <p className={`${admin.cellSub} truncate`} title={item.user_display_name ?? undefined}>
                              {displayName}
                            </p>
                          )}
                        </button>
                      ) : (
                        <span className={text.muted}>—</span>
                      )}
                    </td>
                    {/* Type badge */}
                    <td className="px-4 py-3">
                      <span className={typeBadge(item.type)}>
                        {t(`admin.activity.type${item.type.charAt(0).toUpperCase() + item.type.slice(1)}` as Parameters<typeof t>[0])}
                      </span>
                    </td>
                    {/* Detail */}
                    <td className="px-4 py-3 max-w-[260px]">
                      <span
                        className={`block truncate text-xs font-mono ${text.secondary}`}
                        title={item.detail}
                      >
                        {item.detail || "—"}
                      </span>
                    </td>
                    {/* IP */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={`text-xs font-mono ${text.muted}`}>{item.ip_address ?? "—"}</span>
                    </td>
                    {/* Size */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={admin.cellMeta}>{fmtBytes(item.size_bytes)}</span>
                    </td>
                    {/* Status */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      {item.status_code ? (
                        <span className={statusBadge(item.status_code)}>{item.status_code}</span>
                      ) : (
                        <span className={text.muted}>—</span>
                      )}
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
        )}

        {/* Pagination footer */}
        {data && data.total > 0 && (
          <div className={`flex items-center justify-between px-4 py-3 border-t border-slate-100 dark:border-white/[0.06]`}>
            <span className={`text-xs ${text.muted}`}>
              {t("admin.activity.total").replace("{total}", String(data.total))}
              {" · "}
              {t("admin.activity.page")
                .replace("{page}", String(data.page))
                .replace("{pages}", String(data.pages))}
            </span>
            <div className="flex gap-2">
              <button
                disabled={!data.has_prev || loading}
                onClick={() => setPage((p) => p - 1)}
                className={`${btn.secondary} h-7 text-xs px-3`}
              >
                {t("admin.activity.prev")}
              </button>
              <button
                disabled={!data.has_next || loading}
                onClick={() => setPage((p) => p + 1)}
                className={`${btn.secondary} h-7 text-xs px-3`}
              >
                {t("admin.activity.next")}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2.5 dark:border-white/[0.08] dark:bg-white/[0.03]">
      <p className={`text-[10px] font-semibold uppercase tracking-wider ${text.muted} mb-1`}>{label}</p>
      <p className={`text-base font-bold tabular-nums ${text.primary}`}>{value}</p>
    </div>
  );
}
