import { useCallback, useEffect, useMemo, useState } from "react";
import api from "../utils/api";
import { useDraftState } from "../hooks/useDraftState";

const ADMIN_TOKEN_PAGE_KEY = "admin-token-security";
import PageLoader, { LoadingSpinner } from "../components/LoadingSpinner";

import { admin, surfaceCard } from "../styles/theme";
import { useT } from "../i18n/context";

const RISK_BADGE: Record<string, string> = {
  low:
    "bg-slate-900 text-emerald-200 ring-1 ring-slate-600 dark:bg-emerald-500/15 dark:text-emerald-300 dark:ring-emerald-500/25",
  medium:
    "bg-slate-900 text-amber-200 ring-1 ring-slate-600 dark:bg-amber-500/15 dark:text-amber-300 dark:ring-amber-500/25",
  high:
    "bg-slate-900 text-orange-200 ring-1 ring-slate-600 dark:bg-orange-500/15 dark:text-orange-300 dark:ring-orange-500/25",
  critical:
    "bg-slate-900 text-rose-200 ring-1 ring-slate-600 dark:bg-rose-500/15 dark:text-rose-300 dark:ring-rose-500/25",
};

const REC_BADGE: Record<string, string> = {
  ALLOW:
    "bg-slate-900 text-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-400",
  MONITOR:
    "bg-slate-900 text-amber-200 dark:bg-amber-500/10 dark:text-amber-400",
  REVIEW:
    "bg-slate-900 text-rose-200 dark:bg-rose-500/10 dark:text-rose-400",
  REVOKE:
    "bg-slate-900 text-rose-200 dark:bg-rose-500/10 dark:text-rose-400",
};

function RiskBadge({ level }: { level: string }) {
  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${RISK_BADGE[level] ?? RISK_BADGE.medium}`}>
      {level}
    </span>
  );
}

function RecBadge({ rec }: { rec: string }) {
  return (
    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${REC_BADGE[rec] ?? REC_BADGE.MONITOR}`}>
      {rec}
    </span>
  );
}

const BEHAVIOR_BADGE: Record<string, string> = {
  high: "bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/25",
  medium: "bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/25",
  low: "bg-slate-500/15 text-slate-300 ring-1 ring-slate-500/20",
};

const AGREEMENT_BADGE: Record<string, string> = {
  agree: "bg-emerald-500/10 text-emerald-300",
  partial: "bg-amber-500/10 text-amber-300",
  disagree: "bg-rose-500/10 text-rose-300",
};

function BehaviorBadge({ label, severity }: { label: string; severity?: string }) {
  const cls = BEHAVIOR_BADGE[severity ?? "medium"] ?? BEHAVIOR_BADGE.medium;
  return (
    <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${cls}`}>
      {label}
    </span>
  );
}

function AgreementBadge({ status, label }: { status: string; label: string }) {
  return (
    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${AGREEMENT_BADGE[status] ?? AGREEMENT_BADGE.partial}`}>
      {label}
    </span>
  );
}

// ── Types ──────────────────────────────────────────────────────────────────────

interface TokenMetric {
  token_id: string;
  token_type: "jwt" | "sas";
  user_id?: string;
  email?: string | null;
  role?: string | null;
  blob_name?: string;
  risk_score: number;
  risk_level: string;
  recommendation: string;
  reasons: string[];
  active_sessions?: number;
  ip_count: number;
  accesses_per_hour?: number;
  downloads_per_hour?: number;
  token_age_hours: number;
  is_revoked?: boolean;
  is_expired?: boolean;
}

interface Overview {
  generated_at: string;
  jwt: { active: number; revoked: number; expired: number; total: number };
  sas: { active: number; revoked: number; expired: number; total: number };
  risk_summary: {
    high_risk_tokens: number;
    critical_tokens: number;
    auto_revoke_candidates: number;
    access_events_24h: number;
  };
  config: {
    access_token_ttl_minutes: number;
    refresh_token_ttl_days: number;
    auto_revoke_score_threshold: number;
  };
  top_risk_tokens?: TokenMetric[];
}

interface AiHealth {
  ready: boolean;
  realtime_enabled?: boolean;
  mode?: "local" | "remote";
  ai_url?: string;
  version?: string;
  trained_at?: string;
  metrics?: {
    accuracy?: number;
    f1?: number;
    roc_auc?: number;
    precision?: number;
    recall?: number;
    train_size?: number;
  };
  error?: string;
  ai_dir?: string;
  hint?: string;
}

interface ShapFeature {
  feature: string;
  impact: number;
  direction: string;
}

interface BehaviorBadgeData {
  id: string;
  label: string;
  severity: string;
}

interface RuleAiAgreement {
  status: string;
  label: string;
  rule_level?: string;
  ai_level?: string;
  delta?: number;
}

interface AiTokenResult {
  token_id?: string;
  token_type?: string;
  subject_label?: string;
  email?: string | null;
  blob_name?: string | null;
  role?: string | null;
  file_id?: string | null;
  risk_score_pct: number;
  risk_score_raw: number;
  risk_level: string;
  ai_level_raw: string;
  decision: string;
  ai_decision?: string;
  is_attack: boolean;
  rule_score?: number;
  rule_level?: string;
  rule_recommendation?: string;
  rule_reasons?: string[];
  active_sessions?: number;
  access_count?: number;
  ip_count?: number;
  accesses_per_hour?: number;
  downloads_per_hour?: number;
  token_age_hours?: number;
  is_revoked?: boolean;
  is_expired?: boolean;
  source?: string;
  requires_admin_action?: boolean;
  overridden_by_rule?: boolean;
  behavior_badges?: BehaviorBadgeData[];
  summary_vi?: string;
  agreement?: RuleAiAgreement;
  explanation: {
    summary: string;
    summary_vi?: string;
    top_features: ShapFeature[];
  };
  error?: string;
}

type JobStatus = "pending" | "running" | "completed" | "failed";

interface AiAnalysisJob {
  job_id: string;
  triggered_by?: string | null;
  token_type: string;
  total_tokens: number;
  analyzed_count: number;
  skipped_cached: number;
  failed_count: number;
  status: JobStatus;
  error_message?: string | null;
  progress_pct: number;
  result_summary?: {
    total_requested: number;
    skipped_recent: number;
    skipped_benign?: number;
    skipped_cache: number;
    ai_analyzed: number;
    failed: number;
    saved_snapshots: number;
    high_risk_count?: number;
    revoke_recommendations?: number;
  } | null;
  created_at?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  snapshots?: AiSnapshotRow[];
  snapshots_total?: number;
  snapshots_total_available?: number;
  snapshots_truncated?: boolean;
}

interface AiSnapshotRow {
  id: string;
  token_type: string;
  token_ref: string;
  user_id?: string | null;
  subject_label?: string;
  email?: string | null;
  blob_name?: string | null;
  role?: string | null;
  file_id?: string | null;
  rule_score: number;
  rule_level?: string;
  rule_recommendation?: string;
  rule_reasons?: string[];
  ai_score_pct: number;
  ai_level: string;
  decision: string;
  active_sessions?: number;
  access_count?: number;
  ip_count?: number;
  accesses_per_hour?: number;
  downloads_per_hour?: number;
  token_age_hours?: number;
  is_revoked?: boolean;
  is_expired?: boolean;
  source: string;
  created_at: string;
}

type Tab = "overview" | "tokens" | "ai-report" | "trends" | "files";

interface SecurityAlert {
  id: string;
  token_type: string;
  file_id?: string | null;
  file_name?: string | null;
  subject_label?: string;
  rule_score: number;
  ai_score_pct: number;
  decision: string;
  agreement_status?: string;
  behavior_badges?: BehaviorBadgeData[];
  summary_vi?: string;
  is_read: boolean;
  created_at: string;
}

interface TrendData {
  days: number;
  labels: string[];
  access_events: number[];
  ai_alerts: number[];
  ai_high_scores: number[];
  rule_ai_disagree: number[];
  totals: Record<string, number>;
}

interface TopFileRow {
  file_id: string | null;
  file_name: string;
  downloads: number;
  unique_ips: number;
  unique_users: number;
  active_sas_links: number;
  ai_alerts: number;
  suspicious: boolean;
  owner_email?: string | null;
  owner_email_valid?: boolean;
  owner_id?: string | null;
  storage_mode?: string | null;
}

interface TopUploadFileRow {
  file_id: string | null;
  file_name: string;
  uploads: number;
  unique_ips: number;
  unique_users: number;
  total_bytes: number;
  owner_email?: string | null;
  owner_email_valid?: boolean;
  owner_id?: string | null;
  storage_mode?: string | null;
}

interface FileActivityData {
  days: number;
  labels: string[];
  summary: {
    uploads: number;
    downloads: number;
    unique_files_downloaded: number;
    unique_files_uploaded?: number;
    suspicious_files: number;
  };
  trend: {
    uploads_per_day: number[];
    downloads_per_day: number[];
  };
  top_file_trends: { file_id: string; file_name: string; downloads_per_day: number[] }[];
  top_upload_file_trends?: { file_id: string; file_name: string; uploads_per_day: number[] }[];
  top_files: TopFileRow[];
  top_upload_files?: TopUploadFileRow[];
}

interface FileDetailData {
  file_id: string;
  file_name: string;
  owner_email?: string | null;
  owner_email_valid?: boolean;
  owner_id?: string | null;
  storage_mode?: string | null;
  file_size_bytes: number;
  created_at: string;
  stats: {
    downloads: number;
    uploads: number;
    unique_ips: number;
    active_sas_links: number;
    suspicious: boolean;
  };
  recent_downloads: { user_id?: string | null; ip_address?: string | null; created_at: string }[];
  recent_uploads?: {
    user_id?: string | null;
    ip_address?: string | null;
    upload_type?: string;
    file_size_bytes?: number;
    created_at: string;
  }[];
  recent_alerts: { id: string; ai_score_pct: number; decision: string; summary_vi?: string; created_at: string }[];
}

function MiniBarChart({
  labels,
  series,
  colorClass,
  emptyLabel,
}: {
  labels: string[];
  series: number[];
  colorClass: string;
  emptyLabel: string;
}) {
  const max = Math.max(1, ...series);
  const hasData = series.some((v) => v > 0);

  if (!hasData) {
    return (
      <div className="h-52 rounded-2xl border border-white/10 bg-slate-950/35 flex items-center justify-center text-center px-6">
        <div>
          <p className="text-sm font-medium text-slate-200 dark:text-white/80">{emptyLabel}</p>
          <p className="mt-1 text-xs text-slate-500 dark:text-white/35">
            {labels.length > 0 ? `${labels[0].slice(5)} → ${labels[labels.length - 1].slice(5)}` : ""}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-white/10 bg-slate-950/35 p-4">
      <div className="mb-3 flex items-center justify-between text-[11px]">
        <span className="text-slate-500 dark:text-white/35">Max</span>
        <span className="font-semibold text-slate-200 dark:text-white/80">{max}</span>
      </div>
      <div className="relative h-44">
        <div className="pointer-events-none absolute inset-0 flex flex-col justify-between">
          {[0, 1, 2, 3].map((line) => (
            <div key={line} className="border-t border-dashed border-white/8" />
          ))}
        </div>
        <div className="relative flex h-full items-end gap-2">
          {series.map((v, i) => (
            <div key={labels[i]} className="flex-1 flex flex-col items-center justify-end gap-2 min-w-0 h-full">
              <span className="text-[10px] font-medium text-slate-400 dark:text-white/45">{v || ""}</span>
              <div className="relative flex w-full flex-1 items-end">
                <div className="absolute inset-x-0 bottom-0 rounded-t-xl bg-white/[0.04]" />
                <div
                  className={`relative w-full rounded-t-xl ${colorClass} shadow-[0_0_18px_rgba(59,130,246,0.18)] transition-all`}
                  style={{ height: `${Math.max(8, (v / max) * 100)}%` }}
                  title={`${labels[i]}: ${v}`}
                />
              </div>
              <span className="text-[10px] text-slate-500 dark:text-white/28 truncate w-full text-center">
                {labels[i].slice(5)}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────────────────────

export default function AdminTokenSecurityPage() {
  const t = useT();
  const [activeTab, setActiveTab] = useDraftState<Tab>(
    ADMIN_TOKEN_PAGE_KEY,
    "activeTab",
    "overview"
  );
  const [loading, setLoading] = useState(true);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [aiHealth, setAiHealth] = useState<AiHealth | null>(null);
  const [aiHealthLoading, setAiHealthLoading] = useState(false);

  const [tokens, setTokens] = useState<TokenMetric[]>([]);
  const [tokensLoading, setTokensLoading] = useState(false);
  const [tokenType, setTokenType] = useDraftState<"all" | "jwt" | "sas">(
    ADMIN_TOKEN_PAGE_KEY,
    "tokenType",
    "all"
  );

  const [aiResults, setAiResults] = useState<AiTokenResult[]>([]);
  const [aiRuleMetrics, setAiRuleMetrics] = useState<TokenMetric[]>([]);
  const [aiError, setAiError] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [savedReports, setSavedReports] = useState<AiAnalysisJob[]>([]);
  const [savedReportsLoading, setSavedReportsLoading] = useState(false);
  const [selectedReportJobId, setSelectedReportJobId] = useState<string | null>(null);
  const [selectedReportMeta, setSelectedReportMeta] = useState<AiAnalysisJob | null>(null);
  const [reportDetailLoading, setReportDetailLoading] = useState<string | null>(null);

  const [_activeJobId, setActiveJobId] = useState<string | null>(null);
  const [activeJob, setActiveJob] = useState<AiAnalysisJob | null>(null);
  const [jobPollTimer, setJobPollTimer] = useState<number | null>(null);

  const [busyId, setBusyId] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ type: "ok" | "err"; msg: string } | null>(null);

  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [unreadAlerts, setUnreadAlerts] = useState(0);
  const [trends, setTrends] = useState<TrendData | null>(null);
  const [trendsLoading, setTrendsLoading] = useState(false);

  const [fileActivity, setFileActivity] = useState<FileActivityData | null>(null);
  const [fileActivityLoading, setFileActivityLoading] = useState(false);
  const [fileDetail, setFileDetail] = useState<FileDetailData | null>(null);
  const [fileDetailLoading, setFileDetailLoading] = useState(false);
  const [notifyOwnerBusy, setNotifyOwnerBusy] = useState(false);
  const [modelInfoOpen, setModelInfoOpen] = useState(false);
  const [aiFilterType, setAiFilterType] = useState<"all" | "jwt" | "sas">("all");
  const [aiFilterDecision, setAiFilterDecision] = useState<
    "all" | "ALLOW" | "MONITOR" | "REVIEW" | "REVOKE" | "needs_review" | "disagree"
  >("all");
  const [aiFilterQuery, setAiFilterQuery] = useState("");

  const flash = (type: "ok" | "err", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 5000);
  };

  // ── Load overview LIGHT (counts + risk_summary) + lazy top_risk ─────────────

  const loadTopRisk = useCallback(async () => {
    try {
      const res = await api.get<{
        top_risk_tokens: TokenMetric[];
        high_risk_tokens?: number;
        critical_tokens?: number;
        auto_revoke_candidates?: number;
      }>("/auth/admin/token-security/overview/top-risk");
      setOverview((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          top_risk_tokens: res.data.top_risk_tokens ?? [],
          risk_summary: {
            ...prev.risk_summary,
            high_risk_tokens:
              res.data.high_risk_tokens ?? prev.risk_summary.high_risk_tokens,
            critical_tokens:
              res.data.critical_tokens ?? prev.risk_summary.critical_tokens,
            auto_revoke_candidates:
              res.data.auto_revoke_candidates ??
              prev.risk_summary.auto_revoke_candidates,
          },
        };
      });
    } catch {
      /* optional — top risk là optional feature */
    }
  }, []);

  const loadOverview = useCallback(async (opts?: { skipCache?: boolean }) => {
    try {
      setLoading(true);
      const res = await api.get<{ overview: Overview }>(
        `/auth/admin/token-security/overview?skip_cache=${opts?.skipCache ? "1" : "0"}`
      );
      setOverview(res.data.overview);
      // Ngay sau khi overview render KPI → chạy lazy load top_risk + các phần nặng
      window.setTimeout(() => void loadTopRisk(), 30);
      window.setTimeout(() => void loadAiHealth(), 50);
    } catch {
      flash("err", t("admin.tokenSecurity.loadFailed"));
    } finally {
      // Tắt loading ngay sau khi có counts (không chờ top_risk / AI health heavy)
      setLoading(false);
    }
  }, [loadTopRisk]);

  useEffect(() => { void loadOverview(); }, [loadOverview]);

  // ── Load AI health ──────────────────────────────────────────────────────────

  const loadAiHealth = useCallback(async () => {
    setAiHealthLoading(true);
    try {
      const res = await api.get<AiHealth>("/auth/admin/token-security/ai/health");
      setAiHealth(res.data);
    } catch {
      setAiHealth({ ready: false, error: t("admin.tokenSecurity.backendFailed") });
    } finally {
      setAiHealthLoading(false);
    }
  }, []);

  useEffect(() => { void loadAiHealth(); }, [loadAiHealth]);

  const loadAlerts = useCallback(async () => {
    try {
      const res = await api.get<{ alerts: SecurityAlert[]; unread_count: number }>(
        "/auth/admin/token-security/alerts?limit=15"
      );
      setAlerts(res.data.alerts ?? []);
      setUnreadAlerts(res.data.unread_count ?? 0);
    } catch {
      /* optional */
    }
  }, []);

  const mapSnapshotToAiResult = (s: AiSnapshotRow): AiTokenResult => ({
    token_id: s.token_ref,
    token_type: s.token_type as "jwt" | "sas",
    subject_label: s.subject_label,
    email: s.email,
    blob_name: s.blob_name,
    role: s.role,
    file_id: s.file_id,
    risk_score_pct: s.ai_score_pct,
    risk_score_raw: s.ai_score_pct / 100,
    risk_level: s.ai_level,
    ai_level_raw: s.ai_level,
    decision: s.decision,
    ai_decision: undefined,
    is_attack: s.ai_score_pct >= 50,
    rule_score: s.rule_score,
    rule_level: s.rule_level,
    rule_recommendation: s.rule_recommendation,
    rule_reasons: s.rule_reasons,
    active_sessions: s.active_sessions,
    access_count: s.access_count,
    ip_count: s.ip_count,
    accesses_per_hour: s.accesses_per_hour,
    downloads_per_hour: s.downloads_per_hour,
    token_age_hours: s.token_age_hours,
    is_revoked: s.is_revoked,
    is_expired: s.is_expired,
    source: s.source,
    requires_admin_action: s.decision === "REVIEW",
    overridden_by_rule: s.decision === "REVIEW" && s.rule_recommendation === "REVOKE",
    behavior_badges: [],
    agreement: undefined,
    explanation: { summary: "", top_features: [], summary_vi: s.source },
  });

  const upsertSavedReport = useCallback((job: AiAnalysisJob) => {
    setSavedReports((prev) => {
      const merged = [job, ...prev.filter((item) => item.job_id !== job.job_id)];
      merged.sort((a, b) => {
        const ta = new Date(a.created_at ?? 0).getTime();
        const tb = new Date(b.created_at ?? 0).getTime();
        return tb - ta;
      });
      return merged;
    });
  }, []);

  const applySavedReport = useCallback((job: AiAnalysisJob) => {
    const decisionRank = (d?: string) => {
      const x = (d ?? "").toUpperCase();
      if (x === "REVOKE") return 0;
      if (x === "REVIEW") return 1;
      if (x === "MONITOR") return 2;
      return 3;
    };
    const snapshots = [...(job.snapshots ?? [])].sort((a, b) => {
      const rd = decisionRank(a.decision) - decisionRank(b.decision);
      if (rd !== 0) return rd;
      return (b.ai_score_pct ?? 0) - (a.ai_score_pct ?? 0);
    });
    setSelectedReportJobId(job.job_id);
    setSelectedReportMeta(job);
    setAiRuleMetrics([]);
    setAiResults(snapshots.map(mapSnapshotToAiResult));
    setAiError(null);
    // Ưu tiên hiện Needs Review khi report bị cắt limit
    if (job.snapshots_truncated) {
      setAiFilterDecision("needs_review");
    }
  }, []);

  const loadSavedReport = useCallback(async (jobId: string) => {
    setReportDetailLoading(jobId);
    try {
      // Ưu tiên tải tối đa (BE le=5000); fallback nếu BE cũ.
      const limits = [5000, 2000, 500, 200];
      let lastErr: unknown = null;
      for (const limit of limits) {
        try {
          const res = await api.get<AiAnalysisJob>(
            `/auth/admin/token-security/ai/jobs/${jobId}`,
            { params: { include_details: true, snapshots_limit: limit } }
          );
          applySavedReport(res.data);
          return;
        } catch (err: unknown) {
          lastErr = err;
          const status = (err as { response?: { status?: number } })?.response?.status;
          // 422 = query param ngoài bound (snapshots_limit) → thử limit thấp hơn
          if (status === 422 && limit !== limits[limits.length - 1]) continue;
          break;
        }
      }
      const detail =
        (lastErr as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      const detailText =
        typeof detail === "string"
          ? detail
          : Array.isArray(detail)
            ? detail.map((d: { msg?: string }) => d?.msg).filter(Boolean).join("; ")
            : null;
      setAiError(
        detailText
          ? `Không tải được report đã lưu: ${detailText}`
          : "Không tải được report đã lưu."
      );
    } finally {
      setReportDetailLoading(null);
    }
  }, [applySavedReport]);

  const loadSavedReports = useCallback(async (preferredJobId?: string | null) => {
    setSavedReportsLoading(true);
    try {
      const res = await api.get<{ jobs: AiAnalysisJob[] }>("/auth/admin/token-security/ai/jobs?limit=20");
      const completedJobs = (res.data.jobs ?? []).filter((job) => job.status === "completed");
      setSavedReports(completedJobs);

      const preferredJob = preferredJobId
        ? completedJobs.find((job) => job.job_id === preferredJobId)
        : null;

      if (preferredJobId) {
        if (preferredJob) {
          void loadSavedReport(preferredJob.job_id);
        }
        return;
      }

      const jobToOpen =
        (selectedReportJobId && completedJobs.find((job) => job.job_id === selectedReportJobId)) ??
        completedJobs[0];

      if (jobToOpen) {
        void loadSavedReport(jobToOpen.job_id);
      } else {
        setSelectedReportJobId(null);
        setSelectedReportMeta(null);
        setAiResults([]);
      }
    } catch {
      setAiError("Không tải được danh sách report đã lưu.");
    } finally {
      setSavedReportsLoading(false);
    }
  }, [loadSavedReport, selectedReportJobId]);

  useEffect(() => {
    if (activeTab === "ai-report") {
      void loadSavedReports();
    }
  }, [activeTab, loadSavedReports]);

  useEffect(() => {
    if (aiHealth?.realtime_enabled === false) return;
    if (aiHealth == null) return;
    void loadAlerts();
    const t = setInterval(() => void loadAlerts(), 30_000);
    return () => clearInterval(t);
  }, [loadAlerts, aiHealth?.realtime_enabled]);

  const loadTrends = useCallback(async () => {
    setTrendsLoading(true);
    try {
      const res = await api.get<TrendData>("/auth/admin/token-security/ai/trends?days=7");
      setTrends(res.data);
    } catch {
      flash("err", t("admin.tokenSecurity.trendFailed"));
    } finally {
      setTrendsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "trends") void loadTrends();
  }, [activeTab, loadTrends]);

  const loadFileActivity = useCallback(async () => {
    setFileActivityLoading(true);
    try {
      const res = await api.get<FileActivityData>(
        "/auth/admin/token-security/files/activity?days=7&limit=20"
      );
      setFileActivity(res.data);
    } catch {
      flash("err", t("admin.tokenSecurity.fileActivityFailed"));
    } finally {
      setFileActivityLoading(false);
    }
  }, []);

  const loadFileDetail = useCallback(async (fileId: string) => {
    setFileDetailLoading(true);
    try {
      const res = await api.get<FileDetailData>(
        `/auth/admin/token-security/files/${fileId}/activity?days=7`
      );
      setFileDetail(res.data);
    } catch {
      flash("err", t("admin.tokenSecurity.fileDetailFailed"));
      setFileDetail(null);
    } finally {
      setFileDetailLoading(false);
    }
  }, []);

  const notifyFileOwner = useCallback(async (fileId: string) => {
    setNotifyOwnerBusy(true);
    try {
      const res = await api.post<{
        owner_email?: string;
        email_sent?: boolean;
      }>(`/auth/admin/token-security/files/${fileId}/notify-owner`);
      const email = res.data.owner_email;
      flash(
        "ok",
        res.data.email_sent && email
          ? t("admin.notifySentEmail", { email })
          : t("admin.notifySent")
      );
    } catch (e) {
      const msg =
        (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        t("admin.notifyFailed");
      flash("err", msg);
    } finally {
      setNotifyOwnerBusy(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "files") {
      void loadFileActivity();
      setFileDetail(null);
    }
  }, [activeTab, loadFileActivity]);

  const openFileTab = (fileId: string) => {
    setActiveTab("files");
    void loadFileDetail(fileId);
  };

  const markAlertRead = async (id: string) => {
    try {
      await api.post(`/auth/admin/token-security/alerts/${id}/read`);
      void loadAlerts();
    } catch {
      flash("err", t("admin.tokenSecurity.alertUpdateFailed"));
    }
  };

  const markAllAlertsRead = async () => {
    try {
      await api.post("/auth/admin/token-security/alerts/read-all");
      void loadAlerts();
    } catch {
      flash("err", t("admin.tokenSecurity.alertUpdateFailed"));
    }
  };

  // ── Load token list ─────────────────────────────────────────────────────────

  const loadTokens = useCallback(async (type: "all" | "jwt" | "sas" = tokenType) => {
    setTokensLoading(true);
    try {
      const res = await api.get<{ tokens: TokenMetric[] }>(
        `/auth/admin/token-security/tokens?token_type=${type}`
      );
      setTokens(res.data.tokens);
    } catch {
      flash("err", t("admin.tokenSecurity.tokenListFailed"));
    } finally {
      setTokensLoading(false);
    }
  }, [tokenType]);

  useEffect(() => {
    if (activeTab === "tokens") void loadTokens();
  }, [activeTab, loadTokens]);

  // ── AI analysis ─────────────────────────────────────────────────────────────

  const aiRuleByTokenId = useMemo(() => {
    const map = new Map<string, TokenMetric>();
    for (const m of aiRuleMetrics) {
      if (m.token_id) map.set(m.token_id, m);
    }
    return map;
  }, [aiRuleMetrics]);

  const filteredAiResults = useMemo(() => {
    const q = aiFilterQuery.trim().toLowerCase();
    return aiResults.filter((r) => {
      const type = (r.token_type ?? "jwt").toLowerCase();
      if (aiFilterType !== "all" && type !== aiFilterType) return false;

      const decision = (r.decision ?? "").toUpperCase();
      if (aiFilterDecision === "needs_review") {
        if (decision !== "REVIEW" && decision !== "REVOKE") return false;
      } else if (aiFilterDecision === "disagree") {
        if (r.agreement?.status !== "disagree") return false;
      } else if (aiFilterDecision !== "all") {
        if (decision !== aiFilterDecision) return false;
      }

      if (!q) return true;
      const haystack = [
        r.subject_label,
        r.email,
        r.blob_name,
        r.file_id,
        r.token_id,
        r.role,
        r.decision,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [aiResults, aiFilterType, aiFilterDecision, aiFilterQuery]);

  const aiFilterCounts = useMemo(() => {
    const jwt = aiResults.filter((r) => (r.token_type ?? "jwt") === "jwt").length;
    const sas = aiResults.filter((r) => r.token_type === "sas").length;
    const byDecision = {
      ALLOW: 0,
      MONITOR: 0,
      REVIEW: 0,
      REVOKE: 0,
    };
    let disagree = 0;
    for (const r of aiResults) {
      const d = (r.decision ?? "").toUpperCase() as keyof typeof byDecision;
      if (d in byDecision) byDecision[d] += 1;
      if (r.agreement?.status === "disagree") disagree += 1;
    }
    return {
      jwt,
      sas,
      ...byDecision,
      needs_review: byDecision.REVIEW + byDecision.REVOKE,
      disagree,
    };
  }, [aiResults]);

  const exportAiCsv = () => {
    const rowsSrc = filteredAiResults.length ? filteredAiResults : aiResults;
    if (!rowsSrc.length) return;
    const header = [
      "token_id", "token_type", "email", "rule_score", "rule_level", "rule_rec",
      "ai_score_pct", "ai_level", "decision", "agreement", "behaviors", "summary_vi",
    ];
    const rows = rowsSrc.map((r) => {
      const rule = r.token_id ? aiRuleByTokenId.get(r.token_id) : undefined;
      const esc = (v: string | number | undefined) => {
        const s = String(v ?? "");
        return s.includes(",") || s.includes('"') ? `"${s.replace(/"/g, '""')}"` : s;
      };
      return [
        r.token_id, r.token_type, r.email ?? rule?.email ?? "",
        r.rule_score ?? rule?.risk_score, r.rule_level ?? rule?.risk_level, r.rule_recommendation ?? rule?.recommendation,
        r.risk_score_pct, r.ai_level_raw, r.decision,
        r.agreement?.label ?? "", (r.behavior_badges ?? []).map((b) => b.label).join("; "),
        r.summary_vi ?? r.explanation?.summary_vi ?? "",
      ].map(esc).join(",");
    });
    const blob = new Blob([header.join(",") + "\n" + rows.join("\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `locksend-ai-report-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const runAiAnalyze = async (forceAll: boolean = false) => {
    setAnalyzing(true);
    setAiResults([]);
    setAiRuleMetrics([]);
    setAiError(null);
    setSelectedReportMeta(null);
    setActiveJob(null);
    try {
      const res = await api.post<{
        job_id: string;
        status: JobStatus;
        total_tokens: number;
        message: string;
        poll_url: string;
      }>("/auth/admin/token-security/ai/analyze", {
        token_type: "all",
        skip_recent: !forceAll,
        force_all: forceAll,
      });
        const { job_id, total_tokens, status } = res.data;
        const queuedJob: AiAnalysisJob = {
          job_id,
          token_type: "all",
          total_tokens,
          analyzed_count: 0,
          skipped_cached: 0,
          failed_count: 0,
          status,
          progress_pct: 0,
          result_summary: null,
          created_at: new Date().toISOString(),
          snapshots: [],
        };
        setSelectedReportJobId(job_id);
        setSelectedReportMeta(queuedJob);
        upsertSavedReport(queuedJob);
      setActiveJobId(job_id);
      flash("ok", t("admin.tokenSecurity.jobStarted") ?? `Job ${job_id.slice(0, 8)} started…`);
      void pollJob(job_id);
    } catch {
      setAiError(t("admin.tokenSecurity.aiAnalyzeFailed"));
      setAnalyzing(false);
      setActiveJobId(null);
    }
  };

  const pollJob = useCallback(
    async (jobId: string) => {
      try {
        // Poll chỉ lấy tiến trình — snapshot chi tiết được nạp 1 lần khi job xong.
        const res = await api.get<AiAnalysisJob>(
          `/auth/admin/token-security/ai/jobs/${jobId}`,
          { params: { include_details: false } }
        );
        const job = res.data;
        setActiveJob(job);
        if (job.status === "completed") {
          upsertSavedReport(job);
          setSelectedReportJobId(job.job_id);
          setSelectedReportMeta(job);
          void loadSavedReports(jobId);
          setActiveTab("ai-report");
          const summary = job.result_summary;
          const countOk = summary?.ai_analyzed ?? job.analyzed_count;
          const skipped = summary?.skipped_benign ?? summary?.skipped_recent ?? job.skipped_cached;
          
          if (skipped > 0) {
              flash("ok", `Analyzed ${countOk} tokens. Skipped ${skipped} previously-benign tokens.`);
          } else {
            flash("ok", t("admin.tokenSecurity.aiAnalyzed", { count: countOk }) ?? `Analyzed ${countOk} tokens successfully.`);
          }
          
          setAnalyzing(false);
          setActiveJobId(null);
          return;
        }
        if (job.status === "failed") {
          setAiError(
            job.error_message ?? (t("admin.tokenSecurity.aiAnalyzeFailed") as string)
          );
          setAnalyzing(false);
          setActiveJobId(null);
          return;
        }
        const timer = window.setTimeout(() => void pollJob(jobId), 1500);
        setJobPollTimer((prev) => {
          if (prev) window.clearTimeout(prev);
          return timer;
        });
      } catch {
        setAiError(t("admin.tokenSecurity.aiAnalyzeFailed"));
        setAnalyzing(false);
        setActiveJobId(null);
      }
    },
    [loadSavedReports, t, upsertSavedReport]
  );

  useEffect(() => {
    return () => {
      if (jobPollTimer) window.clearTimeout(jobPollTimer);
    };
  }, [jobPollTimer]);

  // ── Actions ─────────────────────────────────────────────────────────────────

  const revokeJwt = async (userId: string, email: string | null) => {
    if (!confirm(t("admin.tokenSecurity.revokeJwtConfirm", { email: email ?? userId }))) return;
    setBusyId(userId);
    try {
      const res = await api.post<{ revoked_sessions: number }>(
        `/auth/admin/token-security/revoke/jwt/${userId}`,
        { reason: "Admin manual revoke" }
      );
      flash("ok", t("admin.tokenSecurity.revokeJwtOk", { count: res.data.revoked_sessions }));
      void loadOverview({ skipCache: true });
    } catch {
      flash("err", t("admin.tokenSecurity.revokeJwtFailed"));
    } finally {
      setBusyId(null);
    }
  };

  const revokeSas = async (tokenId: string) => {
    if (!confirm(`Soft-revoke SAS token ${tokenId.slice(0, 8)}…?`)) return;
    setBusyId(tokenId);
    try {
      await api.post(`/auth/admin/token-security/revoke/sas/${tokenId}`, {
        reason: "Admin manual revoke",
      });
      flash("ok", t("admin.tokenSecurity.revokeSasOk"));
      void loadTokens();
    } catch {
      flash("err", t("admin.tokenSecurity.revokeSasFailed"));
    } finally {
      setBusyId(null);
    }
  };

  const triggerAutoRevoke = async () => {
    if (!confirm(t("admin.tokenSecurity.autoRevokeConfirm"))) return;
    try {
      const res = await api.post<{ revoked_jwt_sessions: number; revoked_sas_tokens: number }>(
        "/auth/admin/token-security/auto-revoke"
      );
      flash("ok", `Auto-revoke: ${res.data.revoked_jwt_sessions} JWT, ${res.data.revoked_sas_tokens} SAS`);
      void loadOverview({ skipCache: true });
    } catch {
      flash("err", t("admin.tokenSecurity.autoRevokeFailed"));
    }
  };

  const cleanup = async () => {
    try {
      const res = await api.post<{ deleted_sas_records: number; deleted_access_logs: number }>(
        "/auth/admin/token-security/cleanup"
      );
      flash("ok", t("admin.tokenSecurity.cleanupOk", {
        sas: res.data.deleted_sas_records,
        logs: res.data.deleted_access_logs,
      }));
    } catch {
      flash("err", t("admin.tokenSecurity.cleanupFailed"));
    }
  };

  // ── Render ──────────────────────────────────────────────────────────────────

  if (loading && !overview) {
    return <PageLoader title={t("admin.tokenSecurity.loading")} />;
  }

  const topRisk = overview?.top_risk_tokens ?? [];
  const aiReady = aiHealth?.ready === true;
  const visibleSavedReports =
    selectedReportMeta && !savedReports.some((job) => job.job_id === selectedReportMeta.job_id)
      ? [selectedReportMeta, ...savedReports]
      : savedReports;

  return (
    <div className="space-y-5">

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
        <div>
          <h2 className={admin.title}>Token Security</h2>
          <p className={admin.desc}>{t("admin.tokenSecurity.subtitle")}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void loadOverview({ skipCache: true })}
            disabled={loading}
            className={`${admin.btnGhost} disabled:opacity-40`}
          >
            {t("admin.refresh")}
          </button>
          <button type="button" onClick={triggerAutoRevoke}
            className="px-3 py-2 rounded-xl border border-rose-500/30 text-sm text-rose-400 hover:bg-rose-500/10 transition">
            Auto-revoke
          </button>
          <button type="button" onClick={cleanup} className={admin.btnGhost}>
            Cleanup
          </button>
        </div>
      </div>

      {/* Realtime alerts (chỉ khi LOCKSEND_AI_REALTIME_ENABLED=true) */}
      {aiHealth?.realtime_enabled !== false && unreadAlerts > 0 && (
        <div className={`${surfaceCard} px-5 py-4 border-amber-500/20`}>
          <div className="flex flex-wrap items-center gap-2 mb-3">
            <span className="text-sm font-semibold text-amber-300">
              {t("admin.tokenSecurity.realtimeAlerts", { count: unreadAlerts })}
            </span>
            <button
              type="button"
              onClick={() => void markAllAlertsRead()}
              className="ml-auto text-[11px] text-slate-400 hover:text-white"
            >
              {t("admin.tokenSecurity.markAllRead")}
            </button>
          </div>
          <ul className="space-y-2 max-h-48 overflow-y-auto">
            {alerts.filter((a) => !a.is_read).slice(0, 5).map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-2 text-xs">
                <span className="text-slate-700 dark:text-white/70 truncate max-w-[180px]">
                  {a.file_name ? (
                    a.file_id ? (
                      <button
                        type="button"
                        onClick={() => openFileTab(a.file_id!)}
                        className="text-sky-400 hover:underline truncate max-w-[180px] text-left"
                        title={a.file_name}
                      >
                        {a.file_name}
                      </button>
                    ) : (
                      a.file_name
                    )
                  ) : (
                    a.subject_label ?? a.id.slice(0, 8)
                  )}
                </span>
                {a.token_type === "sas" && a.file_name && (
                  <span className="text-[10px] text-slate-500">SAS</span>
                )}
                <span className="text-slate-500">Rule {a.rule_score} → AI {a.ai_score_pct}%</span>
                <RecBadge rec={a.decision} />
                {a.behavior_badges?.slice(0, 1).map((b) => (
                  <BehaviorBadge key={b.id} label={b.label} severity={b.severity} />
                ))}
                <button
                  type="button"
                  onClick={() => void markAlertRead(a.id)}
                  className="text-[10px] text-slate-500 hover:text-white ml-auto"
                >
                  {t("admin.tokenSecurity.markRead")}
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* AI analyzed banner (3-layer data source fallback)
          1. activeJob FAILED → red banner with error details
          2. activeJob RUNNING / COMPLETED → blue / emerald with job data
          3. NO activeJob but aiResults.length > 0 (PER-TOKEN = 94 đang hiện như ảnh user)
             → emerald with aiResults.length (đồng bộ với PER-TOKEN banner con bên dưới)
          4. NO activeJob + NO aiResults + NO feedback → hiện feedback (nếu có) */}
      {activeJob && activeJob.status === "failed" && (
        <div className="text-sm px-4 py-2.5 rounded-xl border text-rose-300 bg-rose-500/10 border-rose-500/20 whitespace-pre-wrap">
          ⚠️ {t("admin.tokenSecurity.jobFailed", {
            failed: activeJob.failed_count ?? 0,
            total: activeJob.result_summary?.total_requested ?? activeJob.total_tokens ?? 0,
            analyzed: activeJob.analyzed_count ?? 0,
          })}
          {activeJob.error_message && (
            <span className="block mt-1 text-xs text-rose-200/80 whitespace-pre-wrap">
              Chi tiết: {activeJob.error_message}
            </span>
          )}
        </div>
      )}
      {activeJob && activeJob.status !== "failed" && (
        <div className={`text-sm px-4 py-2.5 rounded-xl border ${
          activeJob.status === "completed"
            ? "text-emerald-300 bg-emerald-500/10 border-emerald-500/20"
            : "text-sky-300 bg-sky-500/10 border-sky-500/20"
        }`}>
          {activeJob.status === "completed"
            ? t("admin.tokenSecurity.aiAnalyzed", {
                count: activeJob.result_summary?.ai_analyzed ?? activeJob.analyzed_count ?? aiResults.length ?? 0,
              })
            : t("admin.tokenSecurity.jobAnalyzing", {
                analyzed: activeJob.analyzed_count,
                total: activeJob.total_tokens,
                skipped: activeJob.skipped_cached,
                pct: activeJob.progress_pct,
              })}
        </div>
      )}
      {!activeJob && aiResults.length > 0 && (
        <div className="text-sm px-4 py-2.5 rounded-xl border text-emerald-300 bg-emerald-500/10 border-emerald-500/20">
          {t("admin.tokenSecurity.aiAnalyzed", {
            count:
              selectedReportMeta?.result_summary?.ai_analyzed ??
              selectedReportMeta?.analyzed_count ??
              aiResults.length,
          })}
          {(selectedReportMeta?.result_summary?.ai_analyzed ??
            selectedReportMeta?.analyzed_count ??
            0) > aiResults.length
            ? ` · đang hiện ${aiResults.length} trong danh sách`
            : ""}
        </div>
      )}

      {/* Feedback (chỉ hiện khi KHÔNG có activeJob, KHÔNG có aiResults — tránh đè banner đồng bộ) */}
      {feedback && !activeJob && aiResults.length === 0 && (
        <p className={`text-sm px-4 py-2.5 rounded-xl border ${
          feedback.type === "ok"
            ? "text-emerald-300 bg-emerald-500/10 border-emerald-500/20"
            : "text-rose-300 bg-rose-500/10 border-rose-500/20"
        }`}>
          {feedback.msg}
        </p>
      )}

      {/* AI + Rule engine status banner */}
      <div className={`${surfaceCard} px-5 py-3.5 flex flex-wrap items-center gap-5`}>
        {/* LockSend AI status */}
        <div className="flex items-center gap-2.5">
          {aiHealthLoading ? (
            <LoadingSpinner size="sm" />
          ) : (
            <span className={`text-sm font-semibold ${aiReady ? "text-emerald-400" : "text-amber-400"}`}>
              {aiReady ? "● LockSend AI" : "○ LockSend AI"}
            </span>
          )}
          {aiHealth && (
            <span className="text-xs text-slate-600 dark:text-white/35">
              {aiReady
                ? `v${aiHealth.version ?? "?"} · ROC-AUC ${((aiHealth.metrics?.roc_auc ?? 0) * 100).toFixed(1)}%`
                : t("admin.tokenSecurity.modelNotReady")}
            </span>
          )}
        </div>

        <div className={`h-4 w-px ${admin.dividerLight}`} />

        {/* Rule engine */}
        <span className="text-sm font-medium text-indigo-700 dark:text-indigo-300">● Rule engine</span>
        <span className="text-xs text-slate-500 dark:text-white/30">
          {t("admin.tokenSecurity.autoRevokeThreshold", {
            score: overview?.config.auto_revoke_score_threshold ?? 80,
          })}
        </span>

        {/* Hint nếu AI chưa sẵn */}
        {aiHealth && !aiReady && (
          <span className="text-xs text-amber-300/60 ml-auto hidden sm:block">
            {aiHealth.hint ?? `cd ${aiHealth.ai_dir} && python train.py`}
          </span>
        )}
      </div>

      {/* Stat cards */}
      {overview && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "JWT Active",  value: overview.jwt.active,                     color: "text-indigo-400" },
            { label: "SAS Active",  value: overview.sas.active,                     color: "text-sky-400" },
            { label: "High Risk",   value: overview.risk_summary.high_risk_tokens,  color: "text-orange-400" },
            { label: "Access/24h",  value: overview.risk_summary.access_events_24h, color: "text-violet-400" },
          ].map(({ label, value, color }) => (
            <div key={label} className={`${surfaceCard} p-4 text-center`}>
              <p className={`text-2xl font-bold ${color}`}>{value}</p>
              <p className="text-[11px] text-slate-600 dark:text-white/35 uppercase tracking-wide mt-1">{label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className={`${surfaceCard} p-1.5 inline-flex gap-1`}>
        {(["overview", "tokens", "ai-report", "trends", "files"] as Tab[]).map((tabId) => (
          <button key={tabId} type="button" onClick={() => setActiveTab(tabId)}
            className={`px-4 py-2 rounded-xl text-[13px] font-medium transition ${
              activeTab === tabId ? admin.tabActive : admin.tabInactive
            }`}>
            {tabId === "overview"
              ? t("admin.tokenSecurity.tabOverview")
              : tabId === "tokens"
                ? t("admin.tokenSecurity.tabTokens")
                : tabId === "ai-report"
                  ? t("admin.tokenSecurity.tabAiReport")
                  : tabId === "trends"
                    ? t("admin.tokenSecurity.tabTrends")
                    : t("admin.tokenSecurity.tabFiles")}
          </button>
        ))}
      </div>

      {/* ── Tab: Overview ── */}
      {activeTab === "overview" && overview && (
        <div className="space-y-4">
          <div className="grid sm:grid-cols-2 gap-4">
            {/* JWT */}
            <div className={`${surfaceCard} p-5`}>
              <h3 className={`${admin.sectionTitle} mb-3`}>JWT / Refresh Tokens</h3>
              <div className="space-y-1.5 text-sm">
                {[
                  ["Active",  overview.jwt.active,  "text-indigo-400"],
                  ["Revoked", overview.jwt.revoked,  "text-rose-400"],
                  ["Expired", overview.jwt.expired,  "text-slate-600 dark:text-white/35"],
                  ["Total",   overview.jwt.total,    "text-slate-700 dark:text-white/60"],
                ].map(([label, val, cls]) => (
                  <div key={String(label)} className="flex justify-between">
                    <span className="text-slate-600 dark:text-white/45">{label}</span>
                    <span className={String(cls)}>{val}</span>
                  </div>
                ))}
                <div className={`pt-2 border-t ${admin.divider} text-xs text-slate-500 dark:text-white/30`}>
                  Access token TTL: {overview.config.access_token_ttl_minutes}m · Refresh TTL: {overview.config.refresh_token_ttl_days}d
                </div>
              </div>
            </div>
            {/* SAS */}
            <div className={`${surfaceCard} p-5`}>
              <h3 className={`${admin.sectionTitle} mb-3`}>SAS URL Tokens</h3>
              <div className="space-y-1.5 text-sm">
                {[
                  ["Active",  overview.sas.active,  "text-sky-400"],
                  ["Revoked", overview.sas.revoked,  "text-rose-400"],
                  ["Expired", overview.sas.expired,  "text-slate-600 dark:text-white/35"],
                  ["Total",   overview.sas.total,    "text-slate-700 dark:text-white/60"],
                ].map(([label, val, cls]) => (
                  <div key={String(label)} className="flex justify-between">
                    <span className="text-slate-600 dark:text-white/45">{label}</span>
                    <span className={String(cls)}>{val}</span>
                  </div>
                ))}
                <div className={`pt-2 border-t ${admin.divider} text-xs text-slate-500 dark:text-white/30`}>
                  Auto-revoke candidates: {overview.risk_summary.auto_revoke_candidates}
                </div>
              </div>
            </div>
          </div>

          {overview.risk_summary.critical_tokens > 0 && (
            <div className={`${surfaceCard} p-4 border-rose-500/20`}>
              <p className="text-xs text-rose-400 font-medium">
                {t("admin.tokenSecurity.criticalTokens", {
                  count: overview.risk_summary.critical_tokens,
                })}
              </p>
            </div>
          )}

          {/* LockSend AI model info (collapsed by default) */}
          {aiHealth && aiReady && aiHealth.metrics && (
            <div className={surfaceCard}>
              <button
                type="button"
                onClick={() => setModelInfoOpen((o) => !o)}
                className="w-full px-4 py-2.5 flex items-center gap-2 text-left hover:bg-white/[0.02] transition rounded-[inherit]"
                aria-expanded={modelInfoOpen}
              >
                <span className="text-xs font-semibold text-emerald-300">Model info</span>
                <span className="text-[11px] text-slate-500 dark:text-white/35 truncate">
                  Random Forest · {aiHealth.version}
                  {aiHealth.metrics.roc_auc != null
                    ? ` · ROC-AUC ${(aiHealth.metrics.roc_auc * 100).toFixed(1)}%`
                    : ""}
                </span>
                <span className="ml-auto text-slate-500 dark:text-white/30 text-xs shrink-0">
                  {modelInfoOpen ? "▾" : "▸"}
                </span>
              </button>
              {modelInfoOpen && (
                <div className={`px-4 pb-4 pt-1 border-t ${admin.divider}`}>
                  <div className="grid grid-cols-3 sm:grid-cols-5 gap-3">
                    {[
                      { label: "Accuracy",  val: aiHealth.metrics.accuracy },
                      { label: "F1",        val: aiHealth.metrics.f1 },
                      { label: "ROC-AUC",   val: aiHealth.metrics.roc_auc },
                      { label: "Precision", val: aiHealth.metrics.precision },
                      { label: "Recall",    val: aiHealth.metrics.recall },
                    ].map(({ label, val }) => (
                      <div key={label} className="text-center">
                        <p className="text-sm font-bold text-emerald-300">{val != null ? (val * 100).toFixed(1) + "%" : "—"}</p>
                        <p className="text-[10px] text-slate-500 dark:text-white/30 mt-0.5">{label}</p>
                      </div>
                    ))}
                  </div>
                  <p className="text-[10px] text-slate-400 dark:text-white/20 mt-3">
                    Train: {aiHealth.metrics.train_size?.toLocaleString()} samples · Dataset: CIC-IDS2017 (brute-force, DoS, Bot, DDoS)
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Top risk */}
          {topRisk.length > 0 && (
            <div className={`${surfaceCard} p-5`}>
              <h3 className={`${admin.sectionTitle} mb-3`}>{t("admin.tokenSecurity.topRisk")}</h3>
              <ul className="space-y-2">
                {topRisk.slice(0, 5).map((t) => (
                  <li key={t.token_id} className="flex items-center gap-2 text-xs text-slate-700 dark:text-white/55">
                    <RiskBadge level={t.risk_level} />
                    <span className="truncate flex-1">{t.email ?? t.blob_name ?? t.token_id}</span>
                    <span className="text-slate-600 dark:text-white/35">{t.risk_score}</span>
                    <RecBadge rec={t.recommendation} />
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* AI Analyze button */}
          <div className={`${surfaceCard} p-5`}>
            <h3 className={`${admin.sectionTitle} mb-2`}>{t("admin.tokenSecurity.aiAnalyzeTitle")}</h3>
            <p className="text-xs text-slate-600 dark:text-white/35 mb-4">
              {t("admin.tokenSecurity.aiAnalyzeDesc")}
              {!aiReady && (
                <span className="text-amber-300/60 ml-2">
                  — {aiHealth?.mode === "remote"
                    ? (aiHealth.error ?? aiHealth.hint ?? t("admin.tokenSecurity.aiRemoteNotConnected"))
                    : (aiHealth?.hint ?? t("admin.tokenSecurity.aiNotReadyHint"))}
                </span>
              )}
            </p>

            {analyzing && activeJob && (
              <div className="mb-5 space-y-3 rounded-2xl border border-white/10 bg-slate-950/55 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <LoadingSpinner size="sm" />
                    <span className="text-sm font-medium text-white/85">
                      {activeJob.status === "pending"
                        ? (t("admin.tokenSecurity.jobPending") ?? "Pending…")
                        : activeJob.status === "running"
                          ? (t("admin.tokenSecurity.jobRunning") ?? "Analyzing in background…")
                          : activeJob.status}
                    </span>
                  </div>
                  <span className="text-xs font-bold text-emerald-300 tabular-nums">
                    {activeJob.progress_pct}%
                  </span>
                </div>
                <div className="relative h-2.5 w-full overflow-hidden rounded-full bg-white/5 ring-1 ring-white/10">
                  <div
                    className="absolute inset-y-0 left-0 rounded-full bg-gradient-to-r from-emerald-500 to-teal-400 transition-all"
                    style={{ width: `${Math.max(2, Math.min(100, activeJob.progress_pct))}%` }}
                  />
                </div>
                <div className="grid grid-cols-4 gap-2 text-[11px]">
                  <div>
                    <p className="text-slate-500 dark:text-white/30">Total</p>
                    <p className="font-semibold text-white/80 tabular-nums">{activeJob.total_tokens}</p>
                  </div>
                  <div>
                    <p className="text-slate-500 dark:text-white/30">Analyzed</p>
                    <p className="font-semibold text-emerald-300 tabular-nums">{activeJob.analyzed_count}</p>
                  </div>
                  <div>
                    <p className="text-slate-500 dark:text-white/30">Skipped</p>
                    <p className="font-semibold text-sky-300 tabular-nums">{activeJob.skipped_cached}</p>
                  </div>
                  <div>
                    <p className="text-slate-500 dark:text-white/30">Failed</p>
                    <p className="font-semibold text-rose-300 tabular-nums">{activeJob.failed_count}</p>
                  </div>
                </div>
                {activeJob.result_summary && activeJob.status === "completed" && (
                  <div className="text-[11px] text-slate-400 dark:text-white/45 border-t border-white/5 pt-2">
                    High risk: <span className="text-rose-300 font-semibold">{activeJob.result_summary.high_risk_count ?? 0}</span>
                    <span className="mx-2">·</span>
                    Revoke: <span className="text-amber-300 font-semibold">{activeJob.result_summary.revoke_recommendations ?? 0}</span>
                    <span className="mx-2">·</span>
                    Saved: <span className="text-emerald-300 font-semibold">{activeJob.result_summary.saved_snapshots ?? 0}</span>
                  </div>
                )}
                {activeJob.error_message && activeJob.status === "failed" && (
                  <p className="text-[11px] text-rose-300 truncate">{activeJob.error_message}</p>
                )}
              </div>
            )}

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => void runAiAnalyze(false)}
                disabled={analyzing || !aiReady}
                className="inline-flex items-center gap-2 px-5 py-2 rounded-xl bg-emerald-700 hover:bg-emerald-600 disabled:bg-white/10 text-sm font-medium text-white transition disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {analyzing ? <LoadingSpinner size="sm" /> : null}
                {analyzing ? t("admin.tokenSecurity.analyzing") : t("admin.tokenSecurity.runAi")}
              </button>
              <button
                type="button"
                onClick={() => void runAiAnalyze(true)}
                disabled={analyzing || !aiReady}
                title="Phân tích lại toàn bộ token, bỏ qua bộ lọc benign đã lưu"
                className="inline-flex items-center gap-2 px-4 py-2 rounded-xl border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-50 text-sm font-medium transition disabled:cursor-not-allowed"
              >
                Force re-analyze
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Tab: Token List ── */}
      {activeTab === "tokens" && (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            {(["all", "jwt", "sas"] as const).map((t) => (
              <button key={t} type="button" onClick={() => { setTokenType(t); void loadTokens(t); }}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                  tokenType === t ? admin.tabActive : admin.tabInactive
                }`}>
                {t.toUpperCase()}
              </button>
            ))}
            {tokensLoading && <LoadingSpinner size="sm" />}
          </div>

          <div className={`${surfaceCard} overflow-hidden`}>
            {!tokens.length ? (
              <p className="px-5 py-10 text-sm text-slate-500 dark:text-white/30 text-center">
                {tokensLoading ? t("common.loading") : t("admin.tokenSecurity.noTokens")}
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className={admin.tableHeadInner}>
                      <th className="px-4 py-3 font-medium">Token / User</th>
                      <th className="px-3 py-3 font-medium">Type</th>
                      <th className="px-3 py-3 font-medium">Score</th>
                      <th className="px-3 py-3 font-medium">IPs</th>
                      <th className="px-3 py-3 font-medium">Age (h)</th>
                      <th className="px-3 py-3 font-medium">Rec</th>
                      <th className="px-4 py-3 font-medium text-right">{t("admin.tokenSecurity.colActions")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tokens.map((t) => (
                      <tr key={t.token_id} className={admin.rowInner}>
                        <td className="px-4 py-3 max-w-[200px]">
                          <p className="text-slate-900 dark:text-white/80 text-xs truncate">{t.email ?? t.blob_name ?? t.token_id.slice(0, 12) + "…"}</p>
                          <p className="text-[10px] text-slate-500 dark:text-white/30">{t.role ?? t.token_type}</p>
                        </td>
                        <td className="px-3 py-3">
                          <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                            t.token_type === "jwt" ? "bg-indigo-500/15 text-indigo-300" : "bg-sky-500/15 text-sky-300"
                          }`}>{t.token_type.toUpperCase()}</span>
                        </td>
                        <td className="px-3 py-3">
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-800 dark:text-white/70 text-xs w-5">{t.risk_score}</span>
                            <RiskBadge level={t.risk_level} />
                          </div>
                        </td>
                        <td className="px-3 py-3 text-slate-600 dark:text-white/50 text-xs">{t.ip_count}</td>
                        <td className="px-3 py-3 text-slate-600 dark:text-white/50 text-xs">{t.token_age_hours}</td>
                        <td className="px-3 py-3"><RecBadge rec={t.recommendation} /></td>
                        <td className="px-4 py-3 text-right">
                          {t.token_type === "jwt" && t.user_id && (
                            <button type="button" disabled={busyId === t.user_id || t.active_sessions === 0}
                              onClick={() => void revokeJwt(t.user_id!, t.email ?? null)}
                              className="text-[11px] text-rose-400 hover:text-rose-300 disabled:opacity-30">
                              {busyId === t.user_id ? "…" : "Revoke"}
                            </button>
                          )}
                          {t.token_type === "sas" && !t.is_revoked && (
                            <button type="button" disabled={busyId === t.token_id}
                              onClick={() => void revokeSas(t.token_id)}
                              className="text-[11px] text-rose-400 hover:text-rose-300 disabled:opacity-30">
                              {busyId === t.token_id ? "…" : "Revoke"}
                            </button>
                          )}
                          {t.is_revoked && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-900 text-white/70 dark:bg-transparent dark:text-white/25">
                              Revoked
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Tab: Trends ── */}
      {activeTab === "trends" && (
        <div className="space-y-4">
          {trendsLoading && (
            <div className="flex justify-center py-10"><LoadingSpinner /></div>
          )}
          {trends && !trendsLoading && (
            <>
              <div className="rounded-3xl border border-white/10 bg-slate-950/55 backdrop-blur-md p-4 sm:p-5">
                <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-100 dark:text-white/90">
                      {t("admin.tokenSecurity.tabTrends")}
                    </h3>
                    <p className="text-xs text-slate-500 dark:text-white/35">
                      {t("admin.tokenSecurity.days", { count: trends.days })} · {t("admin.tokenSecurity.trendReadableHint")}
                    </p>
                  </div>
                </div>
                <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
                  {[
                    { label: t("admin.tokenSecurity.trendTokenAccess"), value: trends.totals.access_events, color: "text-violet-400" },
                    { label: t("admin.tokenSecurity.trendAiAlerts"), value: trends.totals.ai_alerts, color: "text-amber-400" },
                    { label: "Score AI ≥50%", value: trends.totals.ai_high_scores, color: "text-rose-400" },
                    { label: "Rule ≠ AI", value: trends.totals.rule_ai_disagree, color: "text-orange-400" },
                  ].map(({ label, value, color }) => (
                    <div key={label} className="rounded-2xl border border-white/10 bg-slate-950/55 px-4 py-4">
                      <p className={`text-3xl font-bold ${color}`}>{value}</p>
                      <p className="mt-2 text-xs font-medium text-slate-200 dark:text-white/75">{label}</p>
                      <p className="text-[11px] text-slate-500 dark:text-white/30">{t("admin.tokenSecurity.days", { count: trends.days })}</p>
                    </div>
                  ))}
                </div>
              </div>
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
                {[
                  { title: t("admin.tokenSecurity.chartTokenPerDay"), data: trends.access_events, color: "bg-violet-500/70", dot: "bg-violet-400" },
                  { title: t("admin.tokenSecurity.chartAiAlertsPerDay"), data: trends.ai_alerts, color: "bg-amber-500/70", dot: "bg-amber-400" },
                  { title: t("admin.tokenSecurity.chartAiHighPerDay"), data: trends.ai_high_scores, color: "bg-rose-500/70", dot: "bg-rose-400" },
                  { title: t("admin.tokenSecurity.chartRuleDisagreePerDay"), data: trends.rule_ai_disagree, color: "bg-orange-500/70", dot: "bg-orange-400" },
                ].map(({ title, data, color, dot }) => (
                  <div key={title} className="rounded-3xl border border-white/10 bg-slate-950/60 backdrop-blur-md p-5 sm:p-6">
                    <div className="mb-4 flex items-start justify-between gap-3">
                      <div>
                        <h4 className="text-sm font-semibold text-slate-100 dark:text-white/85">{title}</h4>
                        <p className="mt-1 text-xs text-slate-500 dark:text-white/30">
                          {data.some((v) => v > 0)
                            ? t("admin.tokenSecurity.trendHoverHint")
                            : t("admin.tokenSecurity.trendQuietPeriod")}
                        </p>
                      </div>
                      <span className={`h-2.5 w-2.5 rounded-full ${dot}`} />
                    </div>
                    <MiniBarChart
                      labels={trends.labels}
                      series={data}
                      colorClass={color}
                      emptyLabel={t("admin.tokenSecurity.trendQuietPeriod")}
                    />
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}

      {/* ── Tab: File Activity ── */}
      {activeTab === "files" && (
        <div className="space-y-4">
          {fileActivityLoading && (
            <div className="flex justify-center py-10"><LoadingSpinner /></div>
          )}
          {fileActivity && !fileActivityLoading && (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  { label: "Upload", value: fileActivity.summary.uploads, color: "text-indigo-400" },
                  { label: "Download", value: fileActivity.summary.downloads, color: "text-sky-400" },
                  { label: t("admin.tokenSecurity.filesDownloaded"), value: fileActivity.summary.unique_files_downloaded, color: "text-violet-400" },
                  { label: t("admin.tokenSecurity.suspiciousFiles"), value: fileActivity.summary.suspicious_files, color: "text-rose-400" },
                ].map(({ label, value, color }) => (
                  <div key={label} className={`${surfaceCard} p-4 text-center`}>
                    <p className={`text-2xl font-bold ${color}`}>{value}</p>
                    <p className="text-[11px] text-slate-600 dark:text-white/35 mt-1">{label}</p>
                    <p className="text-[10px] text-slate-500 dark:text-white/25">{t("admin.tokenSecurity.days", { count: fileActivity.days })}</p>
                  </div>
                ))}
              </div>

              <div className="grid sm:grid-cols-2 gap-4">
                {[
                  { title: t("admin.tokenSecurity.chartUploadPerDay"), data: fileActivity.trend.uploads_per_day, color: "bg-indigo-500/70" },
                  { title: t("admin.tokenSecurity.chartDownloadPerDay"), data: fileActivity.trend.downloads_per_day, color: "bg-sky-500/70" },
                ].map(({ title, data, color }) => (
                  <div key={title} className={`${surfaceCard} p-5`}>
                    <h4 className="text-xs font-semibold text-slate-600 dark:text-white/50 mb-4">{title}</h4>
                    <MiniBarChart
                      labels={fileActivity.labels}
                      series={data}
                      colorClass={color}
                      emptyLabel={t("admin.tokenSecurity.noDownloadsInDays", { days: fileActivity.days })}
                    />
                  </div>
                ))}
              </div>

              {fileActivity.top_upload_file_trends && fileActivity.top_upload_file_trends.length > 0 && (
                <div className={`${surfaceCard} p-5`}>
                  <h4 className="text-xs font-semibold text-slate-600 dark:text-white/50 mb-4">
                    {t("admin.tokenSecurity.topUploadFileTrend")}
                  </h4>
                  <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
                    {fileActivity.top_upload_file_trends.map((f) => (
                      <div key={`up-${f.file_id}`} className="rounded-xl border border-slate-200/10 p-3">
                        <button
                          type="button"
                          onClick={() => void loadFileDetail(f.file_id)}
                          className="text-xs font-medium text-indigo-400 hover:underline truncate block max-w-full mb-2 text-left"
                          title={f.file_name}
                        >
                          {f.file_name}
                        </button>
                        <MiniBarChart
                          labels={fileActivity.labels}
                          series={f.uploads_per_day}
                          colorClass="bg-indigo-500/70"
                          emptyLabel={t("admin.tokenSecurity.noUploadsInDays", { days: fileActivity.days })}
                        />
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {fileActivity.top_file_trends.length > 0 && (
                <div className={`${surfaceCard} p-5`}>
                  <h4 className="text-xs font-semibold text-slate-600 dark:text-white/50 mb-4">
                    {t("admin.tokenSecurity.topFileTrend")}
                  </h4>
                  <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
                    {fileActivity.top_file_trends.map((f) => (
                      <div key={f.file_id} className="rounded-xl border border-slate-200/10 p-3">
                        <button
                          type="button"
                          onClick={() => void loadFileDetail(f.file_id)}
                          className="text-xs font-medium text-sky-400 hover:underline truncate block max-w-full mb-2 text-left"
                          title={f.file_name}
                        >
                          {f.file_name}
                        </button>
                        <MiniBarChart
                          labels={fileActivity.labels}
                          series={f.downloads_per_day}
                          colorClass="bg-emerald-500/70"
                          emptyLabel={t("admin.tokenSecurity.noDownloadsInDays", { days: fileActivity.days })}
                        />
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {(fileActivity.top_upload_files?.length ?? 0) > 0 && (
                <div className={`${surfaceCard} overflow-hidden`}>
                  <div className="px-5 py-3 border-b border-slate-200/10 flex items-center justify-between">
                    <h3 className={admin.sectionTitle}>{t("admin.tokenSecurity.topFilesByUp")}</h3>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="text-left text-slate-500 dark:text-white/35 border-b border-slate-200/10">
                          <th className="px-4 py-2 font-medium">File</th>
                          <th className="px-4 py-2 font-medium">Owner</th>
                          <th className="px-4 py-2 font-medium text-right">Uploads</th>
                          <th className="px-4 py-2 font-medium text-right">IP</th>
                          <th className="px-4 py-2 font-medium text-right">Users</th>
                          <th className="px-4 py-2 font-medium text-right">Bytes</th>
                          <th className="px-4 py-2 font-medium"> </th>
                        </tr>
                      </thead>
                      <tbody>
                        {fileActivity.top_upload_files!.map((f) => (
                          <tr
                            key={`up-row-${f.file_id}-${f.file_name}`}
                            className="border-b border-slate-200/5 hover:bg-slate-500/5"
                          >
                            <td className="px-4 py-2.5 max-w-[200px]">
                              {f.file_id ? (
                                <button
                                  type="button"
                                  onClick={() => void loadFileDetail(f.file_id!)}
                                  className="text-indigo-400 hover:underline truncate block max-w-full text-left"
                                  title={f.file_name}
                                >
                                  {f.file_name}
                                </button>
                              ) : (
                                <span className="truncate block max-w-full">{f.file_name}</span>
                              )}
                            </td>
                            <td className="px-4 py-2.5 text-slate-400 truncate max-w-[160px]">
                              {f.owner_email ?? "—"}
                            </td>
                            <td className="px-4 py-2.5 text-right font-mono">{f.uploads}</td>
                            <td className="px-4 py-2.5 text-right font-mono">{f.unique_ips}</td>
                            <td className="px-4 py-2.5 text-right font-mono">{f.unique_users}</td>
                            <td className="px-4 py-2.5 text-right font-mono">
                              {(f.total_bytes / (1024 * 1024)).toFixed(1)} MB
                            </td>
                            <td className="px-4 py-2.5">
                              {f.file_id && (
                                <button
                                  type="button"
                                  onClick={() => void loadFileDetail(f.file_id!)}
                                  className="text-[10px] text-slate-400 hover:text-white"
                                >
                                  Details
                                </button>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              <div className={`${surfaceCard} overflow-hidden`}>
                <div className="px-5 py-3 border-b border-slate-200/10 flex items-center justify-between">
                  <h3 className={admin.sectionTitle}>{t("admin.tokenSecurity.topFilesByDl")}</h3>
                  <button type="button" onClick={() => void loadFileActivity()} className={admin.btnGhost}>
                    {t("admin.refresh")}
                  </button>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-left text-slate-500 dark:text-white/35 border-b border-slate-200/10">
                        <th className="px-4 py-2 font-medium">File</th>
                        <th className="px-4 py-2 font-medium">Owner</th>
                        <th className="px-4 py-2 font-medium text-right">DL</th>
                        <th className="px-4 py-2 font-medium text-right">IP</th>
                        <th className="px-4 py-2 font-medium text-right">SAS</th>
                        <th className="px-4 py-2 font-medium text-right">AI</th>
                        <th className="px-4 py-2 font-medium">Risk</th>
                        <th className="px-4 py-2 font-medium"> </th>
                      </tr>
                    </thead>
                    <tbody>
                      {fileActivity.top_files.length === 0 && (
                        <tr>
                          <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                            {t("admin.tokenSecurity.noDownloadsInDays", { days: fileActivity.days })}
                          </td>
                        </tr>
                      )}
                      {fileActivity.top_files.map((f) => (
                        <tr
                          key={`${f.file_id}-${f.file_name}`}
                          className="border-b border-slate-200/5 hover:bg-slate-500/5"
                        >
                          <td className="px-4 py-2.5 max-w-[200px]">
                            {f.file_id ? (
                              <button
                                type="button"
                                onClick={() => void loadFileDetail(f.file_id!)}
                                className="text-sky-400 hover:underline truncate block max-w-full text-left"
                                title={f.file_name}
                              >
                                {f.file_name}
                              </button>
                            ) : (
                              <span className="truncate block">{f.file_name}</span>
                            )}
                          </td>
                          <td className="px-4 py-2.5 text-slate-600 dark:text-white/45 truncate max-w-[140px]">
                            <span className={f.owner_email_valid === false ? "text-amber-600 dark:text-amber-400" : ""}>
                              {f.owner_email ?? "—"}
                            </span>
                            {f.owner_email_valid === false && (
                              <span className="block text-[9px] text-amber-600 dark:text-amber-400">
                                {t("admin.ownerEmailInvalid")}
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-2.5 text-right font-mono">{f.downloads}</td>
                          <td className="px-4 py-2.5 text-right font-mono">{f.unique_ips}</td>
                          <td className="px-4 py-2.5 text-right font-mono">{f.active_sas_links}</td>
                          <td className="px-4 py-2.5 text-right font-mono">{f.ai_alerts || "—"}</td>
                          <td className="px-4 py-2.5">
                            {f.suspicious || f.ai_alerts > 0 ? (
                              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-rose-500/15 text-rose-300">
                                {f.ai_alerts > 0 ? "AI" : "IP"}
                              </span>
                            ) : (
                              <span className="text-slate-500">—</span>
                            )}
                          </td>
                          <td className="px-4 py-2.5 text-right">
                            {f.suspicious && f.file_id ? (
                              <button
                                type="button"
                                onClick={() => void notifyFileOwner(f.file_id!)}
                                disabled={notifyOwnerBusy || f.owner_email_valid === false}
                                title={
                                  f.owner_email_valid === false
                                    ? t("admin.ownerEmailInvalidHint")
                                    : undefined
                                }
                                className="text-[10px] px-2 py-1 rounded bg-rose-600/80 text-white hover:bg-rose-500 disabled:opacity-50"
                              >
                                {t("admin.tokenSecurity.warn")}
                              </button>
                            ) : (
                              <span className="text-slate-600">—</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}

          {(fileDetailLoading || fileDetail) && (
            <div className={`${surfaceCard} p-5`}>
              {fileDetailLoading && <LoadingSpinner size="sm" />}
              {fileDetail && !fileDetailLoading && (
                <div className="space-y-4">
                  <div className="flex flex-wrap items-start gap-3">
                    <div>
                      <h3 className="text-sm font-semibold text-slate-800 dark:text-white/90">
                        {fileDetail.file_name}
                      </h3>
                      <p className="text-xs text-slate-500 mt-1">
                        Owner: {fileDetail.owner_email ?? "—"}
                        {fileDetail.owner_email_valid === false && (
                          <span className="text-amber-600 dark:text-amber-400">
                            {" "}
                            ({t("admin.ownerEmailInvalid")})
                          </span>
                        )}
                        {" · "}
                        {fileDetail.storage_mode ?? "share"}
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setFileDetail(null)}
                      className="ml-auto text-xs text-slate-500 hover:text-white"
                    >
                      {t("admin.close")}
                    </button>
                    {fileDetail.stats.suspicious && (
                      <button
                        type="button"
                        disabled={notifyOwnerBusy || fileDetail.owner_email_valid === false}
                        title={
                          fileDetail.owner_email_valid === false
                            ? t("admin.ownerEmailInvalidHint")
                            : undefined
                        }
                        onClick={() => void notifyFileOwner(fileDetail.file_id)}
                        className="text-xs px-3 py-1.5 rounded-lg bg-rose-600/90 text-white hover:bg-rose-500 disabled:opacity-50"
                      >
                        {notifyOwnerBusy ? t("admin.notifying") : t("admin.notifyOwner")}
                      </button>
                    )}
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-center text-xs">
                    {[
                      ["Download", fileDetail.stats.downloads],
                      ["Upload", fileDetail.stats.uploads],
                      ["IP", fileDetail.stats.unique_ips],
                      ["SAS active", fileDetail.stats.active_sas_links],
                      [t("admin.tokenSecurity.risk"), fileDetail.stats.suspicious ? t("admin.tokenSecurity.riskYes") : t("admin.tokenSecurity.riskNo")],
                    ].map(([label, val]) => (
                      <div key={String(label)} className="rounded-lg bg-slate-500/5 py-2">
                        <p className="font-mono font-semibold">{val}</p>
                        <p className="text-slate-500">{label}</p>
                      </div>
                    ))}
                  </div>
                  {fileDetail.recent_alerts.length > 0 && (
                    <div>
                      <h4 className="text-xs font-semibold text-amber-300 mb-2">{t("admin.tokenSecurity.relatedAiAlerts")}</h4>
                      <ul className="space-y-1.5 text-xs">
                        {fileDetail.recent_alerts.map((a) => (
                          <li key={a.id} className="flex flex-wrap gap-2 text-slate-600 dark:text-white/60">
                            <RecBadge rec={a.decision} />
                            <span>AI {a.ai_score_pct}%</span>
                            <span className="text-slate-500">{a.summary_vi ?? ""}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {(fileDetail.recent_uploads?.length ?? 0) > 0 && (
                    <div>
                      <h4 className="text-xs font-semibold text-slate-600 dark:text-white/50 mb-2">
                        {t("admin.tokenSecurity.recentUploads")}
                      </h4>
                      <ul className="space-y-1 text-[11px] font-mono text-slate-500">
                        {fileDetail.recent_uploads!.map((u, i) => (
                          <li key={`up-${i}`}>
                            {u.created_at.slice(0, 16)} · {u.ip_address ?? "?"} · {u.upload_type ?? "upload"} · user {u.user_id?.slice(0, 8) ?? "?"}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {fileDetail.recent_downloads.length > 0 && (
                    <div>
                      <h4 className="text-xs font-semibold text-slate-600 dark:text-white/50 mb-2">
                        {t("admin.tokenSecurity.recentDownloads")}
                      </h4>
                      <ul className="space-y-1 text-[11px] font-mono text-slate-500">
                        {fileDetail.recent_downloads.map((d, i) => (
                          <li key={i}>
                            {d.created_at.slice(0, 16)} · {d.ip_address ?? "?"} · user {d.user_id?.slice(0, 8) ?? "?"}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Tab: AI Report ── */}
      {activeTab === "ai-report" && (
        <div className="space-y-4">

          {/* Empty state */}
          {!aiResults.length && !aiError && !savedReportsLoading && savedReports.length === 0 && (
            <div className={`${surfaceCard} p-8 text-center`}>
              <p className="text-slate-600 dark:text-white/35 text-sm mb-4">
                {t("admin.tokenSecurity.noAiReport")}
              </p>
              <button type="button" onClick={() => void runAiAnalyze(false)} disabled={analyzing || !aiReady}
                className="inline-flex items-center gap-2 px-5 py-2 rounded-xl bg-emerald-700 hover:bg-emerald-600 text-sm text-white transition disabled:opacity-50">
                {analyzing ? <LoadingSpinner size="sm" /> : null}
                {aiReady ? t("admin.tokenSecurity.runAi") : t("admin.tokenSecurity.modelNotReadyBtn")}
              </button>
            </div>
          )}

          {/* Error */}
          {aiError && !aiResults.length && (
            <div className={`${surfaceCard} p-5`}>
              <p className="text-sm text-amber-300/90">
                <span className="font-medium">{t("admin.tokenSecurity.aiError")}</span> {aiError}
              </p>
              {aiHealth && !aiHealth.ready && (
                <p className="text-xs text-slate-500 dark:text-white/30 mt-2 font-mono">
                  {aiHealth.hint ?? `cd ${aiHealth.ai_dir} && python train.py`}
                </p>
              )}
            </div>
          )}

          {!aiResults.length && !aiError && selectedReportMeta && (
            <div className={`${surfaceCard} p-5`}>
              <div className="flex flex-wrap items-center gap-3 mb-3">
                <h3 className="text-sm font-semibold text-emerald-300">
                  Report {selectedReportMeta.job_id.slice(0, 8)}
                </h3>
                {selectedReportMeta.created_at && (
                  <span className="text-xs text-slate-500 dark:text-white/30">
                    Saved at {new Date(selectedReportMeta.created_at).toLocaleString("vi-VN")}
                  </span>
                )}
              </div>
              <p className="text-sm text-slate-300">
                Lần phân tích này không tạo snapshot AI mới
                {(selectedReportMeta.result_summary?.skipped_benign ??
                  selectedReportMeta.result_summary?.skipped_recent ??
                  selectedReportMeta.skipped_cached) > 0
                  ? " — hầu hết token đã được đánh dấu benign ở lần chạy trước nên bị bỏ qua."
                  : "."}
              </p>
              <p className="mt-2 text-xs text-slate-500 dark:text-white/35">
                Analyzed: {selectedReportMeta.result_summary?.ai_analyzed ?? selectedReportMeta.analyzed_count}
                <span className="mx-2">·</span>
                Skipped: {selectedReportMeta.result_summary?.skipped_benign ?? selectedReportMeta.result_summary?.skipped_recent ?? selectedReportMeta.skipped_cached}
                <span className="mx-2">·</span>
                Saved snapshots: {selectedReportMeta.result_summary?.saved_snapshots ?? 0}
              </p>
              <button
                type="button"
                onClick={() => void runAiAnalyze(true)}
                disabled={analyzing || !aiReady}
                className="mt-4 inline-flex items-center gap-2 px-4 py-2 rounded-xl border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-50 text-sm font-medium transition"
              >
                Force re-analyze (không skip)
              </button>
            </div>
          )}

          {/* Results */}
          {aiResults.length > 0 && (
            <>
              {/* Summary stats */}
              <div className={`${surfaceCard} p-5`}>
                <div className="flex flex-wrap items-center gap-3 mb-3">
                  <h3 className="text-sm font-semibold text-emerald-300">{t("admin.tokenSecurity.aiResults")}</h3>
                  {selectedReportMeta && (
                    <span className="rounded-full bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-300">
                      Report {selectedReportMeta.job_id.slice(0, 8)}
                    </span>
                  )}
                  <span className="text-xs text-slate-500 dark:text-white/30">
                    {t("admin.tokenSecurity.tokensAnalyzed", {
                      count:
                        selectedReportMeta?.result_summary?.ai_analyzed ??
                        selectedReportMeta?.analyzed_count ??
                        aiResults.length,
                    })}
                    {aiResults.length > 0 &&
                    (selectedReportMeta?.snapshots_total_available ??
                      selectedReportMeta?.result_summary?.ai_analyzed ??
                      selectedReportMeta?.analyzed_count ??
                      0) > aiResults.length
                      ? ` · đang hiện ${aiResults.length}/${selectedReportMeta?.snapshots_total_available ?? "?"} (ưu tiên REVOKE/REVIEW)`
                      : ""}
                  </span>
                  {selectedReportMeta?.snapshots_truncated && (
                    <span className="rounded-full bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-amber-300">
                      Danh sách bị cắt — token rủi ro cao được ưu tiên hiện trước
                    </span>
                  )}
                  {selectedReportMeta?.created_at && (
                    <span className="text-xs text-slate-500 dark:text-white/30">
                      Saved at {new Date(selectedReportMeta.created_at).toLocaleString("vi-VN")}
                    </span>
                  )}
                  {selectedReportMeta?.result_summary && (
                    <span className="text-xs text-slate-500 dark:text-white/30">
                      Requested {selectedReportMeta.result_summary.total_requested}
                      {" · "}
                      Skipped {selectedReportMeta.result_summary.skipped_benign ?? selectedReportMeta.result_summary.skipped_recent}
                    </span>
                  )}
                  <button
                    type="button"
                    onClick={exportAiCsv}
                    className="ml-auto text-xs px-3 py-1.5 rounded-lg border border-white/10 text-slate-400 hover:text-white hover:bg-white/5 transition"
                  >
                    {t("admin.tokenSecurity.exportCsv")}
                  </button>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-center">
                  {[
                    {
                      key: "MONITOR" as const,
                      label: t("admin.tokenSecurity.monitor"),
                      value: aiFilterCounts.MONITOR,
                      color: "text-amber-300",
                    },
                    {
                      key: "needs_review" as const,
                      label: "Needs Review",
                      value: aiFilterCounts.needs_review,
                      color: "text-rose-300",
                    },
                    {
                      key: "disagree" as const,
                      label: t("admin.tokenSecurity.ruleDisagree"),
                      value: aiFilterCounts.disagree,
                      color: "text-orange-300",
                    },
                  ].map(({ key, label, value, color }) => (
                    <button
                      key={key}
                      type="button"
                      onClick={() =>
                        setAiFilterDecision((prev) => (prev === key ? "all" : key))
                      }
                      className={`rounded-xl px-2 py-2 transition ${
                        aiFilterDecision === key
                          ? "bg-white/[0.06] ring-1 ring-white/15"
                          : "hover:bg-white/[0.03]"
                      }`}
                    >
                      <p className={`text-xl font-bold ${color}`}>{value}</p>
                      <p className="text-[11px] text-slate-600 dark:text-white/35 mt-0.5">{label}</p>
                    </button>
                  ))}
                </div>
              </div>

              {/* Filters */}
              <div className={`${surfaceCard} p-4 space-y-3`}>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[11px] uppercase tracking-wide text-slate-500 dark:text-white/35 mr-1">
                    Type
                  </span>
                  {([
                    { id: "all", label: `All (${aiResults.length})` },
                    { id: "jwt", label: `JWT (${aiFilterCounts.jwt})` },
                    { id: "sas", label: `SAS (${aiFilterCounts.sas})` },
                  ] as const).map((opt) => (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => setAiFilterType(opt.id)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                        aiFilterType === opt.id ? admin.tabActive : admin.tabInactive
                      }`}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[11px] uppercase tracking-wide text-slate-500 dark:text-white/35 mr-1">
                    Decision
                  </span>
                  {([
                    { id: "all", label: "All" },
                    { id: "ALLOW", label: `ALLOW (${aiFilterCounts.ALLOW})` },
                    { id: "MONITOR", label: `MONITOR (${aiFilterCounts.MONITOR})` },
                    { id: "REVIEW", label: `REVIEW (${aiFilterCounts.REVIEW})` },
                    { id: "REVOKE", label: `REVOKE (${aiFilterCounts.REVOKE})` },
                  ] as const).map((opt) => (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => setAiFilterDecision(opt.id)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                        aiFilterDecision === opt.id ? admin.tabActive : admin.tabInactive
                      }`}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <input
                    type="search"
                    value={aiFilterQuery}
                    onChange={(e) => setAiFilterQuery(e.target.value)}
                    placeholder="Tìm email, blob, file id, token ref…"
                    className="min-w-[220px] flex-1 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500/40"
                  />
                  <span className="text-xs text-slate-500 dark:text-white/35">
                    Hiện {filteredAiResults.length}/{aiResults.length}
                  </span>
                  {(aiFilterType !== "all" || aiFilterDecision !== "all" || aiFilterQuery.trim()) && (
                    <button
                      type="button"
                      onClick={() => {
                        setAiFilterType("all");
                        setAiFilterDecision("all");
                        setAiFilterQuery("");
                      }}
                      className="text-xs px-3 py-1.5 rounded-lg border border-white/10 text-slate-400 hover:text-white hover:bg-white/5 transition"
                    >
                      Reset
                    </button>
                  )}
                </div>
              </div>

              {/* Per-token results */}
              <div className={`${surfaceCard} overflow-hidden`}>
                <div className={`px-5 py-3 border-b ${admin.divider} flex items-center gap-2`}>
                  <h4 className="text-xs font-semibold text-slate-600 dark:text-white/50 uppercase tracking-wide">{t("admin.tokenSecurity.perTokenDetails")}</h4>
                  <span className="text-[11px] text-slate-500 dark:text-white/30">
                    {filteredAiResults.length} token
                  </span>
                </div>
                <div className="divide-y divide-white/[0.04]">
                  {!filteredAiResults.length ? (
                    <p className="px-5 py-8 text-center text-sm text-slate-500 dark:text-white/35">
                      Không có token khớp bộ lọc hiện tại.
                    </p>
                  ) : (
                  filteredAiResults.map((r) => {
                    const rule = r.token_id ? aiRuleByTokenId.get(r.token_id) : undefined;
                    if (r.error) return (
                      <div key={r.token_id ?? `${r.email}-${r.decision}`} className="px-5 py-3 text-xs text-rose-300/60">
                        {r.token_id?.slice(0, 12)}… — {t("admin.tokenSecurity.tokenError")} {r.error}
                      </div>
                    );
                    const ruleScore = r.rule_score ?? rule?.risk_score ?? "—";
                    const showDisagree = r.agreement?.status === "disagree";
                      const primaryLabel = r.subject_label ?? rule?.email ?? r.email ?? r.blob_name ?? r.token_id?.slice(0, 20) ?? "—";
                    return (
                      <details key={r.token_id ?? `${primaryLabel}-${r.decision}`} className="group px-5 py-3.5">
                        <summary className="cursor-pointer list-none [&::-webkit-details-marker]:hidden">
                          <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
                            <span className="text-xs text-slate-800 dark:text-white/75 truncate max-w-[200px] sm:max-w-xs">
                                {primaryLabel}
                            </span>
                            <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono shrink-0 ${
                              r.token_type === "jwt" ? "bg-indigo-500/15 text-indigo-300" : "bg-sky-500/15 text-sky-300"
                            }`}>{(r.token_type ?? "jwt").toUpperCase()}</span>
                            <span className="text-xs font-medium text-slate-600 dark:text-white/55 shrink-0">
                              Rule {ruleScore} → AI {r.risk_score_pct}%
                            </span>
                            <RecBadge rec={r.decision} />
                            {showDisagree && r.agreement && (
                              <AgreementBadge status={r.agreement.status} label={r.agreement.label} />
                            )}
                            <span className="text-[10px] text-slate-500 dark:text-white/25 ml-auto hidden sm:inline group-open:hidden">
                              {t("admin.tokenSecurity.details")}
                            </span>
                          </div>
                            <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-slate-500 dark:text-white/35">
                              {r.email && <span>Email: {r.email}</span>}
                              {r.blob_name && <span>Blob: {r.blob_name}</span>}
                              {r.file_id && <span>File: {r.file_id.slice(0, 8)}…</span>}
                              {r.token_id && <span>Ref: {r.token_id.slice(0, 16)}…</span>}
                            </div>
                          {(r.behavior_badges?.length ?? 0) > 0 && (
                            <div className="flex flex-wrap gap-1.5 mt-2">
                              {r.behavior_badges!.slice(0, 2).map((b) => (
                                <BehaviorBadge key={b.id} label={b.label} severity={b.severity} />
                              ))}
                            </div>
                          )}
                        </summary>
                        <div className="mt-2 pt-2 border-t border-white/[0.04] space-y-2 text-[11px] text-slate-500 dark:text-white/40">
                            <p>{r.summary_vi ?? r.explanation?.summary_vi}</p>
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px]">
                              <div className="rounded-lg bg-white/[0.03] px-2.5 py-2">
                                <p className="text-slate-400">Admin action</p>
                                <p className="font-semibold text-white/80">{r.decision}</p>
                              </div>
                              <div className="rounded-lg bg-white/[0.03] px-2.5 py-2">
                                <p className="text-slate-400">Rule rec</p>
                                <p className="font-semibold text-white/80">{r.rule_recommendation ?? "—"}</p>
                              </div>
                              <div className="rounded-lg bg-white/[0.03] px-2.5 py-2">
                                <p className="text-slate-400">IPs</p>
                                <p className="font-semibold text-white/80">{r.ip_count ?? "—"}</p>
                              </div>
                              <div className="rounded-lg bg-white/[0.03] px-2.5 py-2">
                                <p className="text-slate-400">Age (h)</p>
                                <p className="font-semibold text-white/80">{r.token_age_hours ?? "—"}</p>
                              </div>
                              {r.token_type === "jwt" ? (
                                <>
                                  <div className="rounded-lg bg-white/[0.03] px-2.5 py-2">
                                    <p className="text-slate-400">Sessions</p>
                                    <p className="font-semibold text-white/80">{r.active_sessions ?? "—"}</p>
                                  </div>
                                  <div className="rounded-lg bg-white/[0.03] px-2.5 py-2">
                                    <p className="text-slate-400">Access/hr</p>
                                    <p className="font-semibold text-white/80">{r.accesses_per_hour ?? "—"}</p>
                                  </div>
                                </>
                              ) : (
                                <>
                                  <div className="rounded-lg bg-white/[0.03] px-2.5 py-2">
                                    <p className="text-slate-400">Access total</p>
                                    <p className="font-semibold text-white/80">{r.access_count ?? "—"}</p>
                                  </div>
                                  <div className="rounded-lg bg-white/[0.03] px-2.5 py-2">
                                    <p className="text-slate-400">Download/hr</p>
                                    <p className="font-semibold text-white/80">{r.downloads_per_hour ?? "—"}</p>
                                  </div>
                                </>
                              )}
                              <div className="rounded-lg bg-white/[0.03] px-2.5 py-2">
                                <p className="text-slate-400">Expired</p>
                                <p className="font-semibold text-white/80">{r.is_expired ? "Yes" : "No"}</p>
                              </div>
                              <div className="rounded-lg bg-white/[0.03] px-2.5 py-2">
                                <p className="text-slate-400">Revoked</p>
                                <p className="font-semibold text-white/80">{r.is_revoked ? "Yes" : "No"}</p>
                              </div>
                            </div>
                            {r.requires_admin_action && (
                              <div className="rounded-lg border border-rose-500/20 bg-rose-500/8 px-3 py-2 text-[11px] text-rose-200">
                                Case này cần admin quyết định cuối cùng. Hệ thống chỉ gợi ý review, không tự revoke theo AI report.
                              </div>
                            )}
                            {(r.rule_reasons?.length ?? 0) > 0 && (
                              <div>
                                <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-slate-400">Rule signals</p>
                                <ul className="space-y-1">
                                  {r.rule_reasons!.map((reason, idx) => (
                                    <li key={`${r.token_id}-${idx}`} className="text-[11px] text-slate-300">
                                      - {reason}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          {r.explanation?.top_features?.length > 0 && (
                            <div className="flex flex-wrap gap-1.5">
                              {r.explanation.top_features.slice(0, 3).map((f, fi) => (
                                <span key={fi} className={`text-[10px] px-2 py-0.5 rounded-full ${
                                  f.impact > 0 ? "bg-rose-500/10 text-rose-300/60" : "bg-emerald-500/10 text-emerald-300/60"
                                }`}>
                                  {f.feature} {f.impact > 0 ? "↑" : "↓"}{Math.abs(f.impact).toFixed(3)}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      </details>
                    );
                  })
                  )}
                </div>
              </div>
            </>
          )}

          <div className={`${surfaceCard} p-5`}>
            <div className="flex flex-wrap items-center gap-3 mb-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-100 dark:text-white/85">Saved reports</h3>
                <p className="text-xs text-slate-500 dark:text-white/30">
                  Mỗi lần Analyze được lưu thành một report riêng theo job.
                </p>
              </div>
              <button
                type="button"
                onClick={() => void loadSavedReports(selectedReportJobId)}
                className="ml-auto text-xs px-3 py-1.5 rounded-lg border border-white/10 text-slate-400 hover:text-white hover:bg-white/5 transition"
              >
                Refresh reports
              </button>
            </div>

            {savedReportsLoading ? (
              <div className="flex items-center gap-2 text-sm text-slate-400">
                <LoadingSpinner size="sm" />
                <span>Đang tải danh sách report…</span>
              </div>
            ) : visibleSavedReports.length === 0 ? (
              <p className="text-sm text-slate-500 dark:text-white/30">
                Chưa có report đã lưu. Chạy Analyze để tạo report đầu tiên.
              </p>
            ) : (
              <div className="space-y-2">
                {visibleSavedReports.map((job) => {
                  const isActive = job.job_id === selectedReportJobId;
                  const isLoadingDetail = reportDetailLoading === job.job_id;
                  const createdAt = job.created_at
                    ? new Date(job.created_at).toLocaleString("vi-VN")
                    : "Unknown time";
                  const analyzed = job.result_summary?.ai_analyzed ?? job.analyzed_count;
                  const skipped = job.result_summary?.skipped_benign ?? job.result_summary?.skipped_recent ?? job.skipped_cached;
                  const durationSec =
                    job.started_at && job.completed_at
                      ? Math.max(
                          0,
                          Math.round(
                            (new Date(job.completed_at).getTime() -
                              new Date(job.started_at).getTime()) / 1000
                          )
                        )
                      : null;
                  return (
                    <button
                      key={job.job_id}
                      type="button"
                      onClick={() => void loadSavedReport(job.job_id)}
                      disabled={isLoadingDetail}
                      className={`w-full rounded-xl border px-4 py-3 text-left transition disabled:opacity-60 ${
                        isActive
                          ? "border-emerald-500/30 bg-emerald-500/10"
                          : "border-white/10 bg-slate-950/40 hover:bg-white/[0.04]"
                      }`}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-medium text-white/85">Report {job.job_id.slice(0, 8)}</span>
                        <span className="text-[11px] text-slate-500">{createdAt}</span>
                        <span className="rounded-full bg-white/5 px-2 py-0.5 text-[10px] font-medium text-slate-300 uppercase">
                          {job.token_type}
                        </span>
                        {job.status !== "completed" && (
                          <span className="rounded-full bg-sky-500/10 px-2 py-0.5 text-[10px] font-medium text-sky-300">
                            {job.status}
                          </span>
                        )}
                        <span className="ml-auto text-[11px] text-slate-400">
                          {analyzed} analyzed · {skipped} skipped
                        </span>
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-x-2 text-[11px] text-slate-500 dark:text-white/35">
                        <span>Saved snapshots: {job.result_summary?.saved_snapshots ?? 0}</span>
                        <span>·</span>
                        <span>High risk: {job.result_summary?.high_risk_count ?? 0}</span>
                        <span>·</span>
                        <span>Revoke: {job.result_summary?.revoke_recommendations ?? 0}</span>
                        {job.failed_count > 0 && (
                          <>
                            <span>·</span>
                            <span className="text-rose-300/80">Failed: {job.failed_count}</span>
                          </>
                        )}
                        {durationSec !== null && (
                          <>
                            <span>·</span>
                            <span>{durationSec}s</span>
                          </>
                        )}
                        <span className="ml-auto inline-flex items-center gap-1.5 font-medium text-emerald-300/90">
                          {isLoadingDetail ? (
                            <>
                              <LoadingSpinner size="sm" />
                              Đang tải chi tiết…
                            </>
                          ) : isActive ? (
                            "Đang xem chi tiết"
                          ) : (
                            "Xem chi tiết →"
                          )}
                        </span>
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
