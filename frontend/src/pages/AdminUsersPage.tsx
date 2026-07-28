import { useEffect, useState } from "react";
import { useAuth } from "../contexts/AuthContext";
import api from "../utils/api";
import PageLoader, { LoadingSpinner } from "../components/LoadingSpinner";
import { admin, surfaceCard } from "../styles/theme";
import { useT } from "../i18n/context";

interface UserRow {
  id: string;
  email: string | null;
  display_name: string | null;
  role: string;
  storage_plan: "free" | "pro";
  vault_quota_bytes: number | null;
  effective_vault_quota_bytes: number;
  created_at: string;
}

const ROLE_OPTIONS = ["owner", "recipient", "admin"] as const;
type Role = (typeof ROLE_OPTIONS)[number];

const ROLE_BADGE: Record<Role, string> = {
  owner: admin.roleOwner,
  recipient: admin.roleRecipient,
  admin: admin.roleAdmin,
};

function formatBytes(n: number): string {
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(n % (1024 ** 3) === 0 ? 0 : 1)} GB`;
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

export default function AdminUsersPage() {
  const t = useT();
  const { user: me } = useAuth();
  const [users, setUsers] = useState<UserRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [changing, setChanging] = useState<string | null>(null);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const res = await api.get<UserRow[]>("/auth/admin/users");
      setUsers(res.data);
      setError(null);
    } catch {
      setError(t("admin.usersPage.loadFailed"));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchUsers();
  }, []);

  const handleRoleChange = async (userId: string, newRole: Role) => {
    setChanging(userId);
    try {
      const res = await api.patch<UserRow>(`/auth/admin/users/${userId}/role`, {
        role: newRole,
      });
      setUsers((prev) =>
        prev.map((u) => (u.id === userId ? { ...u, role: res.data.role } : u))
      );
    } catch {
      setError(t("admin.usersPage.roleChangeFailed"));
    } finally {
      setChanging(null);
    }
  };

  const handleDelete = async (userId: string, email: string | null) => {
    if (!confirm(t("admin.usersPage.deleteConfirm", { email: email ?? userId }))) return;
    setChanging(userId);
    try {
      await api.delete(`/auth/admin/users/${userId}`);
      setUsers((prev) => prev.filter((u) => u.id !== userId));
    } catch {
      setError(t("admin.usersPage.deleteFailed"));
    } finally {
      setChanging(null);
    }
  };

  const handleStoragePlanChange = async (userId: string, storagePlan: "free" | "pro") => {
    setChanging(userId);
    try {
      const res = await api.patch<UserRow>(`/auth/admin/users/${userId}/storage-plan`, {
        storage_plan: storagePlan,
      });
      setUsers((prev) =>
        prev.map((u) => (u.id === userId ? res.data : u))
      );
      setError(null);
    } catch {
      setError(t("admin.usersPage.planChangeFailed"));
    } finally {
      setChanging(null);
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
        <div>
          <h2 className={admin.title}>{t("admin.usersPage.title")}</h2>
          <p className={admin.desc}>{t("admin.usersPage.desc")}</p>
        </div>
        <button
          type="button"
          onClick={() => void fetchUsers()}
          disabled={loading}
          className={`${admin.btnGhost} self-start`}
        >
          {loading ? <LoadingSpinner size="sm" /> : (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          )}
          {t("admin.refresh")}
        </button>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800 dark:border-rose-500/25 dark:bg-rose-500/10 dark:text-rose-300">
          <svg className="w-4 h-4 shrink-0" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
          </svg>
          {error}
        </div>
      )}

      <div className={`flex flex-wrap gap-x-4 gap-y-2 ${admin.legend}`}>
        {ROLE_OPTIONS.map((r) => (
          <div key={r} className="flex items-center gap-2">
            <span className={`px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wide ${ROLE_BADGE[r]}`}>
              {r}
            </span>
            <span>
              {r === "owner"
                ? t("admin.usersPage.roleOwnerDesc")
                : r === "recipient"
                  ? t("admin.usersPage.roleRecipientDesc")
                  : t("admin.usersPage.roleAdminDesc")}
            </span>
          </div>
        ))}
      </div>

      <div className={`${surfaceCard} overflow-hidden`}>
        {loading ? (
          <PageLoader
            variant="embedded"
            title={t("admin.usersPage.loading")}
            className="py-12"
          />
        ) : users.length === 0 ? (
          <div className={`py-16 text-center ${admin.empty}`}>{t("admin.usersPage.empty")}</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm min-w-[640px]">
              <thead>
                <tr className={admin.tableHead}>
                  <th className="px-4 sm:px-5 py-3">{t("admin.usersPage.colUser")}</th>
                  <th className="px-4 sm:px-5 py-3">{t("admin.usersPage.colRole")}</th>
                  <th className="px-4 sm:px-5 py-3">{t("admin.usersPage.colPlan")}</th>
                  <th className="px-4 sm:px-5 py-3 whitespace-nowrap">{t("admin.usersPage.colCreated")}</th>
                  <th className="px-4 sm:px-5 py-3 w-44">{t("admin.usersPage.colActions")}</th>
                </tr>
              </thead>
              <tbody className={admin.tableDivide}>
                {users.map((u) => {
                  const isMe = u.id === me?.user_id;
                  const isBusy = changing === u.id;
                  return (
                    <tr
                      key={u.id}
                      className={`${admin.rowHover} ${isMe ? admin.rowHighlight : ""}`}
                    >
                      <td className="px-4 sm:px-5 py-3.5">
                        <div className="flex items-center gap-3">
                          <div className="w-9 h-9 rounded-full bg-slate-200 dark:bg-slate-700 flex items-center justify-center text-slate-800 dark:text-slate-200 font-semibold text-sm shrink-0">
                            {(u.display_name || u.email || "U")[0].toUpperCase()}
                          </div>
                          <div className="min-w-0">
                            <div className={`${admin.cellName} flex items-center gap-2 flex-wrap`}>
                              <span className="truncate">{u.display_name || u.email}</span>
                              {isMe && (
                                <span className={admin.selfTag}>{t("admin.usersPage.selfTag")}</span>
                              )}
                            </div>
                            <div className={`${admin.cellSub} truncate`}>{u.email}</div>
                          </div>
                        </div>
                      </td>

                      <td className="px-4 sm:px-5 py-3.5">
                        {isMe ? (
                          <span className={`inline-flex px-2.5 py-1 rounded-md text-xs font-semibold ${ROLE_BADGE[u.role as Role] ?? ""}`}>
                            {u.role}
                          </span>
                        ) : (
                          <select
                            value={u.role}
                            disabled={isBusy}
                            onChange={(e) => void handleRoleChange(u.id, e.target.value as Role)}
                            className={`${admin.select} ${isBusy ? "opacity-50 cursor-not-allowed" : ""}`}
                          >
                            {ROLE_OPTIONS.map((r) => (
                              <option key={r} value={r} className="bg-slate-900 text-white">
                                {r}
                              </option>
                            ))}
                          </select>
                        )}
                      </td>

                      <td className="px-4 sm:px-5 py-3.5">
                        <div className="flex flex-col gap-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span
                              className={`inline-flex px-2.5 py-1 rounded-md text-[11px] font-semibold uppercase tracking-wide ${
                                u.storage_plan === "pro"
                                  ? "bg-amber-500/15 text-amber-300 border border-amber-400/25"
                                  : "bg-slate-500/15 text-slate-300 border border-slate-400/20"
                              }`}
                            >
                              {u.storage_plan}
                            </span>
                            {u.storage_plan === "pro" && (
                              <span className="text-[10px] font-semibold uppercase tracking-wide text-amber-300">
                                {t("admin.usersPage.proTag")}
                              </span>
                            )}
                          </div>
                          <div className={admin.cellMeta}>
                            {t("admin.usersPage.storageQuota", {
                              total: formatBytes(u.effective_vault_quota_bytes),
                            })}
                          </div>
                        </div>
                      </td>

                      <td className={`px-4 sm:px-5 py-3.5 ${admin.cellMeta}`}>
                        {new Date(u.created_at).toLocaleDateString("vi-VN", {
                          day: "2-digit",
                          month: "2-digit",
                          year: "numeric",
                        })}
                      </td>

                      <td className="px-4 sm:px-5 py-3.5">
                        {!isMe && (
                          <div className="flex flex-col gap-2">
                            <button
                              type="button"
                              onClick={() => void handleStoragePlanChange(u.id, u.storage_plan === "pro" ? "free" : "pro")}
                              disabled={isBusy}
                              className={`inline-flex items-center justify-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium border transition ${
                                u.storage_plan === "pro"
                                  ? "border-slate-500/30 text-slate-300 hover:bg-slate-500/10"
                                  : "border-amber-400/30 text-amber-300 hover:bg-amber-500/10"
                              } ${isBusy ? "opacity-50 cursor-not-allowed" : ""}`}
                            >
                              {isBusy ? (
                                <LoadingSpinner size="xs" />
                              ) : u.storage_plan === "pro" ? (
                                t("admin.usersPage.downgradeFree")
                              ) : (
                                t("admin.usersPage.upgradePro")
                              )}
                            </button>
                            <button
                              type="button"
                              onClick={() => void handleDelete(u.id, u.email)}
                              disabled={isBusy}
                              className={admin.deleteBtn}
                            >
                              {isBusy ? (
                                <LoadingSpinner size="xs" />
                              ) : (
                                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                  <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                </svg>
                              )}
                              {t("admin.delete")}
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <p className={admin.footer}>
        {t("admin.usersPage.footer", {
          total: users.length,
          owners: users.filter((u) => u.role === "owner").length,
          recipients: users.filter((u) => u.role === "recipient").length,
          admins: users.filter((u) => u.role === "admin").length,
        })}
      </p>
    </div>
  );
}
