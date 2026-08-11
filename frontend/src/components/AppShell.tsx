import React, { useState, useEffect, useRef, useCallback } from "react";
import { NavLink, Navigate, Routes, Route, Link, useLocation } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { useT } from "../i18n/context";
import { shell, header, nav, text, brand, badge } from "../styles/theme";
import { useKeySync } from "../hooks/useKeySync";
import { useInboxNotifications } from "../hooks/useInboxNotifications";
import NotificationPanel from "./NotificationPanel";
import {
  restoreFromSession,
  hasSessionWrapper,
  isUnlocked,
  onLock,
  resetLockTimer,
} from "../utils/keyVault";

import ProtectedRoute from "./ProtectedRoute";
import KeyUnlockModal from "./KeyUnlockModal";
import SecurityAlertsBanner from "./SecurityAlertsBanner";
import AssistantChatWidget from "./AssistantChatWidget";
import FloatingCryptoIcons from "./FloatingCryptoIcons";
import PageBackground from "./PageBackground";
import ThemeToggle from "./ThemeToggle";
import LanguageToggle from "./LanguageToggle";
import { LockSendMark } from "./LockSendLogo";
import { safeInitial, safeLabel } from "../utils/safeLabel";

import UploadPage from "../pages/UploadPage";
import DownloadPage from "../pages/DownloadPage";
import ProfilePage from "../pages/ProfilePage";
import KeyManagement from "../pages/KeyManagement";
import AdminLayout from "../pages/AdminLayout";
import AdminUsersPage from "../pages/AdminUsersPage";
import AdminActivityPage from "../pages/AdminActivityPage";
import AdminTokenSecurityPage from "../pages/AdminTokenSecurityPage";

// ── Nav icons ─────────────────────────────────────────────────────────────────

const NAV_ICONS: Record<string, React.ReactElement> = {
  upload: (
    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
    </svg>
  ),
  download: (
    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
    </svg>
  ),
  key: (
    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
    </svg>
  ),
  profile: (
    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
    </svg>
  ),
  admin: (
    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  ),
};

// ── TopNavItem ─────────────────────────────────────────────────────────────────

interface TopNavItemProps {
  to: string;
  label: string;
  icon: string;
  danger?: boolean;
  badgeCount?: number;
}

export function TopNavItem({ to, label, icon, danger, badgeCount }: TopNavItemProps) {
  return (
    <NavLink
      to={to}
      end
      className={({ isActive }) =>
        `relative flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[13px] font-medium transition-all duration-150 ${
          isActive
            ? danger ? nav.activeDanger : nav.active
            : danger ? nav.inactiveDanger : nav.inactive
        }`
      }
    >
      {NAV_ICONS[icon]}
      {label}
      {!!badgeCount && badgeCount > 0 && (
        <span className="absolute -top-1 -right-1 min-w-[16px] h-4 px-0.5 flex items-center justify-center rounded-full bg-rose-500 text-white text-[10px] font-bold leading-none shadow">
          {badgeCount > 99 ? "99+" : badgeCount}
        </span>
      )}
    </NavLink>
  );
}

// ── Role config ────────────────────────────────────────────────────────────────

const ROLE_CONFIG: Record<string, { label: string; badgeClass: string }> = {
  owner:     { label: "Owner",     badgeClass: badge.info },
  recipient: { label: "Recipient", badgeClass: badge.success },
  admin:     { label: "Admin",     badgeClass: badge.danger },
};

// ── AppShell ──────────────────────────────────────────────────────────────────

export default function AppShell() {
  const { user, logout } = useAuth();
  const t = useT();
  const location = useLocation();
  useKeySync(!!user && user.role !== "recipient");

  const [showUnlockModal, setShowUnlockModal] = useState(false);
  const [panelOpen, setPanelOpen] = useState(false);
  const role = user?.role ?? "owner";
  const roleCfg = ROLE_CONFIG[role] ?? ROLE_CONFIG.owner;
  const isRecipient = role === "recipient";
  const isAdmin = role === "admin";
  const isAdminRoute = location.pathname.startsWith("/admin");
  const contentMax = isAdminRoute ? "max-w-7xl" : "max-w-6xl";
  const initials = safeInitial(user?.display_name || user?.email, "U");

  const {
    inboxItems,
    sentItems,
    newInboxItems,
    unreadCount,
    loading: notifLoading,
    permissionState,
    requestPermission,
    markAllSeen,
    refresh: refreshNotifs,
  } = useInboxNotifications();

  // ── Clear inbox badge when user navigates to profile (where inbox lives) ─────
  useEffect(() => {
    if (location.pathname === "/profile") {
      markAllSeen();
    }
  }, [location.pathname, markAllSeen]);

  // ── Key vault restore on mount (F5) ────────────────────────────────────────
  useEffect(() => {
    if (isUnlocked()) return;
    if (hasSessionWrapper()) {
      restoreFromSession().then((keys) => {
        if (!keys) setShowUnlockModal(true);
      });
    } else {
      setShowUnlockModal(true);
    }
  }, []);

  // ── Register lock callback ──────────────────────────────────────────────────
  useEffect(() => {
    const unsub = onLock(() => setShowUnlockModal(true));
    return unsub;
  }, []);

  // ── Global activity → reset inactivity timer ───────────────────────────────
  const handleActivity = useCallback(() => { resetLockTimer(); }, []);
  const activityAttached = useRef(false);
  useEffect(() => {
    if (activityAttached.current) return;
    activityAttached.current = true;
    const events = ["mousemove", "keydown", "mousedown", "touchstart", "scroll"];
    events.forEach((e) => window.addEventListener(e, handleActivity, { passive: true }));
    return () => {
      events.forEach((e) => window.removeEventListener(e, handleActivity));
      activityAttached.current = false;
    };
  }, [handleActivity]);

  return (
    <div className={`${shell.page} relative`}>
      <PageBackground />
      <FloatingCryptoIcons />

      {showUnlockModal && (
        <KeyUnlockModal
          onUnlocked={() => setShowUnlockModal(false)}
          onDismiss={() => setShowUnlockModal(false)}
        />
      )}

      <div className="relative z-10 flex flex-col flex-1 min-h-screen w-full">
        {/* ── Top navigation bar ── */}
        <header className={header.bar}>
          <div className={`${contentMax} mx-auto px-5 h-14 flex items-center justify-between gap-4`}>
            {/* Brand */}
            <div className="flex items-center gap-3 shrink-0">
              <LockSendMark />
              <span className="font-bold text-[15px] tracking-tight">
                <span className={brand.lock}>Lock</span><span className={brand.send}>Send</span>
              </span>
            </div>

            {/* Nav links */}
            <nav className="flex items-center gap-0.5 flex-1 justify-center">
              {!isRecipient && <TopNavItem to="/" label={t("nav.upload")} icon="upload" />}
              <TopNavItem to="/download" label={t("nav.download")} icon="download" />
              <TopNavItem to="/keys" label={t("nav.keys")} icon="key" />
              <TopNavItem
                to="/profile"
                label={t("nav.profile")}
                icon="profile"
                badgeCount={unreadCount}
              />
              {isAdmin && <TopNavItem to="/admin" label={t("nav.admin")} icon="admin" danger />}
            </nav>

            {/* User menu */}
            <div className="flex items-center gap-2 shrink-0">
              {/* ── Notification bell + dropdown panel ── */}
              <div className="relative">
                <button
                  type="button"
                  title={
                    unreadCount > 0
                      ? t("notifications.unreadFilesPlural").replace("{count}", String(unreadCount))
                      : t("notifications.panelTitle")
                  }
                  onClick={() => {
                    setPanelOpen((v) => !v);
                    if (!panelOpen) markAllSeen();
                  }}
                  className={`relative p-1.5 rounded-lg transition ${
                    panelOpen
                      ? "text-violet-600 bg-violet-50 dark:text-violet-400 dark:bg-violet-400/10"
                      : `${text.faint} hover:text-violet-600 hover:bg-violet-50 dark:hover:text-violet-400 dark:hover:bg-violet-400/10`
                  }`}
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6 6 0 10-12 0v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
                  </svg>
                  {unreadCount > 0 && (
                    <span className="absolute -top-0.5 -right-0.5 min-w-[14px] h-3.5 px-0.5 flex items-center justify-center rounded-full bg-rose-500 text-white text-[9px] font-bold leading-none">
                      {unreadCount > 99 ? "99+" : unreadCount}
                    </span>
                  )}
                  {/* Amber dot when notifications not yet enabled */}
                  {permissionState === "default" && unreadCount === 0 && (
                    <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
                  )}
                </button>

                <NotificationPanel
                  open={panelOpen}
                  onClose={() => setPanelOpen(false)}
                  inboxItems={inboxItems}
                  sentItems={sentItems}
                  newInboxItems={newInboxItems}
                  unreadCount={unreadCount}
                  loading={notifLoading}
                  onMarkAllSeen={markAllSeen}
                  onRefresh={refreshNotifs}
                  permissionState={permissionState}
                  onRequestPermission={requestPermission}
                />
              </div>

              <LanguageToggle />
              <ThemeToggle />
              <div className={`flex items-center gap-2.5 pl-3 border-l ${header.divider}`}>
                <Link
                  to="/profile"
                  title={t("nav.profile")}
                  className="flex items-center gap-2.5 rounded-lg pr-1 -ml-1 hover:bg-slate-100 dark:hover:bg-slate-800/60 transition"
                >
                  <div className="w-7 h-7 rounded-full bg-slate-200 flex items-center justify-center text-[11px] font-semibold text-slate-700 dark:bg-slate-700 dark:text-slate-200">
                    {initials}
                  </div>
                  <div className="hidden sm:flex flex-col leading-none gap-0.5">
                    <span className={`text-[12px] font-medium max-w-[110px] truncate ${text.secondary}`}>
                      {safeLabel(user?.display_name, user?.email ?? "User", 40)}
                    </span>
                    <span className={`${roleCfg.badgeClass} w-fit`}>
                      {roleCfg.label}
                    </span>
                  </div>
                </Link>
                <button
                  onClick={() => void logout()}
                  title={t("common.signOut")}
                  className={`ml-1 p-1.5 rounded-lg transition ${text.faint} hover:text-rose-600 hover:bg-rose-50 dark:hover:text-rose-400 dark:hover:bg-rose-400/10`}
                >
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </header>

        {/* ── Page content ── */}
        <main className={`flex-1 ${contentMax} w-full min-w-0 mx-auto px-5 py-8`}>
          <SecurityAlertsBanner />

          <Routes>
            <Route path="/" element={isRecipient ? <DownloadPage /> : <UploadPage />} />
            <Route path="/download" element={<DownloadPage />} />
            <Route path="/profile" element={<ProfilePage />} />
            <Route path="/shared" element={<Navigate to="/profile?tab=history" replace />} />
            <Route path="/history" element={<Navigate to="/profile?tab=history" replace />} />
            <Route path="/vault" element={<Navigate to="/profile" replace />} />
            <Route path="/keys" element={<KeyManagement />} />
            <Route path="/help" element={<Navigate to="/" replace />} />
            <Route
              path="/admin/*"
              element={
                <ProtectedRoute requiredRole="admin">
                  <AdminLayout />
                </ProtectedRoute>
              }
            >
              <Route index element={<Navigate to="users" replace />} />
              <Route path="users" element={<AdminUsersPage />} />
              <Route path="activity" element={<AdminActivityPage />} />
              <Route path="token-security" element={<AdminTokenSecurityPage />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>

        {/* ── Footer ── */}
        <footer className={header.footer}>
          <p className={`text-[11px] ${text.faint}`}>FPT University — Information Security</p>
        </footer>

        <AssistantChatWidget />
      </div>
    </div>
  );
}
