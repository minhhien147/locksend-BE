import { NavLink, Outlet } from "react-router-dom";
import { useT } from "../i18n/context";
import { admin, surfaceCardAdmin as surfaceCard, text } from "../styles/theme";

export default function AdminLayout() {
  const t = useT();

  return (
    <div className="w-full min-w-0 space-y-6">
      <header>
        <h1 className={`text-2xl font-bold ${text.primary} tracking-tight`}>{t("nav.admin")}</h1>
      </header>

      <nav className={`${surfaceCard} p-1.5 inline-flex flex-wrap gap-1`}>
        <NavLink
          to="/admin/users"
          className={({ isActive }) =>
            `px-4 py-2 rounded-xl text-[13px] font-medium transition ${
              isActive
                ? admin.navActiveUsers
                : admin.navInactive
            }`
          }
        >
          {t("admin.users")}
        </NavLink>
        <NavLink
          to="/admin/activity"
          className={({ isActive }) =>
            `px-4 py-2 rounded-xl text-[13px] font-medium transition ${
              isActive
                ? admin.navActiveActivity
                : admin.navInactive
            }`
          }
        >
          {t("admin.activityNav")}
        </NavLink>
        <NavLink
          to="/admin/token-security"
          className={({ isActive }) =>
            `px-4 py-2 rounded-xl text-[13px] font-medium transition ${
              isActive
                ? admin.navActiveToken
                : admin.navInactive
            }`
          }
        >
          {t("admin.tokenSecurityNav")}
        </NavLink>
      </nav>

      <Outlet />
    </div>
  );
}
