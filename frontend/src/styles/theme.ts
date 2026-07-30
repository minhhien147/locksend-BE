/**
 * LockSend — "Security Console" design direction
 * Ref: Linear (density, nav) + Stripe (forms) + cold slate/blue palette.
 * - Một accent (blue) cho CTA; sky cho highlight text
 * - Viền thay shadow; blur tối thiểu
 * - Radius: md (control) / lg (surface)
 */

export const shell = {
  page: "min-h-screen flex flex-col text-slate-900 dark:text-slate-100",
  auth: "min-h-screen flex relative",
  authAsideBg:
    "border-r border-slate-200/80 bg-slate-50/60 " +
    "dark:border-white/[0.07] dark:bg-[#0a0e14]/55",
  authAside:
    "hidden lg:flex lg:w-[42%] xl:w-[38%] relative z-20 flex-col justify-between p-10 xl:p-14",
  authPanel: "flex-1 relative z-20 flex items-center justify-center p-6 sm:p-10",
};

/** Panel chính — nền đủ đặc để đọc trên ảnh nền */
export const surfaceCard =
  "rounded-lg border border-slate-200 bg-white shadow-sm " +
  "dark:border-white/[0.1] dark:bg-[#0d1118]/96 dark:shadow-lg dark:shadow-black/25";

/** Hàng trong danh sách (history, vault, …) */
export const surfaceListItem =
  "rounded-lg border border-slate-200 bg-white p-4 space-y-3 transition-colors " +
  "hover:border-slate-300 dark:border-white/[0.1] dark:bg-[#12161f]/95 dark:hover:border-white/[0.14]";

export const surfaceCardAdmin = surfaceCard;

export const surfaceInset =
  "rounded-md border border-slate-200 bg-slate-50 px-3 py-2 " +
  "dark:border-white/[0.09] dark:bg-[#0a0e14]/80";

const controlBase =
  "h-9 min-h-9 rounded-md text-sm font-medium transition-colors duration-150 " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40 focus-visible:ring-offset-2 " +
  "focus-visible:ring-offset-white dark:focus-visible:ring-offset-[#0a0e14] " +
  "disabled:opacity-45 disabled:pointer-events-none";

export const inputBase =
  "w-full h-9 rounded-md px-3 text-sm " +
  "bg-white border border-slate-300/90 text-slate-900 placeholder:text-slate-400 " +
  "focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/25 " +
  "disabled:opacity-50 " +
  "dark:bg-[#12161f] dark:border-white/[0.1] dark:text-slate-100 dark:placeholder:text-slate-500 " +
  "dark:focus:border-blue-400/80 dark:focus:ring-blue-500/20";

export const btnGhost =
  "border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 " +
  "dark:border-white/12 dark:bg-transparent dark:text-slate-300 dark:hover:bg-white/[0.05]";

export const keyField =
  "rounded-md border border-slate-200/80 bg-slate-50 px-3 py-2 text-[13px] font-mono text-slate-800 break-all " +
  "dark:border-white/[0.09] dark:bg-[#0a0e14] dark:text-slate-200";

export const text = {
  primary: "text-slate-900 dark:text-slate-100",
  secondary: "text-slate-600 dark:text-slate-300",
  muted: "text-slate-500 dark:text-slate-400",
  faint: "text-slate-400 dark:text-slate-500",
  onBrand: "text-slate-700 dark:text-slate-200",
};

export const header = {
  bar:
    "sticky top-0 z-50 border-b border-slate-200/90 bg-white/90 backdrop-blur-sm " +
    "dark:border-white/[0.07] dark:bg-[#0a0e14]/88",
  footer: "border-t border-slate-200/80 py-4 text-center dark:border-white/[0.06]",
  divider: "border-slate-200/80 dark:border-white/[0.07]",
};

export const nav = {
  inactive:
    "text-slate-600 hover:text-slate-900 hover:bg-slate-100/90 " +
    "dark:text-slate-400 dark:hover:text-slate-100 dark:hover:bg-white/[0.05]",
  inactiveDanger:
    "text-slate-600 hover:text-rose-700 hover:bg-rose-50 " +
    "dark:text-slate-400 dark:hover:text-rose-400 dark:hover:bg-rose-500/[0.08]",
  active:
    "bg-slate-100 text-slate-900 font-medium " +
    "dark:bg-white/[0.08] dark:text-slate-100",
  activeDanger:
    "bg-rose-50 text-rose-800 font-medium " +
    "dark:bg-rose-500/12 dark:text-rose-300",
};

export const panel = {
  subtle:
    "bg-slate-50 border border-slate-200/80 " +
    "dark:bg-white/[0.03] dark:border-white/[0.07]",
  hover: "hover:border-slate-300 dark:hover:border-white/12",
  dropdown:
    "rounded-md border border-slate-200 bg-white shadow-lg " +
    "dark:border-white/[0.1] dark:bg-[#12161f]",
};

export const orb = {
  indigo: "bg-blue-500/[0.04] dark:bg-blue-600/[0.05]",
  violet: "bg-sky-500/[0.03] dark:bg-sky-600/[0.04]",
  sky: "bg-sky-500/[0.03] dark:bg-sky-600/[0.03]",
};

export const brand = {
  lock: "text-slate-900 dark:text-slate-100",
  send: "text-blue-800 dark:text-blue-500",
};

export const label =
  "text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500 dark:text-slate-500";

export const sectionTitle = "text-base font-semibold text-slate-900 dark:text-slate-100";

export const pageTitle = "text-lg font-semibold tracking-tight text-slate-900 dark:text-slate-100";

export const pageDesc = "text-sm text-slate-500 dark:text-slate-400 mt-1";

export const btn = {
  primary:
    `inline-flex items-center justify-center gap-2 px-4 ${controlBase} ` +
    "bg-blue-700 text-white hover:bg-blue-600 active:bg-blue-800 " +
    "dark:bg-blue-700 dark:hover:bg-blue-600 dark:active:bg-blue-800",
  secondary:
    `inline-flex items-center justify-center gap-2 px-4 ${controlBase} ` +
    "border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 " +
    "dark:border-white/12 dark:bg-transparent dark:text-slate-200 dark:hover:bg-white/[0.05]",
  danger:
    `inline-flex items-center justify-center gap-2 px-4 ${controlBase} ` +
    "border border-rose-300/80 bg-white text-rose-700 hover:bg-rose-50 " +
    "dark:border-rose-500/30 dark:bg-transparent dark:text-rose-400 dark:hover:bg-rose-500/10",
  ghost:
    `inline-flex items-center justify-center gap-2 px-3 ${controlBase} ` +
    "text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-white/[0.05]",
};

export const badge = {
  neutral:
    "inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium " +
    "bg-slate-100 text-slate-600 dark:bg-white/[0.06] dark:text-slate-300",
  success:
    "inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium " +
    "bg-emerald-50 text-emerald-800 dark:bg-emerald-500/12 dark:text-emerald-300",
  warning:
    "inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium " +
    "bg-amber-50 text-amber-800 dark:bg-amber-500/12 dark:text-amber-300",
  danger:
    "inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium " +
    "bg-rose-50 text-rose-800 dark:bg-rose-500/12 dark:text-rose-300",
  info:
    "inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium " +
    "bg-blue-50 text-blue-800 dark:bg-blue-500/12 dark:text-blue-300",
};

export const alert = {
  info:
    "rounded-md border border-slate-200 bg-slate-50 px-3.5 py-3 text-sm text-slate-700 " +
    "dark:border-white/[0.08] dark:bg-white/[0.04] dark:text-slate-300",
  warning:
    "rounded-md border border-amber-200/90 bg-amber-50 px-3.5 py-3 text-sm text-amber-900 " +
    "dark:border-amber-500/25 dark:bg-amber-500/[0.08] dark:text-amber-200",
  error:
    "rounded-md border border-rose-200/90 bg-rose-50 px-3.5 py-3 text-sm text-rose-800 " +
    "dark:border-rose-500/25 dark:bg-rose-500/[0.08] dark:text-rose-300",
  success:
    "rounded-md border border-emerald-200/90 bg-emerald-50 px-3.5 py-3 text-sm text-emerald-900 " +
    "dark:border-emerald-500/25 dark:bg-emerald-500/[0.08] dark:text-emerald-200",
};

export const dropzone = {
  base:
    "rounded-lg border border-dashed border-slate-300/90 bg-slate-50/50 transition-colors " +
    "dark:border-white/15 dark:bg-white/[0.02]",
  active:
    "border-blue-400 bg-blue-50/40 dark:border-blue-400/50 dark:bg-blue-500/[0.08]",
  filled:
    "border-slate-300/80 bg-white/70 dark:border-white/12 dark:bg-white/[0.04]",
};

export const tabs = {
  wrap:
    "inline-flex p-0.5 rounded-md border border-slate-200/90 bg-slate-100/80 " +
    "dark:border-white/[0.08] dark:bg-white/[0.04]",
  item:
    "px-3 py-1.5 rounded-[5px] text-sm font-medium text-slate-600 transition-colors " +
    "dark:text-slate-400",
  itemActive:
    "bg-white text-slate-900 shadow-sm dark:bg-white/[0.09] dark:text-slate-100",
};

export const table = {
  wrap: "overflow-hidden rounded-lg border border-slate-200 dark:border-white/[0.08]",
  head:
    "text-left text-[10px] font-semibold uppercase tracking-wider text-slate-500 bg-slate-50 " +
    "dark:bg-white/[0.03] dark:text-slate-400",
  row:
    "border-t border-slate-100 hover:bg-slate-50/80 " +
    "dark:border-white/[0.05] dark:hover:bg-white/[0.02]",
  cell: "px-4 py-3 text-sm text-slate-700 dark:text-slate-300",
};

export const admin = {
  title: "text-lg font-bold text-slate-900 dark:text-white tracking-tight",
  desc: "text-sm text-slate-600 dark:text-white/40 mt-0.5",
  legend: "text-[11px] text-slate-600 dark:text-white/38",
  footer: "text-center text-[11px] text-slate-500 dark:text-white/30 tabular-nums",
  empty: "text-sm text-slate-500 dark:text-white/35",
  btnGhost:
    "inline-flex items-center justify-center gap-2 px-3 py-2 rounded-md border text-sm transition disabled:opacity-40 " +
    "border-slate-300 text-slate-700 hover:bg-slate-100 " +
    "dark:border-white/12 dark:text-white/70 dark:hover:bg-white/[0.05] dark:hover:text-white",
  tableHead:
    "border-b text-left text-[10px] font-semibold uppercase tracking-wider " +
    "border-slate-200 bg-slate-900 text-white/90 " +
    "dark:border-white/[0.08] dark:bg-white/[0.04] dark:text-white/40",
  tableDivide: "divide-y divide-slate-100 dark:divide-white/[0.06]",
  rowHover: "transition hover:bg-slate-50 dark:hover:bg-white/[0.02]",
  rowHighlight: "bg-blue-50 dark:bg-blue-500/[0.06]",
  cellName: "font-medium text-slate-900 dark:text-white/90",
  cellSub: "text-xs text-slate-500 dark:text-white/35",
  cellMeta: "text-xs text-slate-600 dark:text-white/40 whitespace-nowrap tabular-nums",
  select:
    "text-xs font-medium rounded-md px-2.5 py-1.5 cursor-pointer focus:outline-none focus:ring-2 " +
    "bg-slate-900 border border-slate-600 text-white focus:ring-blue-500/40 " +
    "dark:bg-[#12161f] dark:border-white/12 dark:focus:ring-blue-500/40",
  navActiveUsers:
    "bg-slate-900 text-rose-200 ring-1 ring-slate-600 " +
    "dark:bg-rose-500/15 dark:text-rose-300 dark:ring-rose-400/25",
  navActiveActivity:
    "bg-slate-900 text-sky-200 ring-1 ring-slate-600 " +
    "dark:bg-sky-500/15 dark:text-sky-300 dark:ring-sky-400/25",
  navActiveToken:
    "bg-slate-900 text-violet-200 ring-1 ring-slate-600 " +
    "dark:bg-violet-500/15 dark:text-violet-300 dark:ring-violet-400/25",
  navInactive: `${nav.inactive} hover:bg-slate-100 dark:hover:bg-white/[0.04]`,
  roleOwner:
    "bg-slate-900 text-blue-200 border border-slate-600 " +
    "dark:bg-blue-500/12 dark:text-blue-300 dark:border-blue-500/30",
  roleRecipient:
    "bg-slate-900 text-emerald-200 border border-slate-600 " +
    "dark:bg-emerald-500/12 dark:text-emerald-300 dark:border-emerald-500/28",
  roleAdmin:
    "bg-slate-900 text-rose-200 border border-slate-600 " +
    "dark:bg-rose-500/12 dark:text-rose-300 dark:border-rose-500/28",
  selfTag:
    "text-[10px] px-1.5 py-0.5 rounded font-semibold shrink-0 " +
    "bg-slate-800 text-blue-200 dark:bg-blue-500/15 dark:text-blue-300",
  deleteBtn:
    "inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium transition disabled:opacity-40 " +
    "text-rose-700 border border-rose-300 hover:bg-rose-50 " +
    "dark:text-rose-400/90 dark:border-rose-500/25 dark:hover:bg-rose-500/10",
  ink: "bg-slate-900 text-white dark:bg-white/[0.06] dark:text-white/70",
  inkMuted: "text-white/80 dark:text-white/35",
  inkLabel: "text-white/70 dark:text-white/70",
  sectionTitle: "text-sm font-semibold text-slate-900 dark:text-white/70",
  tabActive: "bg-slate-900 text-blue-200 dark:bg-blue-500/15 dark:text-blue-300",
  tabInactive:
    "text-slate-600 hover:text-slate-900 hover:bg-slate-100 " +
    "dark:text-white/40 dark:hover:text-white/70 dark:hover:bg-white/[0.04]",
  tableHeadInner:
    "text-left text-[10px] border-b " +
    "border-slate-200 text-slate-600 bg-slate-100 " +
    "dark:border-white/[0.05] dark:text-white/30 dark:bg-transparent",
  rowInner:
    "border-b border-slate-100 hover:bg-slate-50 dark:border-white/[0.04] dark:hover:bg-white/[0.02]",
  cellInner: "text-slate-800 dark:text-white/80",
  cellInnerSub: "text-slate-500 dark:text-white/30",
  divider: "border-slate-200 dark:border-white/[0.05]",
  dividerLight: "bg-slate-200 dark:bg-white/10",
};

export const linkAccent =
  "text-blue-700 hover:text-blue-900 font-medium dark:text-blue-500 dark:hover:text-blue-400";
