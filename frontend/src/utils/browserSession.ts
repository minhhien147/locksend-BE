/**
 * browserSession.ts — Phát hiện "trình duyệt đã đóng" để buộc đăng nhập lại.
 *
 * Refresh token là session cookie nên bình thường đóng trình duyệt là mất.
 * Nhưng Chrome/Edge có tùy chọn "Tiếp tục nơi bạn đã dừng" (và luồng restore
 * sau crash) sẽ phục hồi cả session cookie + sessionStorage → session sống lại.
 *
 * Cách chặn: mọi tab đang mở ghi timestamp "còn sống" vào localStorage
 * (dùng chung giữa các tab, KHÔNG được restore theo phiên). Khi app load:
 *   - timestamp còn mới  → vẫn còn tab khác của phiên hiện tại → cho silent refresh.
 *   - timestamp quá cũ   → không tab nào còn sống → coi như đã đóng trình duyệt.
 *
 * Dùng localStorage (không phải sessionStorage) để mở link chia sẻ trong tab mới
 * vẫn giữ được đăng nhập khi trình duyệt chưa hề đóng.
 */

const HEARTBEAT_KEY = "ls_alive";

/** Nhịp ghi heartbeat. Tab ẩn bị Chrome throttle xuống ~1 lần/phút. */
const HEARTBEAT_INTERVAL_MS = 20_000;

/** Khoảng lặng tối đa còn được coi là "trình duyệt vẫn đang mở". */
const STALE_AFTER_MS = 90_000;

function readHeartbeat(): number | null {
  try {
    const raw = localStorage.getItem(HEARTBEAT_KEY);
    if (!raw) return null;
    const ts = Number(raw);
    return Number.isFinite(ts) ? ts : null;
  } catch {
    return null;
  }
}

/** Đánh dấu phiên trình duyệt còn sống. */
export function touchBrowserSession(): void {
  try {
    localStorage.setItem(HEARTBEAT_KEY, String(Date.now()));
  } catch {
    /* private mode / quota — bỏ qua, chỉ còn dựa vào session cookie */
  }
}

export function clearBrowserSession(): void {
  try {
    localStorage.removeItem(HEARTBEAT_KEY);
  } catch {
    /* ignore */
  }
}

/**
 * Chrome/Edge "Memory Saver" & "Sleeping tabs" tự unload tab để tiết kiệm RAM;
 * quay lại tab thì trang được load lại tuy trình duyệt chưa hề đóng. Chrome 68+
 * / Edge 79+ báo qua cờ này (Safari/Firefox không có → undefined).
 */
function wasTabDiscarded(): boolean {
  return (document as Document & { wasDiscarded?: boolean }).wasDiscarded === true;
}

/**
 * true khi không còn tab nào cập nhật heartbeat → trình duyệt đã đóng giữa hai
 * lần truy cập. Chưa có heartbeat (lần đầu / localStorage bị tắt) → không stale,
 * để session cookie tự quyết định.
 */
export function isBrowserSessionStale(): boolean {
  if (wasTabDiscarded()) return false;
  const ts = readHeartbeat();
  if (ts === null) return false;
  return Date.now() - ts > STALE_AFTER_MS;
}

/** Bắt đầu ghi heartbeat. Trả về hàm cleanup. */
export function startBrowserSessionHeartbeat(): () => void {
  touchBrowserSession();

  const timer = window.setInterval(touchBrowserSession, HEARTBEAT_INTERVAL_MS);
  const onWake = () => {
    if (document.visibilityState === "visible") touchBrowserSession();
  };

  document.addEventListener("visibilitychange", onWake);
  window.addEventListener("focus", touchBrowserSession);
  window.addEventListener("pagehide", touchBrowserSession);

  return () => {
    window.clearInterval(timer);
    document.removeEventListener("visibilitychange", onWake);
    window.removeEventListener("focus", touchBrowserSession);
    window.removeEventListener("pagehide", touchBrowserSession);
  };
}
