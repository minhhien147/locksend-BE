/**
 * AuthContext — quản lý trạng thái xác thực toàn cục.
 *
 * Access token: chỉ lưu trong memory (module var trong api.ts).
 *               Không còn localStorage → không bị XSS đọc.
 *
 * Refresh token: httpOnly cookie do backend quản lý.
 *               Frontend không đọc được, tự động gửi kèm request đến /auth/*.
 *
 * Silent refresh on mount:
 *   Mỗi lần load trang → gọi POST /auth/refresh.
 *   Nếu cookie còn hợp lệ → nhận access token mới, khôi phục session.
 *   Nếu không → user cần đăng nhập lại.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import type { ReactNode } from "react";
import {
  authApi,
  changePasswordApi,
  setAccessToken,
  updateProfileApi,
  updateProfileEmailApi,
  type TokenResponse,
} from "../utils/api";
import { clearAll as clearKeyVault } from "../utils/keyVault";
import { clearPageDraft } from "../utils/pageDraft";
import {
  clearBrowserSession,
  isBrowserSessionStale,
  startBrowserSessionHeartbeat,
} from "../utils/browserSession";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface AuthUser {
  user_id: string;
  email: string;
  display_name: string | null;
  role: string;
  email_verified: boolean;
}

function userFromToken(res: TokenResponse): AuthUser {
  return {
    user_id: res.user_id,
    email: res.email,
    display_name: res.display_name,
    role: res.role,
    email_verified: res.email_verified ?? true,
  };
}

interface AuthContextValue {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<TokenResponse>;
  loginWithGoogle: (credential: string) => Promise<TokenResponse>;
  register: (username: string, password: string, displayName?: string) => Promise<TokenResponse>;
  logout: () => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  updateDisplayName: (displayName: string) => Promise<void>;
  updateEmail: (email: string) => Promise<TokenResponse>;
  applyTokenResponse: (res: TokenResponse) => void;
}

// ── Context ───────────────────────────────────────────────────────────────────

const AuthContext = createContext<AuthContextValue | null>(null);

// ── Provider ──────────────────────────────────────────────────────────────────

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  // true trong khi đang kiểm tra session lúc đầu (tránh flash redirect về /login)
  const [isLoading, setIsLoading] = useState(true);

  // ── Silent refresh on mount ─────────────────────────────────────────────────
  useEffect(() => {
    // Trình duyệt đã đóng từ lần truy cập trước: dù cookie có được restore thì
    // vẫn revoke nó trên server và bắt đăng nhập lại.
    if (isBrowserSessionStale()) {
      clearBrowserSession();
      clearKeyVault();
      authApi.logout().finally(() => {
        setAccessToken(null);
        setUser(null);
        setIsLoading(false);
      });
      return;
    }

    authApi
      .refresh()
      .then((res) => {
        setAccessToken(res.access_token);
        setUser(userFromToken(res));
      })
      .catch(() => {
        // Cookie không còn hoặc đã expire — cần đăng nhập lại
        setAccessToken(null);
        setUser(null);
        clearBrowserSession();
      })
      .finally(() => setIsLoading(false));
  }, []);

  // Chỉ ghi heartbeat khi đang có session → tránh giữ dấu vết sau khi logout.
  const isAuthenticated = !!user;
  useEffect(() => {
    if (!isAuthenticated) return;
    return startBrowserSessionHeartbeat();
  }, [isAuthenticated]);

  // ── Login ───────────────────────────────────────────────────────────────────
  const login = useCallback(async (username: string, password: string) => {
    const res = await authApi.login(username, password);
    setAccessToken(res.access_token);
    setUser(userFromToken(res));
    return res;
  }, []);

  const loginWithGoogle = useCallback(async (credential: string) => {
    const res = await authApi.loginWithGoogle(credential);
    setAccessToken(res.access_token);
    setUser(userFromToken(res));
    return res;
  }, []);

  // ── Register ────────────────────────────────────────────────────────────────
  const register = useCallback(
    async (username: string, password: string, displayName?: string) => {
      const res = await authApi.register(username, password, displayName);
      setAccessToken(res.access_token);
      setUser(userFromToken(res));
      return res;
    },
    []
  );

  // ── Logout ──────────────────────────────────────────────────────────────────
  const logout = useCallback(async () => {
    await authApi.logout(); // revoke refresh token trên server + xóa cookie
    setAccessToken(null);
    setUser(null);
    clearBrowserSession();
    clearKeyVault(); // xóa private key khỏi RAM + sessionStorage
    clearPageDraft("profile-settings"); // draft cũ (không theo user)
  }, []);

  const applyTokenResponse = useCallback((res: TokenResponse) => {
    setAccessToken(res.access_token);
    setUser(userFromToken(res));
  }, []);

  const changePassword = useCallback(
    async (currentPassword: string, newPassword: string) => {
      const res = await changePasswordApi(currentPassword, newPassword);
      applyTokenResponse(res);
    },
    [applyTokenResponse]
  );

  const updateDisplayName = useCallback(
    async (displayName: string) => {
      const res = await updateProfileApi(displayName);
      applyTokenResponse(res);
    },
    [applyTokenResponse]
  );

  const updateEmail = useCallback(
    async (email: string) => {
      const res = await updateProfileEmailApi(email);
      applyTokenResponse(res);
      return res;
    },
    [applyTokenResponse]
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      isAuthenticated,
      isLoading,
      login,
      loginWithGoogle,
      register,
      logout,
      changePassword,
      updateDisplayName,
      updateEmail,
      applyTokenResponse,
    }),
    [user, isAuthenticated, isLoading, login, loginWithGoogle, register, logout, changePassword, updateDisplayName, updateEmail, applyTokenResponse]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth phải dùng trong <AuthProvider>");
  return ctx;
}
