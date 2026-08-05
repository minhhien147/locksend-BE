/** auth.ts — Auth API: register, login, logout, profile, keys, security alerts. */

import axios from "axios";
import { api, BASE_URL } from "./client";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user_id: string;
  email: string;
  display_name: string | null;
  role: string;
  email_verified?: boolean;
}

export interface VerificationStatus {
  email_verified: boolean;
  email: string | null;
  verification_required: boolean;
  resend_cooldown_sec: number;
}

export interface DisplayNameHistoryItem {
  id: string;
  old_display_name: string | null;
  new_display_name: string;
  changed_at: string;
  ip_address: string | null;
}

export interface UserSearchResult {
  id: string;
  email: string | null;
  display_name: string | null;
  has_public_key: boolean;
}

export interface PublicKeyResult {
  user_id: string;
  public_key_x25519: string;
  public_key_ed25519: string;
  key_version: number;
}

export interface UserKeys {
  user_id: string;
  public_key_x25519: string;
  public_key_ed25519: string;
}

export interface UserSecurityAlert {
  id: string;
  alert_type: string;
  file_id: string | null;
  file_name: string | null;
  title_vi: string;
  message_vi: string;
  detail_json: Record<string, unknown> | null;
  is_read: boolean;
  created_at: string;
}

export interface UserSecurityAlertsResponse {
  alerts: UserSecurityAlert[];
  unread_count: number;
}

// ── authApi — dùng axios trực tiếp để tránh interceptor loop ─────────────────

export const authApi = {
  async register(
    username: string,
    password: string,
    display_name?: string
  ): Promise<TokenResponse> {
    const res = await axios.post<TokenResponse>(
      `${BASE_URL}/auth/register`,
      { username, password, display_name },
      { withCredentials: true }
    );
    return res.data;
  },

  async login(username: string, password: string): Promise<TokenResponse> {
    const res = await axios.post<TokenResponse>(
      `${BASE_URL}/auth/login`,
      { username, password },
      { withCredentials: true }
    );
    return res.data;
  },

  async loginWithGoogle(credential: string): Promise<TokenResponse> {
    const res = await axios.post<TokenResponse>(
      `${BASE_URL}/auth/google`,
      { credential },
      { withCredentials: true }
    );
    return res.data;
  },

  async refresh(): Promise<TokenResponse> {
    const res = await axios.post<TokenResponse>(
      `${BASE_URL}/auth/refresh`,
      {},
      { withCredentials: true }
    );
    return res.data;
  },

  async verifyEmail(code: string): Promise<TokenResponse> {
    const res = await api.post<TokenResponse>("/auth/verify-email", { code });
    return res.data;
  },

  async resendVerification(): Promise<void> {
    await api.post("/auth/resend-verification", {});
  },

  async logout(): Promise<void> {
    await axios
      .post(`${BASE_URL}/auth/logout`, {}, { withCredentials: true })
      .catch(() => {});
  },
};

// ── Profile API ───────────────────────────────────────────────────────────────

export async function fetchVerificationStatus(): Promise<VerificationStatus> {
  const res = await api.get<VerificationStatus>("/auth/me/verification-status");
  return res.data;
}

export async function updateProfileEmailApi(email: string): Promise<TokenResponse> {
  const res = await api.patch<TokenResponse>("/auth/me/email", { email });
  return res.data;
}

export async function changePasswordApi(
  current_password: string,
  new_password: string
): Promise<TokenResponse> {
  const res = await api.post<TokenResponse>("/auth/change-password", {
    current_password,
    new_password,
  });
  return res.data;
}

export async function updateProfileApi(display_name: string): Promise<TokenResponse> {
  const res = await api.patch<TokenResponse>("/auth/me", { display_name });
  return res.data;
}

export async function fetchMyDisplayNameHistory(
  limit = 20
): Promise<DisplayNameHistoryItem[]> {
  const res = await api.get<DisplayNameHistoryItem[]>("/auth/me/display-name-history", {
    params: { limit },
  });
  return res.data;
}

// ── User search & public keys ─────────────────────────────────────────────────

export async function searchUsers(q: string): Promise<UserSearchResult[]> {
  if (q.trim().length < 2) return [];
  const res = await api.get<UserSearchResult[]>("/auth/users/search", { params: { q } });
  return res.data;
}

export async function getUserPublicKey(userId: string): Promise<PublicKeyResult> {
  const res = await api.get<PublicKeyResult>(`/auth/users/${userId}/public-key`);
  return res.data;
}

// ── Key management ────────────────────────────────────────────────────────────

export async function getRecipientKeys(userId: string): Promise<UserKeys> {
  const res = await api.get<UserKeys>(`/keys/${userId}`);
  return res.data;
}

export async function storeMyPublicKey(params: {
  externalId: string;
  publicKeyX25519: string;
  publicKeyEd25519: string;
  encryptedKeyBlob?: string;
}): Promise<void> {
  await api.post("/keys", {
    user_id: params.externalId,
    public_key_x25519: params.publicKeyX25519,
    public_key_ed25519: params.publicKeyEd25519,
    ...(params.encryptedKeyBlob ? { encrypted_key_blob: params.encryptedKeyBlob } : {}),
  });
}

export async function fetchMyEncryptedKeyBlob(): Promise<{
  encrypted_key_blob: string | null;
  has_keys: boolean;
  public_key_x25519?: string;
  public_key_ed25519?: string;
  keypair_expires_at?: string | null;
  keypair_days_left?: number | null;
  keypair_expired?: boolean;
  keypair_expiring_soon?: boolean;
  key_version?: number;
}> {
  const res = await api.get("/keys/my-encrypted-blob");
  return res.data;
}

// ── Security alerts ───────────────────────────────────────────────────────────

export async function fetchSecurityAlerts(
  limit = 20,
  unreadOnly = false
): Promise<UserSecurityAlertsResponse> {
  const res = await api.get<UserSecurityAlertsResponse>("/auth/me/security-alerts", {
    params: { limit, unread_only: unreadOnly },
  });
  return res.data;
}

export async function markSecurityAlertsRead(alertIds: string[]): Promise<void> {
  await api.patch("/auth/me/security-alerts/read", { alert_ids: alertIds });
}
