/**
 * keyVault.ts — Zero-knowledge in-memory private key vault.
 *
 * Mô hình bảo mật:
 *   - Private key PLAINTEXT chỉ tồn tại trong RAM (_keys).
 *   - sessionStorage lưu "session wrapper": private key được mã hóa bằng một
 *     ephemeral AES-256-GCM key ngẫu nhiên per-tab.
 *     Tab đóng → sessionStorage bị xóa → private key biến mất hoàn toàn.
 *   - Không có gì liên quan đến private key plaintext trong localStorage.
 *   - Server chỉ biết encrypted_key_blob (mã hóa bằng passphrase người dùng).
 *
 * Flow F5 (tab reload):
 *   1. _keys = null (JS RAM bị xóa)
 *   2. restoreFromSession() → sessionStorage → decrypt → _keys (RAM)
 *   3. Không cần nhập lại passphrase
 *
 * Auto-lock (inactivity):
 *   Sau AUTO_LOCK_MS ms không có hoạt động → clearAll() → yêu cầu passphrase lại.
 *   App.tsx gọi resetLockTimer() mỗi khi user tương tác.
 *
 * Logout / tab close:
 *   clearAll() → _keys = null + sessionStorage cleared
 */

import type { UnlockedKeyPairs } from "./crypto";
import { toBase64, fromBase64 } from "./crypto";

// ── Constants ─────────────────────────────────────────────────────────────────

const SESSION_WRAPPER_KEY = "ls_sw";  // Encrypted key blob trong sessionStorage
const SESSION_KEY_KEY = "ls_sk";      // Ephemeral AES key trong sessionStorage
export const AUTO_LOCK_MS = 30 * 60 * 1000; // 30 phút không hoạt động

// ── State ─────────────────────────────────────────────────────────────────────

let _keys: UnlockedKeyPairs | null = null;
let _lockTimer: ReturnType<typeof setTimeout> | null = null;
let _onLockCallbacks: Array<() => void> = [];

// ── Internal helpers ─────────────────────────────────────────────────────────

function _toAB(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

function _serializeKeys(keys: UnlockedKeyPairs): string {
  return JSON.stringify({
    x25519: {
      privateKey: toBase64(keys.x25519.privateKey),
      publicKey: toBase64(keys.x25519.publicKey),
    },
    ed25519: {
      privateKey: toBase64(keys.ed25519.privateKey),
      publicKey: toBase64(keys.ed25519.publicKey),
    },
  });
}

function _deserializeKeys(json: string): UnlockedKeyPairs {
  const p = JSON.parse(json) as {
    x25519: { privateKey: string; publicKey: string };
    ed25519: { privateKey: string; publicKey: string };
  };
  return {
    x25519: {
      privateKey: fromBase64(p.x25519.privateKey),
      publicKey: fromBase64(p.x25519.publicKey),
    },
    ed25519: {
      privateKey: fromBase64(p.ed25519.privateKey),
      publicKey: fromBase64(p.ed25519.publicKey),
    },
  };
}

// ── Session wrapper (sessionStorage) ─────────────────────────────────────────

async function _writeSessionWrapper(keys: UnlockedKeyPairs): Promise<void> {
  try {
    // 1. Ephemeral AES-256-GCM key (random per session)
    const sessionKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", sessionKey));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // 2. Encrypt serialized keys
    const plaintext = new TextEncoder().encode(_serializeKeys(keys));
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: _toAB(iv) },
      sessionKey,
      _toAB(plaintext)
    );

    // 3. Persist both halves in sessionStorage
    sessionStorage.setItem(SESSION_KEY_KEY, toBase64(rawKey));
    sessionStorage.setItem(
      SESSION_WRAPPER_KEY,
      JSON.stringify({ iv: toBase64(iv), ct: toBase64(new Uint8Array(encrypted)) })
    );
  } catch (e) {
    // sessionStorage disabled or quota exceeded — continue without wrapper
    console.warn("[keyVault] sessionStorage write failed:", e);
  }
}

function _clearSessionStorage(): void {
  try {
    sessionStorage.removeItem(SESSION_KEY_KEY);
    sessionStorage.removeItem(SESSION_WRAPPER_KEY);
  } catch { /* ignore */ }
}

// ── Auto-lock timer ──────────────────────────────────────────────────────────

function _hardLock(): void {
  _keys = null;
  _lockTimer = null;
  _clearSessionStorage();
  _onLockCallbacks.forEach((cb) => {
    try { cb(); } catch { /* ignore */ }
  });
}

/** Reset inactivity timer. Gọi từ App.tsx khi user tương tác. */
export function resetLockTimer(): void {
  if (_lockTimer !== null) clearTimeout(_lockTimer);
  if (_keys === null) return; // không cần timer khi vault đã trống
  _lockTimer = setTimeout(() => { _hardLock(); }, AUTO_LOCK_MS);
}

/**
 * Đăng ký callback được gọi khi vault bị hard-lock (timeout / logout).
 * Returns unsubscribe function.
 */
export function onLock(cb: () => void): () => void {
  _onLockCallbacks.push(cb);
  return () => {
    _onLockCallbacks = _onLockCallbacks.filter((c) => c !== cb);
  };
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Lưu keypair vào RAM và tạo session wrapper trong sessionStorage.
 * Gọi sau khi giải mã blob bằng passphrase.
 */
export async function setKeys(keys: UnlockedKeyPairs): Promise<void> {
  _keys = keys;
  await _writeSessionWrapper(keys);
  resetLockTimer();
  try {
    window.dispatchEvent(new Event("ls-vault-unlocked"));
  } catch {
    /* non-browser */
  }
}

/**
 * Lấy keypair từ RAM.
 * Returns null nếu chưa unlock (vault chưa được giải mã hoặc đã lock).
 */
export function getKeys(): UnlockedKeyPairs | null {
  if (_keys !== null) resetLockTimer();
  return _keys;
}

/** Keys đang có trong RAM (đã unlock)? */
export function isUnlocked(): boolean {
  return _keys !== null;
}

/** Có session wrapper trong sessionStorage? (kiểm tra trước khi F5-restore) */
export function hasSessionWrapper(): boolean {
  try {
    return (
      sessionStorage.getItem(SESSION_KEY_KEY) !== null &&
      sessionStorage.getItem(SESSION_WRAPPER_KEY) !== null
    );
  } catch {
    return false;
  }
}

/**
 * Khôi phục keypair từ sessionStorage wrapper vào RAM.
 * Dùng sau F5 — RAM bị xóa nhưng sessionStorage còn.
 * Returns null nếu không có wrapper hoặc wrapper bị hỏng.
 */
export async function restoreFromSession(): Promise<UnlockedKeyPairs | null> {
  try {
    const rawKeyB64 = sessionStorage.getItem(SESSION_KEY_KEY);
    const wrapperJson = sessionStorage.getItem(SESSION_WRAPPER_KEY);
    if (!rawKeyB64 || !wrapperJson) return null;

    const { iv, ct } = JSON.parse(wrapperJson) as { iv: string; ct: string };
    const sessionKey = await crypto.subtle.importKey(
      "raw",
      _toAB(fromBase64(rawKeyB64)),
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: _toAB(fromBase64(iv)) },
      sessionKey,
      _toAB(fromBase64(ct))
    );

    const keys = _deserializeKeys(new TextDecoder().decode(decrypted));
    _keys = keys;
    resetLockTimer();
    try {
      window.dispatchEvent(new Event("ls-vault-unlocked"));
    } catch {
      /* non-browser */
    }
    return keys;
  } catch (e) {
    console.warn("[keyVault] restoreFromSession failed, clearing wrapper:", e);
    _clearSessionStorage();
    return null;
  }
}

/**
 * Khóa mềm: xóa RAM, giữ sessionStorage wrapper.
 * restoreFromSession() vẫn hoạt động mà không cần passphrase.
 * Dùng cho nút "Khóa phiên" trên UI.
 */
export function lockKeys(): void {
  _keys = null;
  if (_lockTimer !== null) { clearTimeout(_lockTimer); _lockTimer = null; }
}

/**
 * Xóa hoàn toàn: RAM + sessionStorage.
 * Gọi khi logout hoặc inactivity timeout.
 * Sau khi gọi, user cần nhập passphrase để unlock lại.
 */
export function clearAll(): void {
  _hardLock();
}

/**
 * Xóa legacy key khỏi localStorage (dùng sau khi đã migrate lên server).
 */
export function clearLegacyLocalStorage(): void {
  try {
    localStorage.removeItem("secure_file_sharing_keys");
  } catch { /* ignore */ }
}

/** Kiểm tra có legacy key trong localStorage không (chưa migrate). */
export function hasLegacyLocalStorage(): boolean {
  try {
    return localStorage.getItem("secure_file_sharing_keys") !== null;
  } catch {
    return false;
  }
}
