/**
 * KeyManagement — Quản lý keypair zero-knowledge.
 *
 * Luồng:
 *  1. Mount: fetch encrypted_key_blob từ server + check vault
 *  2. Nếu chưa có blob: hiện form tạo mới + upload
 *  3. Nếu có blob, vault locked: hiện form nhập passphrase
 *  4. Nếu vault unlocked: hiện info, đổi passphrase, lock session
 *  5. Legacy migration: nếu có key cũ trong localStorage, offer upload lên server
 */

import { useState, useEffect, useRef } from "react";
import { useDraftState } from "../hooks/useDraftState";
import {
  generateX25519KeyPair,
  generateEd25519KeyPair,
  encryptKeyBlob,
  decryptKeyBlob,
  decryptLegacyLocalStorage,
  hasLegacyLocalStorageKey,
  clearLegacyLocalStorage,
  validatePassphrase,
  toBase64,
  type UnlockedKeyPairs,
} from "../utils/crypto";
import {
  getKeys,
  setKeys,
  isUnlocked,
  lockKeys,
  clearAll,
  onLock,
} from "../utils/keyVault";
import { fetchServerEncryptedBlob, syncPublicKeysToServer } from "../utils/keySync";
import {
  storeMyPublicKey,
  fetchMyEncryptedKeyBlob,
  getAccessToken,
  parseJwtPayload,
} from "../utils/api";
import {
  surfaceCard,
  keyField,
  inputBase,
  text,
  btnGhost,
  btn,
  header,
} from "../styles/theme";
import { useT } from "../i18n/context";

type PageState =
  | { phase: "loading" }
  | { phase: "no_keys"; hasLegacy: boolean }
  | { phase: "blob_missing"; hasLegacy: boolean }
  | { phase: "locked"; blob: string }
  | { phase: "unlocked"; keys: UnlockedKeyPairs };

type DangerStep = null | "replace-keys" | "delete-keys";

type KeypairMeta = {
  expires_at: string | null;
  days_left: number | null;
  expired: boolean;
  expiring_soon: boolean;
  key_version?: number;
};

const KEYS_PAGE_KEY = "keys";

export default function KeyManagement() {
  const t = useT();
  const [pageState, setPageState] = useState<PageState>({ phase: "loading" });
  const [dangerStep, setDangerStep] = useDraftState<DangerStep>(
    KEYS_PAGE_KEY,
    "dangerStep",
    null,
    "persist"
  );
  const [status, setStatus] = useState<{ msg: string; isError: boolean } | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [keypairMeta, setKeypairMeta] = useState<KeypairMeta | null>(null);

  // Form fields — chỉ RAM (không ghi passphrase ra sessionStorage)
  const [newPassphrase, setNewPassphrase] = useDraftState(KEYS_PAGE_KEY, "newPassphrase", "", "memory");
  const [confirmPassphrase, setConfirmPassphrase] = useDraftState(
    KEYS_PAGE_KEY,
    "confirmPassphrase",
    "",
    "memory"
  );
  const [unlockPassphrase, setUnlockPassphrase] = useDraftState(
    KEYS_PAGE_KEY,
    "unlockPassphrase",
    "",
    "memory"
  );
  const [currentChangePassphrase, setCurrentChangePassphrase] = useDraftState(
    KEYS_PAGE_KEY,
    "currentChangePassphrase",
    "",
    "memory"
  );
  const [changePassphraseVal, setChangePassphraseVal] = useDraftState(
    KEYS_PAGE_KEY,
    "changePassphraseVal",
    "",
    "memory"
  );
  const [changePhraseConfirm, setChangePhraseConfirm] = useDraftState(
    KEYS_PAGE_KEY,
    "changePhraseConfirm",
    "",
    "memory"
  );
  const [legacyPassphrase, setLegacyPassphrase] = useDraftState(
    KEYS_PAGE_KEY,
    "legacyPassphrase",
    "",
    "memory"
  );

  const statusTimerRef = useRef<number | null>(null);

  async function loadKeypairMeta() {
    try {
      const data = await fetchMyEncryptedKeyBlob();
      setKeypairMeta({
        expires_at: data.keypair_expires_at ?? null,
        days_left: data.keypair_days_left ?? null,
        expired: data.keypair_expired ?? false,
        expiring_soon: data.keypair_expiring_soon ?? false,
        key_version: data.key_version,
      });
      return data;
    } catch {
      setKeypairMeta(null);
      return null;
    }
  }

  // ── Load initial state ───────────────────────────────────────────────────────

  async function loadState() {
    setPageState({ phase: "loading" });
    try {
      const data = await loadKeypairMeta();
      // Check vault first (F5 already restored)
      if (isUnlocked()) {
        const k = getKeys()!;
        setPageState({ phase: "unlocked", keys: k });
        return;
      }
      if (!data?.has_keys) {
        setPageState({ phase: "no_keys", hasLegacy: hasLegacyLocalStorageKey() });
      } else if (!data.encrypted_key_blob) {
        setPageState({ phase: "blob_missing", hasLegacy: hasLegacyLocalStorageKey() });
      } else {
        setPageState({ phase: "locked", blob: data.encrypted_key_blob });
      }
    } catch {
      setPageState({ phase: "no_keys", hasLegacy: hasLegacyLocalStorageKey() });
    }
  }

  useEffect(() => { void loadState(); }, []);

  useEffect(() => {
    const onVaultUnlocked = () => {
      const k = getKeys();
      if (k) setPageState({ phase: "unlocked", keys: k });
      else void loadState();
    };
    const unsubLock = onLock(() => { void loadState(); });
    window.addEventListener("ls-vault-unlocked", onVaultUnlocked);
    return () => {
      unsubLock();
      window.removeEventListener("ls-vault-unlocked", onVaultUnlocked);
    };
  }, []);

  useEffect(() => () => {
    if (statusTimerRef.current !== null) clearTimeout(statusTimerRef.current);
  }, []);

  // ── Helpers ──────────────────────────────────────────────────────────────────

  function showStatus(msg: string, isError = false) {
    setStatus({ msg, isError });
    if (statusTimerRef.current !== null) clearTimeout(statusTimerRef.current);
    statusTimerRef.current = window.setTimeout(() => {
      setStatus(null);
      statusTimerRef.current = null;
    }, 4500);
  }

  function getMyExternalId(): string | null {
    const token = getAccessToken();
    if (!token) return null;
    return (parseJwtPayload(token)?.sub as string) ?? null;
  }

  async function uploadToServer(
    keys: UnlockedKeyPairs,
    encryptedBlob: string
  ): Promise<void> {
    const externalId = getMyExternalId();
    if (!externalId) throw new Error(t("keys.userIdFailed"));
    await storeMyPublicKey({
      externalId,
      publicKeyX25519: toBase64(keys.x25519.publicKey),
      publicKeyEd25519: toBase64(keys.ed25519.publicKey),
      encryptedKeyBlob: encryptedBlob,
    });
  }

  function copyToClipboard(value: string, id: string) {
    void navigator.clipboard.writeText(value);
    setCopied(id);
    window.setTimeout(() => setCopied(null), 2000);
  }

  // ── Actions ──────────────────────────────────────────────────────────────────

  async function handleGenerate() {
    const err = validatePassphrase(newPassphrase);
    if (err) { showStatus(t(`errors.${err}`, { n: 8 }), true); return; }
    if (newPassphrase !== confirmPassphrase) {
      showStatus(t("keys.confirmMismatch"), true);
      return;
    }
    setBusy(true);
    try {
      const x25519Keys = generateX25519KeyPair();
      const ed25519Keys = generateEd25519KeyPair();
      const blob = await encryptKeyBlob(x25519Keys, ed25519Keys, newPassphrase);
      await uploadToServer({ x25519: x25519Keys, ed25519: ed25519Keys }, blob);
      await setKeys({ x25519: x25519Keys, ed25519: ed25519Keys });
      setNewPassphrase("");
      setConfirmPassphrase("");
      setDangerStep(null);
      setPageState({ phase: "unlocked", keys: { x25519: x25519Keys, ed25519: ed25519Keys } });
      await loadKeypairMeta();
      showStatus(t("keys.publicKeySynced"));
    } catch (e) {
      showStatus(e instanceof Error ? e.message : t("keys.createFailed"), true);
    } finally {
      setBusy(false);
    }
  }

  async function handleUnlock() {
    if (pageState.phase !== "locked") return;
    setBusy(true);
    try {
      const keys = await decryptKeyBlob(pageState.blob, unlockPassphrase);
      await setKeys(keys);
      setUnlockPassphrase("");
      setPageState({ phase: "unlocked", keys });
      const sync = await syncPublicKeysToServer();
      showStatus(sync.ok ? t("keys.publicKeySynced") : t("keys.unlockedSession"));
    } catch (e) {
      const code = e instanceof Error ? e.message : "";
      showStatus(
        code === "WRONG_PASSPHRASE" ? t("keys.wrongPassphrase") : t("keys.unlockFailed"),
        true
      );
    } finally {
      setBusy(false);
    }
  }

  async function verifyCurrentPassphrase(
    passphrase: string,
    keys: UnlockedKeyPairs
  ): Promise<boolean> {
    const data = await fetchMyEncryptedKeyBlob();
    if (!data.encrypted_key_blob) return false;
    try {
      const decrypted = await decryptKeyBlob(data.encrypted_key_blob, passphrase);
      return (
        toBase64(decrypted.x25519.privateKey) === toBase64(keys.x25519.privateKey) &&
        toBase64(decrypted.ed25519.privateKey) === toBase64(keys.ed25519.privateKey)
      );
    } catch {
      return false;
    }
  }

  async function handleChangePassphrase() {
    if (pageState.phase !== "unlocked") return;
    if (!currentChangePassphrase) {
      showStatus(t("keys.enterCurrentPassphrase"), true);
      return;
    }
    const err = validatePassphrase(changePassphraseVal);
    if (err) { showStatus(t(`errors.${err}`, { n: 8 }), true); return; }
    if (changePassphraseVal !== changePhraseConfirm) {
      showStatus(t("keys.newConfirmMismatch"), true);
      return;
    }
    if (changePassphraseVal === currentChangePassphrase) {
      showStatus(t("keys.newMustDiffer"), true);
      return;
    }
    setBusy(true);
    try {
      const currentOk = await verifyCurrentPassphrase(
        currentChangePassphrase,
        pageState.keys
      );
      if (!currentOk) {
        showStatus(t("keys.currentWrong"), true);
        return;
      }
      const blob = await encryptKeyBlob(
        pageState.keys.x25519,
        pageState.keys.ed25519,
        changePassphraseVal
      );
      await uploadToServer(pageState.keys, blob);
      await setKeys(pageState.keys);
      setCurrentChangePassphrase("");
      setChangePassphraseVal("");
      setChangePhraseConfirm("");
      showStatus(t("keys.passphraseChanged"));
    } catch (e) {
      showStatus(e instanceof Error ? e.message : t("keys.changeFailed"), true);
    } finally {
      setBusy(false);
    }
  }

  async function handleSyncToServer() {
    if (pageState.phase !== "unlocked") return;
    setSyncing(true);
    try {
      const externalId = getMyExternalId();
      if (!externalId) throw new Error(t("keys.userIdFailed"));
      const encryptedKeyBlob = await fetchServerEncryptedBlob();
      await storeMyPublicKey({
        externalId,
        publicKeyX25519: toBase64(pageState.keys.x25519.publicKey),
        publicKeyEd25519: toBase64(pageState.keys.ed25519.publicKey),
        ...(encryptedKeyBlob ? { encryptedKeyBlob } : {}),
      });
      showStatus(t("keys.publicKeySynced"));
    } catch {
      showStatus(t("keys.syncFailed"), true);
    } finally {
      setSyncing(false);
    }
  }

  function handleLock() {
    lockKeys();
    showStatus(t("keys.lockedFromMemory"));
    void loadState();
  }

  function handleClear() {
    setDangerStep(null);
    clearAll();
    clearLegacyLocalStorage();
    void loadState();
    showStatus(t("keys.clearedFromSession"));
  }

  // ── Legacy migration ─────────────────────────────────────────────────────────

  async function handleLegacyMigrate() {
    setBusy(true);
    try {
      const keys = await decryptLegacyLocalStorage(legacyPassphrase);
      const blob = await encryptKeyBlob(keys.x25519, keys.ed25519, legacyPassphrase);
      await uploadToServer(keys, blob);
      await setKeys(keys);
      clearLegacyLocalStorage();
      setLegacyPassphrase("");
      setPageState({ phase: "unlocked", keys });
      showStatus(t("keys.publicKeySynced"));
    } catch (e) {
      const code = e instanceof Error ? e.message : "";
      showStatus(
        code === "WRONG_PASSPHRASE" ? t("keys.wrongPassphrase") :
        code === "NO_LEGACY" ? t("keys.noLegacy") :
        t("keys.migrateFailed"),
        true
      );
    } finally {
      setBusy(false);
    }
  }

  // ── Render ───────────────────────────────────────────────────────────────────

  const pageWrap =
    pageState.phase === "unlocked"
      ? "max-w-4xl mx-auto space-y-4"
      : "max-w-md mx-auto space-y-3";

  return (
    <div className={pageWrap}>
      <header>
        <h1 className={`text-lg font-bold ${text.primary} tracking-tight`}>{t("keys.title")}</h1>
      </header>

      {keypairMeta?.expires_at && pageState.phase !== "loading" && pageState.phase !== "no_keys" && (
        <div
          className={`rounded-xl border px-4 py-3 text-sm ${
            keypairMeta.expired
              ? "border-rose-400/40 bg-rose-100/80 text-rose-900 dark:border-rose-500/25 dark:bg-rose-500/8 dark:text-rose-200"
              : keypairMeta.expiring_soon
                ? "border-amber-400/40 bg-amber-100/80 text-amber-900 dark:border-amber-500/25 dark:bg-amber-500/8 dark:text-amber-200"
                : "border-slate-200 bg-slate-50 text-slate-700 dark:border-white/10 dark:bg-white/[0.04] dark:text-white/80"
          }`}
        >
          {keypairMeta.expired ? (
            <p>
              <strong>{t("keys.expired")}</strong>{" "}
              {t("keys.expiredHint", { date: keypairMeta.expires_at.slice(0, 10) })}
            </p>
          ) : keypairMeta.expiring_soon ? (
            <p>
              {t("keys.expiringSoon")}{" "}
              <strong>{t("keys.expiringDays", { days: keypairMeta.days_left ?? 0 })}</strong>{" "}
              {t("keys.expiringOn", { date: keypairMeta.expires_at.slice(0, 10) })}
            </p>
          ) : (
            <p>
              {t("keys.expiresLabel")} <strong>{keypairMeta.expires_at.slice(0, 10)}</strong>
              {keypairMeta.days_left != null &&
                ` ${t("keys.daysLeft", { days: keypairMeta.days_left })}`}
              {keypairMeta.key_version != null &&
                ` · ${t("keys.version", { version: keypairMeta.key_version })}`}
            </p>
          )}
        </div>
      )}

      {/* Loading */}
      {pageState.phase === "loading" && (
        <div className="flex justify-center py-12">
          <div className="w-6 h-6 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
        </div>
      )}

      {/* Public keys on server but encrypted blob was lost (e.g. old pubkey-only sync) */}
      {pageState.phase === "blob_missing" && (
        <div className="space-y-4">
          <div className="rounded-xl border border-rose-400/40 bg-rose-100/80 px-4 py-4 space-y-2 dark:border-rose-500/25 dark:bg-rose-500/8">
            <p className="text-sm font-medium text-rose-900 dark:text-rose-200">
              {t("keys.blobMissingTitle")}
            </p>
            <p className={`text-xs ${text.secondary}`}>
              {t("keys.blobMissingHintExtended")}
            </p>
            <button
              type="button"
              onClick={() => void loadState()}
              className={`text-xs font-medium underline ${text.secondary} hover:no-underline`}
            >
              {t("keys.reloadState")}
            </button>
          </div>
          {pageState.hasLegacy && (
            <div className="rounded-xl border border-amber-400/40 bg-amber-100/80 px-4 py-4 space-y-3 dark:border-amber-500/25 dark:bg-amber-500/8">
              <p className="text-sm font-medium text-amber-900 dark:text-amber-200">{t("keys.legacyTitle")}</p>
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  type="password"
                  value={legacyPassphrase}
                  onChange={(e) => setLegacyPassphrase(e.target.value)}
                  placeholder={t("keys.legacyPassphrase")}
                  autoComplete="current-password"
                  disabled={busy}
                  className={`flex-1 ${inputBase}`}
                />
                <button
                  type="button"
                  onClick={() => void handleLegacyMigrate()}
                  disabled={busy || !legacyPassphrase}
                  className="shrink-0 px-4 py-2 rounded-lg text-sm font-semibold bg-amber-200/80 border border-amber-400/50 text-amber-900 disabled:opacity-40 dark:bg-amber-500/20 dark:border-amber-500/30 dark:text-amber-200"
                >
                  {t("keys.migrate")}
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* No keys */}
      {pageState.phase === "no_keys" && (
        <div className="space-y-4">
          {/* Legacy migration banner */}
          {pageState.hasLegacy && (
            <div className="rounded-xl border border-amber-400/40 bg-amber-100/80 px-4 py-4 space-y-3 dark:border-amber-500/25 dark:bg-amber-500/8">
              <p className="text-sm font-medium text-amber-900 dark:text-amber-200">{t("keys.legacyTitle")}</p>
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  type="password"
                  value={legacyPassphrase}
                  onChange={(e) => setLegacyPassphrase(e.target.value)}
                  placeholder={t("keys.legacyPassphrase")}
                  autoComplete="current-password"
                  disabled={busy}
                  className={`flex-1 ${inputBase}`}
                />
                <button
                  type="button"
                  onClick={() => void handleLegacyMigrate()}
                  disabled={busy || !legacyPassphrase}
                  className="shrink-0 px-4 py-2 rounded-lg text-sm font-semibold bg-amber-200/80 border border-amber-400/50 text-amber-900 disabled:opacity-40 dark:bg-amber-500/20 dark:border-amber-500/30 dark:text-amber-200"
                >
                  {t("keys.migrate")}
                </button>
              </div>
            </div>
          )}

          {/* Generate new keys form */}
          <div className={`${surfaceCard} p-3 space-y-2.5`}>
            {!dangerStep ? (
              <>
                <PassphraseFields
                  compact
                  passphrase={newPassphrase}
                  confirm={confirmPassphrase}
                  onPassphraseChange={setNewPassphrase}
                  onConfirmChange={setConfirmPassphrase}
                  disabled={busy}
                />
                <button
                  type="button"
                  onClick={() => void handleGenerate()}
                  disabled={busy || !newPassphrase}
                  className={`${btnBlockPrimary} disabled:opacity-40`}
                >
                  {t("keys.create")}
                </button>
              </>
            ) : null}
          </div>
        </div>
      )}

      {/* Locked — enter passphrase */}
      {pageState.phase === "locked" && (
        <div className={`${surfaceCard} p-3 space-y-2.5`}>
          <PassphraseFields
            compact
            passphrase={unlockPassphrase}
            confirm=""
            onPassphraseChange={setUnlockPassphrase}
            onConfirmChange={() => {}}
            showConfirm={false}
            passphraseLabel={t("keys.passphrase")}
            disabled={busy}
          />
          <button
            type="button"
            onClick={() => void handleUnlock()}
            disabled={busy || !unlockPassphrase}
            className={`${btnBlockPrimary} disabled:opacity-40`}
          >
            {t("keys.unlock")}
          </button>

          {/* Legacy migration in locked state */}
          {hasLegacyLocalStorageKey() && (
            <button
              type="button"
              onClick={() => clearLegacyLocalStorage()}
              className="text-xs text-amber-700 dark:text-amber-300/80 underline hover:no-underline"
            >
              {t("keys.clearLegacyKey")}
            </button>
          )}
        </div>
      )}

      {/* Unlocked — show keys + management */}
      {pageState.phase === "unlocked" && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_22rem] xl:grid-cols-[minmax(0,1fr)_24rem] lg:items-center">
          <div className="flex flex-col gap-3 min-w-0 lg:justify-center">
            <KeyBlock
              title={t("keys.encryptPublic")}
              accent="indigo"
              value={toBase64(pageState.keys.x25519.publicKey)}
              copied={copied === "x25519"}
              onCopy={() => copyToClipboard(toBase64(pageState.keys.x25519.publicKey), "x25519")}
            />
            <KeyBlock
              title={t("keys.signPublic")}
              accent="violet"
              value={toBase64(pageState.keys.ed25519.publicKey)}
              copied={copied === "ed25519"}
              onCopy={() => copyToClipboard(toBase64(pageState.keys.ed25519.publicKey), "ed25519")}
            />
          </div>

          <div className={`${surfaceCard} p-3 space-y-3 w-full max-w-md mx-auto lg:max-w-none lg:mx-0 lg:sticky lg:top-4`}>
            <div
              className={`flex items-center justify-between gap-2 pb-2 border-b ${header.divider}`}
            >
              <span className={`text-sm font-medium ${text.primary}`}>{t("keys.sessionMgmt")}</span>
              <button
                type="button"
                onClick={() => void handleSyncToServer()}
                disabled={syncing || dangerStep !== null}
                className={`shrink-0 rounded-md px-2.5 py-1 text-xs font-medium ${btn.secondary} disabled:opacity-50`}
              >
                {syncing ? "…" : t("common.sync")}
              </button>
            </div>

            <section className="space-y-2">
              <h3 className={`text-xs font-medium ${text.muted}`}>{t("keys.changePassphrase")}</h3>
              <ChangePassphraseFields
                compact
                current={currentChangePassphrase}
                next={changePassphraseVal}
                confirm={changePhraseConfirm}
                onCurrentChange={setCurrentChangePassphrase}
                onNextChange={setChangePassphraseVal}
                onConfirmChange={setChangePhraseConfirm}
                disabled={busy}
              />
              <button
                type="button"
                onClick={() => void handleChangePassphrase()}
                disabled={
                  busy ||
                  !currentChangePassphrase ||
                  !changePassphraseVal ||
                  !changePhraseConfirm
                }
                className={`w-full ${btn.primary} disabled:opacity-40`}
              >
                {t("keys.update")}
              </button>
            </section>

            <section className={`space-y-2 pt-1 border-t ${header.divider}`}>
              <h3 className={`text-xs font-medium ${text.muted}`}>{t("keys.actions")}</h3>
              <div className="grid grid-cols-3 gap-1.5">
                <button
                  type="button"
                  onClick={() => setDangerStep("replace-keys")}
                  disabled={dangerStep !== null}
                  className={`${btnGridSm} ${btn.secondary} disabled:opacity-40`}
                >
                  {t("keys.newKeypair")}
                </button>
                <button
                  type="button"
                  onClick={handleLock}
                  className={`${btnGridSm} ${btn.secondary}`}
                >
                  {t("keys.lockSession")}
                </button>
                <button
                  type="button"
                  onClick={() => setDangerStep("delete-keys")}
                  disabled={dangerStep !== null}
                  className={`${btnGridSm} ${btn.danger} disabled:opacity-40`}
                >
                  {t("keys.deleteSession")}
                </button>
              </div>
            </section>

            {/* Danger: replace keys */}
            {dangerStep === "replace-keys" && (
              <div className="rounded-lg border border-amber-400/40 bg-amber-100/80 px-3 py-3 space-y-2.5 dark:border-amber-500/25 dark:bg-amber-500/8">
                <p className="text-sm text-amber-900 dark:text-amber-200/95">{t("keys.confirmReplaceShort")}</p>
                <PassphraseFields
                  passphrase={newPassphrase}
                  confirm={confirmPassphrase}
                  onPassphraseChange={setNewPassphrase}
                  onConfirmChange={setConfirmPassphrase}
                  disabled={busy}
                />
                <div className="flex gap-2">
                  <button type="button" onClick={() => setDangerStep(null)} className={`flex-1 ${btnCompactGhost}`}>
                    {t("common.cancel")}
                  </button>
                  <button type="button" onClick={() => void handleGenerate()} className={`flex-1 ${btn.primary}`}>
                    {t("common.confirm")}
                  </button>
                </div>
              </div>
            )}

            {dangerStep === "delete-keys" && (
              <div className="rounded-lg border border-rose-400/40 bg-rose-100/70 px-3 py-3 space-y-2.5 dark:border-rose-500/25 dark:bg-rose-950/30">
                <p className="text-sm text-rose-800 dark:text-rose-200/95">{t("keys.confirmDelete")}</p>
                <div className="flex gap-2">
                  <button type="button" onClick={() => setDangerStep(null)} className={`flex-1 ${btnCompactGhost}`}>
                    {t("common.cancel")}
                  </button>
                  <button type="button" onClick={handleClear} className={`flex-1 ${btnCompactDangerSolid}`}>
                    {t("common.delete")}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Status message */}
      {status && (
        <div role="status"
          className={`rounded-lg border px-3 py-2 text-sm ${
            status.isError
              ? "border-rose-400/40 bg-rose-100/80 text-rose-800 dark:border-rose-500/20 dark:bg-rose-500/8 dark:text-rose-200/95"
              : "border-emerald-400/40 bg-emerald-100/80 text-emerald-800 dark:border-emerald-500/20 dark:bg-emerald-500/8 dark:text-emerald-200/95"
          }`}
        >
          <span>{status.msg}</span>
        </div>
      )}
    </div>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────────

const btnBlockPrimary = `w-full ${btn.primary}`;
/** Nút trong panel hẹp (3 cột) */
const btnGridSm = "w-full min-h-[2rem] !px-2 !py-1.5 !text-xs";
const inputCompact =
  "w-full rounded-md px-2.5 py-1.5 text-sm " +
  "bg-white border border-slate-300 text-slate-900 placeholder:text-slate-400 " +
  "focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 " +
  "disabled:opacity-50 " +
  "dark:bg-[#14161e] dark:border-slate-700 dark:text-slate-100 dark:placeholder:text-slate-500 " +
  "dark:focus:border-indigo-500 dark:focus:ring-indigo-500/25";
const btnCompactGhost =
  `inline-flex items-center justify-center rounded-md px-3 py-1.5 text-sm font-medium ${btnGhost}`;
const btnCompactDangerSolid =
  "w-full min-h-[2rem] rounded-md px-3 py-1.5 text-sm font-semibold bg-rose-600/90 text-white hover:bg-rose-600 disabled:opacity-40";

const fieldLabel = `block mb-1 text-xs font-medium ${text.secondary}`;
const fieldLabelCompact = `block mb-0.5 text-[11px] font-medium ${text.muted}`;

function PasswordInput({
  labelText,
  value,
  onChange,
  disabled,
  autoComplete,
  compact,
}: {
  labelText: string;
  value: string;
  onChange: (v: string) => void;
  disabled?: boolean;
  autoComplete: string;
  compact?: boolean;
}) {
  return (
    <div>
      <label className={compact ? fieldLabelCompact : fieldLabel}>{labelText}</label>
      <input
        type="password"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        autoComplete={autoComplete}
        className={compact ? inputCompact : inputBase}
      />
    </div>
  );
}

function PassphraseFields({
  passphrase,
  confirm,
  onPassphraseChange,
  onConfirmChange,
  disabled,
  showConfirm = true,
  passphraseLabel,
  confirmLabel,
  compact,
}: {
  passphrase: string;
  confirm: string;
  onPassphraseChange: (v: string) => void;
  onConfirmChange: (v: string) => void;
  disabled?: boolean;
  showConfirm?: boolean;
  passphraseLabel?: string;
  confirmLabel?: string;
  compact?: boolean;
}) {
  const t = useT();
  const pLabel = passphraseLabel ?? t("keys.passphrase");
  const cLabel = confirmLabel ?? t("keys.confirmLabel");
  return (
    <div className={compact ? "space-y-1.5" : "space-y-2"}>
      <PasswordInput
        compact={compact}
        labelText={pLabel}
        value={passphrase}
        onChange={onPassphraseChange}
        disabled={disabled}
        autoComplete="new-password"
      />
      {showConfirm && (
        <PasswordInput
          compact={compact}
          labelText={cLabel}
          value={confirm}
          onChange={onConfirmChange}
          disabled={disabled}
          autoComplete="new-password"
        />
      )}
    </div>
  );
}

function ChangePassphraseFields({
  current,
  next,
  confirm,
  onCurrentChange,
  onNextChange,
  onConfirmChange,
  disabled,
  compact,
}: {
  current: string;
  next: string;
  confirm: string;
  onCurrentChange: (v: string) => void;
  onNextChange: (v: string) => void;
  onConfirmChange: (v: string) => void;
  disabled?: boolean;
  compact?: boolean;
}) {
  const t = useT();
  const gap = compact ? "space-y-1.5" : "space-y-2";
  return (
    <div className={gap}>
      <PasswordInput
        compact={compact}
        labelText={t("keys.currentPassphrase")}
        value={current}
        onChange={onCurrentChange}
        disabled={disabled}
        autoComplete="current-password"
      />
      <PasswordInput
        compact={compact}
        labelText={t("keys.newPassphrase")}
        value={next}
        onChange={onNextChange}
        disabled={disabled}
        autoComplete="new-password"
      />
      <PasswordInput
        compact={compact}
        labelText={t("keys.confirmNew")}
        value={confirm}
        onChange={onConfirmChange}
        disabled={disabled}
        autoComplete="new-password"
      />
    </div>
  );
}

function KeyBlock({
  title, accent, value, copied, onCopy,
}: {
  title: string; accent: "indigo" | "violet";
  value: string; copied: boolean; onCopy: () => void;
}) {
  const t = useT();
  const ring = accent === "indigo" ? "ring-indigo-400/20" : "ring-violet-400/20";
  const dot = accent === "indigo" ? "bg-indigo-400" : "bg-violet-400";
  const labelColor =
    accent === "indigo" ? "text-indigo-700 dark:text-indigo-300" : "text-violet-700 dark:text-violet-300";
  return (
    <div className={`${surfaceCard} p-3 ring-1 ${ring} h-full flex flex-col`}>
      <div className="flex items-center justify-between gap-2 mb-2">
        <div className="min-w-0 flex items-center gap-1.5">
          <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dot}`} />
          <span className={`text-xs font-semibold ${labelColor}`}>{title}</span>
        </div>
        <button
          type="button"
          onClick={onCopy}
          className={`shrink-0 text-xs font-medium px-2 py-1 rounded-md border transition ${
            copied
              ? "border-emerald-500/40 text-emerald-700 bg-emerald-100 dark:border-emerald-500/30 dark:text-emerald-400 dark:bg-emerald-500/10"
              : accent === "indigo"
                ? "border-indigo-400/45 text-indigo-700 hover:bg-indigo-100 dark:border-indigo-500/25 dark:text-indigo-400/90 dark:hover:bg-indigo-500/15"
                : "border-violet-400/45 text-violet-700 hover:bg-violet-100 dark:border-violet-500/25 dark:text-violet-400/90 dark:hover:bg-violet-500/15"
          }`}
        >
          {copied ? t("common.copied") : t("common.copy")}
        </button>
      </div>
      <div className={`${keyField} flex-1 min-h-[3.25rem] py-2.5 text-[12px] leading-relaxed`}>
        {value}
      </div>
    </div>
  );
}
