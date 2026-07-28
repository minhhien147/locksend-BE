import { useState, useRef, useCallback, useEffect } from "react";
import {
  CHUNKED_THRESHOLD,
  DEFAULT_CHUNK_SIZE,
  fromBase64,
} from "../utils/crypto";
import { isUnlocked } from "../utils/keyVault";
import {
  useUpload,
  type ChunkProgress,
  type RecipientUser,
  type UploadPurpose,
} from "../hooks/useUpload";
import { useClearPageDraft, useDraftState } from "../hooks/useDraftState";
import { migrateLegacyStorage } from "../utils/pageDraft";
import { getVaultFolders, type VaultFolder } from "../utils/api";
import { Link } from "react-router-dom";
import { LoadingSpinner } from "../components/LoadingSpinner";
import KeyUnlockBanner from "../components/KeyUnlockBanner";
import { searchUsers, getUserPublicKey, type UserSearchResult } from "../utils/api";
import { syncPublicKeysToServer } from "../utils/keySync";
import PageHeader from "../components/ui/PageHeader";
import Card from "../components/ui/Card";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import Badge from "../components/ui/Badge";
import SegmentedControl from "../components/ui/SegmentedControl";
import {
  dropzone,
  inputBase,
  text,
  label,
  sectionTitle,
  surfaceInset,
  panel,
} from "../styles/theme";
import { useT } from "../i18n/context";
import TransferProgressPanel from "../components/TransferProgressPanel";

const formatFileSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
};

const CHUNK_MB = DEFAULT_CHUNK_SIZE / (1024 * 1024);
const PAGE_KEY = "upload";
type RecipientMode = "search" | "manual";

export default function UploadPage() {
  const t = useT();
  const clearUploadDraft = useClearPageDraft(PAGE_KEY);
  const [keysReady, setKeysReady] = useState(() => isUnlocked());
  const canUseKeys = keysReady;
  const [file, setFile] = useDraftState<File | null>(PAGE_KEY, "file", null, "memory");
  const [fileHint, setFileHint] = useDraftState<{ name: string; size: number } | null>(
    PAGE_KEY,
    "fileHint",
    null,
    "persist"
  );
  const fileNeedsReselect = !file && !!fileHint;
  const [recipientPublicKey, setRecipientPublicKey] = useDraftState(
    PAGE_KEY,
    "recipientPublicKey",
    ""
  );
  const [uploadPurpose, setUploadPurpose] = useDraftState<UploadPurpose>(
    PAGE_KEY,
    "uploadPurpose",
    "share"
  );
  const [vaultFolderId, setVaultFolderId] = useDraftState<string | null>(
    PAGE_KEY,
    "vaultFolderId",
    null
  );
  const [recipientMode, setRecipientMode] = useDraftState<RecipientMode>(
    PAGE_KEY,
    "recipientMode",
    "search"
  );
  const [searchQuery, setSearchQuery] = useDraftState(PAGE_KEY, "searchQuery", "");
  const [selectedRecipients, setSelectedRecipients] = useDraftState<RecipientUser[]>(
    PAGE_KEY,
    "selectedRecipients",
    []
  );
  const [vaultFolders, setVaultFolders] = useState<VaultFolder[]>([]);
  const [searchResults, setSearchResults] = useState<UserSearchResult[]>([]);
  const [searchLoading, setSearchLoading] = useState(false);
  const [keyLoading, setKeyLoading] = useState(false);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const searchTimerRef = useRef<number | null>(null);

  const {
    stage,
    sasUrl,
    error,
    chunkProgress,
    isChunkedMode,
    transferStats,
    encryptAndUpload,
    cancel,
    reset,
  } = useUpload();

  const onKeysUnlocked = () => {
    setKeysReady(isUnlocked());
    void syncPublicKeysToServer();
  };

  useEffect(() => {
    migrateLegacyStorage("sfs_upload_draft_v1", PAGE_KEY);
  }, []);

  useEffect(() => {
    setFileHint(file ? { name: file.name, size: file.size } : null);
  }, [file, setFileHint]);

  useEffect(() => {
    if (uploadPurpose === "vault") {
      void getVaultFolders().then(setVaultFolders).catch(() => setVaultFolders([]));
    }
  }, [uploadPurpose]);

  useEffect(() => {
    if (searchTimerRef.current !== null) window.clearTimeout(searchTimerRef.current);
    if (!searchQuery.trim() || searchQuery.trim().length < 2) {
      setSearchResults([]);
      return;
    }
    searchTimerRef.current = window.setTimeout(async () => {
      setSearchLoading(true);
      try {
        const results = await searchUsers(searchQuery.trim());
        setSearchResults(results);
      } catch {
        setSearchResults([]);
      } finally {
        setSearchLoading(false);
      }
    }, 350);
    return () => { if (searchTimerRef.current !== null) window.clearTimeout(searchTimerRef.current); };
  }, [searchQuery]);

  async function handleAddRecipient(user: UserSearchResult) {
    if (selectedRecipients.some((r) => r.userId === user.id)) {
      setKeyError(t("upload.recipientExists"));
      return;
    }
    if (!user.has_public_key) {
      setKeyError(t("upload.noPublicKeyRegistered"));
      return;
    }
    setKeyError(null);
    setKeyLoading(true);
    try {
      const pk = await getUserPublicKey(user.id);
      fromBase64(pk.public_key_x25519);
      setSelectedRecipients((prev) => [
        ...prev,
        {
          userId: user.id,
          email: user.email,
          displayName: user.display_name,
          publicKeyX25519: pk.public_key_x25519,
          keyVersion: pk.key_version,
        },
      ]);
      setSearchQuery("");
      setSearchResults([]);
    } catch {
      setKeyError(t("upload.fetchFailedRetry"));
    } finally {
      setKeyLoading(false);
    }
  }

  function handleRemoveRecipient(userId: string) {
    setSelectedRecipients((prev) => prev.filter((r) => r.userId !== userId));
    setKeyError(null);
  }

  function handleClearRecipients() {
    setSelectedRecipients([]);
    setSearchQuery("");
    setSearchResults([]);
    setKeyError(null);
  }

  function handleCopySasUrl() {
    navigator.clipboard.writeText(sasUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function handleReset() {
    clearUploadDraft();
    setCopied(false);
    reset();
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped) setFile(dropped);
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(true);
  }, []);

  const handleDragLeave = useCallback(() => setDragging(false), []);

  const isBusy = stage === "encrypting" || stage === "uploading";
  const isLargeFile = file ? file.size >= CHUNKED_THRESHOLD : false;

  if (stage === "done") {
    return (
      <div className="max-w-2xl mx-auto">
        <DoneCard
          sasUrl={sasUrl}
          copied={copied}
          onCopy={handleCopySasUrl}
          onReset={handleReset}
          purpose={uploadPurpose}
          t={t}
        />
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto space-y-5">
      <PageHeader title={t("upload.title")} />

      <KeyUnlockBanner onUnlocked={onKeysUnlocked} />

      {fileNeedsReselect && !file && (
        <Alert tone="warning">{t("upload.draftNoticeFull")}</Alert>
      )}

      <Card className="space-y-3">
        <h2 className={sectionTitle}>{t("upload.mode")}</h2>
        <SegmentedControl
          value={uploadPurpose}
          onChange={(v) => setUploadPurpose(v as UploadPurpose)}
          disabled={isBusy}
          options={[
            { value: "share", label: t("upload.modeShare") },
            { value: "vault", label: t("upload.modeVault") },
          ]}
        />
        {uploadPurpose === "vault" && (
          <div>
            <label className={label}>{t("upload.folderOptional")}</label>
            <select
              value={vaultFolderId ?? ""}
              onChange={(e) => setVaultFolderId(e.target.value || null)}
              disabled={isBusy}
              className={`w-full mt-1 text-sm ${inputBase}`}
            >
              <option value="">{t("upload.folderRoot")}</option>
              {vaultFolders.map((fo) => (
                <option key={fo.id} value={fo.id}>
                  {fo.name}
                </option>
              ))}
            </select>
            <p className={`text-xs mt-1.5 ${text.faint}`}>
              {t("upload.vaultManageAt")}{" "}
              <Link to="/profile" className="text-indigo-400 hover:underline">
                {t("upload.openVault")}
              </Link>
            </p>
          </div>
        )}
      </Card>

      <div
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => !isBusy && fileInputRef.current?.click()}
        className={`relative p-10 text-center transition-colors ${isBusy ? "cursor-not-allowed opacity-70" : "cursor-pointer"} ${
          dragging ? dropzone.active : file ? dropzone.filled : dropzone.base
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          disabled={isBusy}
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />

        {file ? (
          <div className="space-y-2">
            <p className={`font-medium text-sm truncate max-w-xs mx-auto ${text.primary}`}>{file.name}</p>
            <div className="flex items-center justify-center gap-2">
              <span className={`text-xs ${text.muted}`}>{formatFileSize(file.size)}</span>
              {isLargeFile && (
                <Badge tone="warning">{t("upload.chunkedBadge", { mb: CHUNK_MB })}</Badge>
              )}
            </div>
            {!isBusy && <p className={`text-xs ${text.faint}`}>{t("upload.changeFile")}</p>}
          </div>
        ) : (
          <p className={`text-sm font-medium ${text.secondary}`}>{t("upload.dropzone")}</p>
        )}
      </div>

      {uploadPurpose === "share" && (
      <Card className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <h2 className={sectionTitle}>{t("upload.recipients")}</h2>
          <SegmentedControl
            value={recipientMode}
            onChange={setRecipientMode}
            disabled={isBusy}
            options={[
              { value: "search", label: t("upload.searchUser") },
              { value: "manual", label: t("upload.pasteKey") },
            ]}
          />
        </div>

        {recipientMode === "search" ? (
          <div className="space-y-3">
            {selectedRecipients.length > 0 && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <p className={`text-xs ${text.muted}`}>
                    {t("upload.recipientCount", { count: selectedRecipients.length })}
                  </p>
                  <button
                    type="button"
                    onClick={handleClearRecipients}
                    disabled={isBusy}
                    className={`text-xs ${text.muted} hover:text-rose-600 dark:hover:text-rose-400`}
                  >
                    {t("upload.clearAll")}
                  </button>
                </div>
                <ul className="flex flex-wrap gap-2">
                  {selectedRecipients.map((r) => (
                    <li
                      key={r.userId}
                      className={`flex items-center gap-2 pl-3 pr-1 py-1.5 rounded-md text-sm ${surfaceInset}`}
                    >
                      <span className={`truncate max-w-[180px] ${text.primary}`}>
                        {r.displayName || r.email || r.userId.slice(0, 8)}
                      </span>
                      <Badge tone="neutral">v{r.keyVersion}</Badge>
                      <button
                        type="button"
                        onClick={() => handleRemoveRecipient(r.userId)}
                        disabled={isBusy}
                        className={`p-1 rounded ${text.faint} hover:text-slate-700 dark:hover:text-slate-200`}
                        aria-label={t("upload.removeRecipient")}
                      >
                        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <div className="relative">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={t("upload.searchPlaceholderMulti")}
                disabled={isBusy}
                className={`w-full pr-10 ${inputBase}`}
              />
              <div className="absolute right-3 top-1/2 -translate-y-1/2">
                {searchLoading || keyLoading ? (
                  <LoadingSpinner size="sm" />
                ) : (
                  <svg className={`w-4 h-4 ${text.faint}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                )}
              </div>
              {searchResults.length > 0 && (
                <div className={`absolute top-full mt-1 left-0 right-0 z-20 overflow-hidden ${panel.dropdown}`}>
                  {searchResults.map((u) => (
                    <button
                      key={u.id}
                      type="button"
                      onClick={() => void handleAddRecipient(u)}
                      disabled={selectedRecipients.some((r) => r.userId === u.id) || !u.has_public_key}
                      className="w-full flex items-center gap-3 px-4 py-2.5 hover:bg-slate-50 dark:hover:bg-slate-800/60 transition text-left disabled:opacity-40"
                    >
                      <div className="flex-1 min-w-0">
                        <p className={`text-sm truncate ${text.primary}`}>{u.email}</p>
                        {u.display_name && (
                          <p className={`text-xs ${text.muted}`}>{u.display_name}</p>
                        )}
                      </div>
                      {u.has_public_key ? (
                        <Badge tone="success">{t("upload.badgeAdd")}</Badge>
                      ) : (
                        <Badge tone="warning">{t("upload.badgeNoKey")}</Badge>
                      )}
                    </button>
                  ))}
                </div>
              )}
            </div>
            {keyError && <p className="text-xs text-rose-600 dark:text-rose-400">{keyError}</p>}
          </div>
        ) : (
          <div className="space-y-3">
            <div>
              <label className={label}>{t("upload.publicKeyLabel")}</label>
              <textarea
                value={recipientPublicKey}
                onChange={(e) => setRecipientPublicKey(e.target.value)}
                placeholder={t("upload.keyPlaceholderRecipient")}
                rows={3}
                disabled={isBusy}
                className={`w-full mt-1.5 font-mono text-sm resize-none ${inputBase}`}
              />
            </div>
          </div>
        )}
      </Card>
      )}

      {error && <Alert tone="error">{error}</Alert>}

      {isBusy && transferStats && (
        <TransferProgressPanel
          stats={transferStats}
          label={
            stage === "encrypting"
              ? isChunkedMode
                ? t("upload.encryptingChunk", { mb: CHUNK_MB })
                : t("upload.encrypting")
              : isChunkedMode
                ? t("upload.multipartUpload")
                : t("upload.uploadCiphertext")
          }
          showSpeed={stage === "uploading"}
          showBar={stage === "uploading" && !chunkProgress}
          barClassName="bg-blue-700 dark:bg-blue-600"
        />
      )}

      {isBusy && chunkProgress && <ChunkProgressBar progress={chunkProgress} t={t} />}

      <div className="flex gap-3">
        <Button
          fullWidth
          loading={isBusy}
          disabled={
            isBusy ||
            !canUseKeys ||
            !file ||
            (uploadPurpose === "share" &&
              recipientMode === "search" &&
              (selectedRecipients.length === 0 || keyLoading)) ||
            (uploadPurpose === "share" &&
              recipientMode === "manual" &&
              !recipientPublicKey.trim())
          }
          onClick={() =>
            void encryptAndUpload(
              file,
              recipientMode === "search" ? selectedRecipients : [],
              recipientMode === "manual" ? recipientPublicKey : undefined,
              { purpose: uploadPurpose, folderId: vaultFolderId }
            ).catch(() => {})
          }
        >
          {stage === "encrypting"
            ? isChunkedMode
              ? t("upload.encryptingChunk", { mb: CHUNK_MB })
              : t("upload.encrypting")
            : stage === "uploading"
              ? isChunkedMode
                ? t("upload.multipartUpload")
                : t("upload.uploading")
              : uploadPurpose === "vault"
                ? t("upload.saveVault")
                : t("upload.encryptUpload")}
        </Button>
        {isBusy && (
          <Button variant="secondary" onClick={cancel}>
            {t("common.cancel")}
          </Button>
        )}
      </div>

    </div>
  );
}

function ChunkProgressBar({
  progress,
  t,
}: {
  progress: ChunkProgress;
  t: ReturnType<typeof useT>;
}) {
  const { phase, done, total, currentMB } = progress;
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  const isEncrypt = phase === "encrypt";

  return (
    <Card padding="sm" className="space-y-2">
      <div className={`flex items-center justify-between text-xs ${text.muted}`}>
        <span>
          {isEncrypt ? t("upload.encryptChunk") : t("upload.uploadChunk")}{" "}
          {t("upload.chunkProgress", {
            current: done + (isEncrypt ? 1 : 0),
            total,
          })}
          {currentMB > 0 && ` · ${currentMB}MB`}
        </span>
        <span className="font-medium text-indigo-600 dark:text-indigo-400">{pct}%</span>
      </div>
      <div className="w-full bg-slate-200 dark:bg-slate-800 rounded-full h-1.5 overflow-hidden">
        <div
          className={`h-1.5 rounded-full transition-all duration-300 ${isEncrypt ? "bg-amber-500" : "bg-blue-700 dark:bg-blue-600"}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </Card>
  );
}

function DoneCard({
  sasUrl,
  copied,
  onCopy,
  onReset,
  purpose,
  t,
}: {
  sasUrl: string;
  copied: boolean;
  onCopy: () => void;
  onReset: () => void;
  purpose: UploadPurpose;
  t: ReturnType<typeof useT>;
}) {
  return (
    <div className="space-y-5">
      <PageHeader title={t("upload.title")} />

      <Alert tone="success">
        {purpose === "vault" ? t("upload.savedVault") : t("upload.success")}
      </Alert>

      {purpose === "share" && (
        <Card className="space-y-3">
          <label className={label}>{t("upload.sasLink")}</label>
          <div className="flex gap-2">
            <input readOnly value={sasUrl} className={`flex-1 text-xs font-mono ${inputBase}`} />
            <Button variant="secondary" onClick={onCopy}>
              {copied ? t("common.copied") : t("common.copy")}
            </Button>
          </div>
        </Card>
      )}

      {purpose === "vault" && (
        <Link to="/profile">
          <Button fullWidth>{t("upload.openVaultBtn")}</Button>
        </Link>
      )}

      <Button variant="secondary" fullWidth onClick={onReset}>
        {purpose === "vault" ? t("upload.saveAnother") : t("upload.uploadAnotherShort")}
      </Button>
    </div>
  );
}

