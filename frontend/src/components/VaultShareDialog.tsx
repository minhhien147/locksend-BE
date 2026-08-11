import { useState, useEffect, useRef } from "react";
import { useDraftState } from "../hooks/useDraftState";
import { clearPageDraft } from "../utils/pageDraft";
import {
  searchUsers,
  getUserPublicKey,
  shareVaultFile,
  getMyFiles,
  revokeRecipient,
  type VaultFile,
  type RecipientPayload,
  type RecipientInfo,
} from "../utils/api";
import {
  fromBase64,
  unwrapEnvelopeContentKey,
  wrapEnvelopeForRecipient,
  type EncryptionMetadata,
} from "../utils/crypto";
import { getKeys } from "../utils/keyVault";
import Button from "./ui/Button";
import Alert from "./ui/Alert";
import { useT } from "../i18n/context";
import { inputBase, label, text } from "../styles/theme";

const VAULT_SHARE_KEY = "vault-share";

interface Props {
  file: VaultFile;
  onClose: () => void;
  onShared: () => void;
}

type ShareRecipient = {
  userId: string;
  label: string;
  publicKeyX25519: string;
  keyVersion: number;
};

export default function VaultShareDialog({ file, onClose, onShared }: Props) {
  const t = useT();
  const draftScope = `${VAULT_SHARE_KEY}:${file.file_id}`;
  const [query, setQuery] = useDraftState(draftScope, "query", "");
  const [results, setResults] = useState<
    { id: string; email: string | null; display_name: string | null }[]
  >([]);
  const [selected, setSelected] = useDraftState<ShareRecipient[]>(
    draftScope,
    "selected",
    []
  );
  const [existing, setExisting] = useState<RecipientInfo[]>([]);
  const [loadingExisting, setLoadingExisting] = useState(true);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<number | null>(null);

  async function loadExistingRecipients() {
    setLoadingExisting(true);
    try {
      const files = await getMyFiles();
      const row = files.find((f) => f.file_id === file.file_id);
      setExisting(row?.recipients ?? []);
    } catch {
      setExisting([]);
    } finally {
      setLoadingExisting(false);
    }
  }

  useEffect(() => {
    void loadExistingRecipients();
  }, [file.file_id]);

  useEffect(() => {
    if (timerRef.current) window.clearTimeout(timerRef.current);
    if (query.trim().length < 3) {
      setResults([]);
      return;
    }
    timerRef.current = window.setTimeout(async () => {
      try {
        const activeIds = new Set(
          existing.filter((r) => r.status === "active").map((r) => r.recipient_id)
        );
        const rows = await searchUsers(query);
        setResults(
          rows
            .filter((r) => r.has_public_key && !activeIds.has(r.id))
            .map((r) => ({
              id: r.id,
              email: r.email,
              display_name: r.display_name,
            }))
        );
      } catch {
        setResults([]);
      }
    }, 300);
  }, [query, existing]);

  async function addRecipient(userId: string) {
    if (selected.some((s) => s.userId === userId)) return;
    if (existing.some((r) => r.recipient_id === userId && r.status === "active")) return;
    setError(null);
    try {
      const pk = await getUserPublicKey(userId);
      const label =
        results.find((r) => r.id === userId)?.display_name ||
        results.find((r) => r.id === userId)?.email ||
        userId;
      setSelected((prev) => [
        ...prev,
        {
          userId,
          label,
          publicKeyX25519: pk.public_key_x25519,
          keyVersion: pk.key_version ?? 1,
        },
      ]);
      setQuery("");
      setResults([]);
    } catch {
      setError(t("vault.fetchKeyFailed"));
    }
  }

  async function handleRevoke(recipientId: string) {
    if (!confirm(t("history.revokeConfirm"))) return;
    setRevoking(recipientId);
    setError(null);
    try {
      await revokeRecipient(file.file_id, recipientId);
      setExisting((prev) =>
        prev.map((r) =>
          r.recipient_id === recipientId ? { ...r, status: "revoked" } : r
        )
      );
      onShared();
    } catch {
      setError(t("history.revokeFailed"));
    } finally {
      setRevoking(null);
    }
  }

  async function handleShare() {
    const keys = getKeys();
    if (!keys) {
      setError(t("vault.unlockBeforeShare"));
      return;
    }
    if (selected.length === 0) {
      setError(t("vault.needRecipient"));
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const baseMeta = file.encryption_metadata as unknown as EncryptionMetadata;
      const { contentSecret, contentNonce } = await unwrapEnvelopeContentKey(
        baseMeta,
        keys.x25519.privateKey
      );
      const payloads: RecipientPayload[] = [];
      for (const r of selected) {
        const wrapped = await wrapEnvelopeForRecipient(
          baseMeta,
          contentSecret,
          contentNonce,
          fromBase64(r.publicKeyX25519)
        );
        payloads.push({
          recipient_id: r.userId,
          wrapped_file_key: JSON.stringify(wrapped),
          wrapped_key_alg: "X25519-HKDF",
          key_id: String(r.keyVersion),
          wrapped_key_version: r.keyVersion,
        });
      }
      await shareVaultFile(file.file_id, payloads);
      clearPageDraft(draftScope);
      onShared();
      onClose();
    } catch (e) {
      setError((e as Error).message ?? t("vault.shareFailed"));
    } finally {
      setLoading(false);
    }
  }

  const activeExisting = existing.filter((r) => r.status === "active");
  const revokedExisting = existing.filter((r) => r.status === "revoked");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60">
      <div className="w-full max-w-md rounded-2xl border border-white/10 bg-[#12141c] p-5 space-y-4 shadow-xl max-h-[90vh] overflow-y-auto">
        <h3 className={`text-lg font-semibold ${text.primary}`}>
          {t("vault.shareFromVault")}
        </h3>
        <p className={`text-sm ${text.muted} truncate`}>{file.original_filename}</p>
        {!file.can_share && (
          <Alert tone="warning">{t("vault.chunkedNoShare")}</Alert>
        )}

        <div>
          <p className={label}>{t("vault.currentRecipients")}</p>
          {loadingExisting ? (
            <p className={`mt-1 text-xs ${text.muted}`}>{t("common.loading")}</p>
          ) : existing.length === 0 ? (
            <p className={`mt-1 text-xs ${text.muted}`}>{t("vault.noRecipientsYet")}</p>
          ) : (
            <ul className="mt-2 space-y-1.5">
              {existing.map((r) => (
                <li
                  key={r.recipient_id}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg border border-white/10 ${
                    r.status === "revoked" ? "opacity-50" : "bg-white/[0.03]"
                  }`}
                >
                  <div className="flex-1 min-w-0">
                    <p className={`text-xs truncate ${text.secondary}`}>
                      {r.display_name || r.email || r.recipient_id}
                    </p>
                    {r.display_name && r.email && (
                      <p className="text-[10px] text-white/40 truncate">{r.email}</p>
                    )}
                  </div>
                  {r.status === "revoked" ? (
                    <span className="shrink-0 text-[10px] px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400/70 border border-rose-500/15">
                      {t("vault.revoked")}
                    </span>
                  ) : (
                    <button
                      type="button"
                      disabled={revoking === r.recipient_id || loading}
                      onClick={() => void handleRevoke(r.recipient_id)}
                      className="shrink-0 text-[10px] px-2 py-0.5 rounded-lg border border-rose-500/20 text-rose-400/80 hover:bg-rose-500/10 transition disabled:opacity-40"
                    >
                      {revoking === r.recipient_id ? "…" : t("vault.revoke")}
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
          {!loadingExisting && existing.length > 0 && (
            <p className={`mt-1.5 text-[10px] ${text.muted}`}>
              {t("history.recipientCount", { count: activeExisting.length })}
              {revokedExisting.length > 0
                ? ` ${t("history.recipientRevoked", { count: revokedExisting.length })}`
                : ""}
            </p>
          )}
        </div>

        <div>
          <label className={label}>{t("vault.findRecipient")}</label>
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className={`w-full mt-1 ${inputBase}`}
            placeholder={t("vault.searchRecipientPlaceholder")}
            disabled={loading || !file.can_share}
          />
          {results.length > 0 && (
            <ul className="mt-1 max-h-32 overflow-y-auto rounded-xl border border-white/10 divide-y divide-white/5">
              {results.map((r) => (
                <li key={r.id}>
                  <button
                    type="button"
                    className="w-full text-left px-3 py-2 text-sm hover:bg-white/5"
                    onClick={() => void addRecipient(r.id)}
                  >
                    {r.display_name || r.email}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        {selected.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {selected.map((s) => (
              <span
                key={s.userId}
                className="text-xs px-2 py-1 rounded-lg bg-indigo-500/15 text-indigo-300 border border-indigo-500/25"
              >
                {s.label}
                <button
                  type="button"
                  className="ml-1 text-white/40 hover:text-white"
                  onClick={() =>
                    setSelected((prev) => prev.filter((x) => x.userId !== s.userId))
                  }
                >
                  ×
                </button>
              </span>
            ))}
          </div>
        )}

        {error && <Alert tone="error">{error}</Alert>}

        <div className="flex gap-2 pt-1">
          <Button variant="secondary" fullWidth onClick={onClose} disabled={loading}>
            {t("common.cancel")}
          </Button>
          <Button
            fullWidth
            loading={loading}
            disabled={!file.can_share || selected.length === 0}
            onClick={() => void handleShare()}
          >
            {t("vault.share")}
          </Button>
        </div>
      </div>
    </div>
  );
}
