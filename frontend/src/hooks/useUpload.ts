import { useRef, useState } from "react";
import {
  encryptFile,
  encryptFileForRecipients,
  fromBase64,
  toBase64,
  type EncryptionMetadata,
  prepareChunkedEncryption,
  encryptChunk,
  buildChunkedManifest,
  signManifest,
  computeSHA256Hex,
  CHUNKED_THRESHOLD,
  DEFAULT_CHUNK_SIZE,
  type ChunkedEncryptionMetadata,
} from "../utils/crypto";
import { getKeys, resetLockTimer } from "../utils/keyVault";
import {
  uploadEncryptedFile,
  initMultipartUpload,
  uploadChunk,
  finalizeMultipartUpload,
  type RecipientPayload,
} from "../utils/api";
import { apiErrorDetail } from "../utils/api/client";
import { useT } from "../i18n/context";
import { useTransferTimer } from "./useTransferTimer";
import { computeTransferStats, type TransferStats } from "../utils/transferStats";

export type UploadStage = "idle" | "encrypting" | "uploading" | "done" | "error";

export interface ChunkProgress {
  phase: "encrypt" | "upload";
  done: number;
  total: number;
  currentMB: number;
}

export interface UseUploadState {
  stage: UploadStage;
  sasUrl: string;
  error: string;
  chunkProgress: ChunkProgress | null;
  uploadPercent: number;
  plaintextChecksum: string;
  recipientCount: number;
  bytesTransferred: number;
  bytesTotal: number;
}

/** Người nhận đã chọn (tìm user — có userId cho Hộp nhận) */
export interface RecipientUser {
  userId: string;
  email?: string | null;
  displayName?: string | null;
  publicKeyX25519: string;
  keyVersion: number;
}

export type UploadPurpose = "share" | "vault";

export interface UploadOptions {
  purpose?: UploadPurpose;
  folderId?: string | null;
}

export interface UseUploadReturn extends UseUploadState {
  isChunkedMode: boolean;
  chunkCount: number;
  transferStats: TransferStats | null;
  encryptAndUpload: (
    file: File | null,
    recipients: RecipientUser[],
    manualPublicKey?: string,
    options?: UploadOptions
  ) => Promise<void>;
  cancel: () => void;
  reset: () => void;
}

const initialState: UseUploadState = {
  stage: "idle",
  sasUrl: "",
  error: "",
  chunkProgress: null,
  uploadPercent: 0,
  plaintextChecksum: "",
  recipientCount: 0,
  bytesTransferred: 0,
  bytesTotal: 0,
};

function buildRecipientPayloads(
  users: RecipientUser[],
  metadataPerRecipient: object[]
): RecipientPayload[] {
  return users.map((u, i) => ({
    recipient_id: u.userId,
    wrapped_file_key: JSON.stringify(metadataPerRecipient[i]),
    wrapped_key_alg: "X25519-HKDF",
    key_id: String(u.keyVersion),
    wrapped_key_version: u.keyVersion,
  }));
}

export function useUpload(): UseUploadReturn {
  const t = useT();
  const [state, setState] = useState<UseUploadState>(initialState);
  const [currentFile, setCurrentFile] = useState<File | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const transferActive = state.stage === "encrypting" || state.stage === "uploading";
  const { startedAt, tick } = useTransferTimer(transferActive);
  const transferStats = computeTransferStats(
    state.bytesTransferred,
    state.bytesTotal,
    startedAt,
    tick
  );

  const isChunkedMode =
    currentFile !== null && currentFile.size >= CHUNKED_THRESHOLD;
  const chunkCount = currentFile
    ? Math.ceil(currentFile.size / DEFAULT_CHUNK_SIZE)
    : 0;

  function isAbortError(err: unknown): boolean {
    const anyErr = err as { name?: string; code?: string; message?: string };
    if (abortRef.current?.signal.aborted) return true;
    if (anyErr?.code === "ERR_CANCELED") return true;
    if (anyErr?.name === "CanceledError") return true;
    if (typeof anyErr?.message === "string" && anyErr.message.toLowerCase().includes("canceled")) {
      return true;
    }
    return false;
  }

  function cancel() {
    abortRef.current?.abort();
    abortRef.current = null;
    setState((prev) => ({
      ...prev,
      stage: "idle",
      sasUrl: "",
      error: "",
      chunkProgress: null,
      uploadPercent: 0,
      bytesTransferred: 0,
      bytesTotal: currentFile?.size ?? 0,
    }));
  }

  async function encryptAndUpload(
    file: File | null,
    recipients: RecipientUser[],
    manualPublicKey?: string,
    options?: UploadOptions
  ): Promise<void> {
    if (!file) {
      setState((prev) => ({ ...prev, error: t("upload.pickFile") }));
      return;
    }

    const purpose = options?.purpose ?? "share";
    const vaultFolderId = options?.folderId ?? null;
    const useManual = manualPublicKey?.trim();
    const activeRecipients = useManual ? [] : recipients;

    if (purpose === "share" && !useManual && activeRecipients.length === 0) {
      setState((prev) => ({
        ...prev,
        error: t("upload.needRecipient"),
      }));
      return;
    }
    const myKeys = getKeys();
    if (!myKeys) {
      setState((prev) => ({
        ...prev,
        error: t("download.keysLocked"),
      }));
      return;
    }

    const storageOpts = {
      storageMode: purpose,
      folderId: vaultFolderId,
    } as const;

    const multiCount =
      purpose === "vault" ? 1 : useManual ? 1 : activeRecipients.length;
    if (purpose === "share" && multiCount > 1 && file.size >= CHUNKED_THRESHOLD) {
      setState((prev) => ({
        ...prev,
        error: t("upload.multiRecipientChunkLimit", {
          count: multiCount,
          mb: DEFAULT_CHUNK_SIZE / (1024 * 1024),
        }),
      }));
      return;
    }

    setCurrentFile(file);
    abortRef.current?.abort();
    abortRef.current = new AbortController();
    const signal = abortRef.current.signal;
    setState({
      stage: "encrypting",
      sasUrl: "",
      error: "",
      chunkProgress: null,
      uploadPercent: 0,
      plaintextChecksum: "",
      recipientCount: multiCount,
      bytesTransferred: 0,
      bytesTotal: file.size,
    });

    try {
      if (signal.aborted) throw new Error("CANCELLED");
      if (file.size < CHUNKED_THRESHOLD) {
        let ciphertext: Uint8Array;
        let checksum: string;
        let uploadMetadata: EncryptionMetadata;
        let recipientPayloads: RecipientPayload[] = [];

        if (purpose === "vault") {
          const myPub = myKeys.x25519.publicKey;
          const { ciphertext: ct, plaintextChecksum, perRecipientMetadata } =
            await encryptFileForRecipients(
              file,
              [myPub],
              myKeys.ed25519.privateKey,
              myKeys.ed25519.publicKey
            );
          ciphertext = ct;
          checksum = plaintextChecksum;
          uploadMetadata = {
            ...perRecipientMetadata[0],
            storage_mode: "vault" as const,
          };
        } else if (useManual) {
          const pub = fromBase64(useManual.trim());
          const { ciphertext: ct, metadata } = await encryptFile(
            file,
            pub,
            myKeys.ed25519.privateKey,
            myKeys.ed25519.publicKey
          );
          ciphertext = ct;
          checksum = metadata.plaintextChecksum ?? "";
          uploadMetadata = metadata;
        } else if (activeRecipients.length === 1) {
          const r = activeRecipients[0];
          const pub = fromBase64(r.publicKeyX25519);
          const { ciphertext: ct, metadata } = await encryptFile(
            file,
            pub,
            myKeys.ed25519.privateKey,
            myKeys.ed25519.publicKey
          );
          ciphertext = ct;
          checksum = metadata.plaintextChecksum ?? "";
          uploadMetadata = metadata;
          recipientPayloads = buildRecipientPayloads(activeRecipients, [metadata as object]);
        } else {
          const pubs = activeRecipients.map((r) =>
            fromBase64(r.publicKeyX25519)
          );
          const { ciphertext: ct, plaintextChecksum, perRecipientMetadata } =
            await encryptFileForRecipients(
              file,
              pubs,
              myKeys.ed25519.privateKey,
              myKeys.ed25519.publicKey
            );
          ciphertext = ct;
          checksum = plaintextChecksum;
          uploadMetadata = perRecipientMetadata[0];
          recipientPayloads = buildRecipientPayloads(
            activeRecipients,
            perRecipientMetadata as object[]
          );
        }

        setState((prev) => ({
          ...prev,
          stage: "uploading",
          plaintextChecksum: checksum,
          bytesTotal: ciphertext.byteLength,
          bytesTransferred: 0,
        }));

        const result = await uploadEncryptedFile(
          ciphertext,
          uploadMetadata,
          file.name,
          (loaded, total) =>
            setState((prev) => ({
              ...prev,
              uploadPercent: total ? Math.round((loaded / total) * 100) : 0,
              bytesTransferred: loaded,
              bytesTotal: total,
            })),
          recipientPayloads,
          storageOpts,
          signal
        );

        setState((prev) => ({
          ...prev,
          sasUrl: result.sas_url,
          stage: "done",
        }));
      } else {
        const recipientX25519PubKey =
          purpose === "vault"
            ? myKeys.x25519.publicKey
            : fromBase64(
                (useManual ? useManual : activeRecipients[0].publicKeyX25519).trim()
              );
        const r =
          purpose === "vault"
            ? null
            : useManual
              ? null
              : activeRecipients[0];

        const { aesKey, ephemeralPublicKey, baseNonce } =
          await prepareChunkedEncryption(recipientX25519PubKey);

        const totalChunks = Math.ceil(file.size / DEFAULT_CHUNK_SIZE);
        setState((prev) => ({ ...prev, stage: "uploading" }));

        const { blob_name } = await initMultipartUpload(
          file.name,
          signal,
          DEFAULT_CHUNK_SIZE
        );
        const chunkChecksums: string[] = [];

        for (let i = 0; i < totalChunks; i++) {
          if (signal.aborted) throw new Error("CANCELLED");
          // Upload dài có thể >15 phút — reset auto-lock vault để không bị hỏi passphrase giữa chừng.
          resetLockTimer();
          const start = i * DEFAULT_CHUNK_SIZE;
          const end = Math.min(start + DEFAULT_CHUNK_SIZE, file.size);
          const chunkSizeMB = parseFloat(
            ((end - start) / (1024 * 1024)).toFixed(1)
          );
          const chunkPlainBytes = end - start;

          setState((prev) => ({
            ...prev,
            chunkProgress: {
              phase: "encrypt",
              done: i,
              total: totalChunks,
              currentMB: chunkSizeMB,
            },
            bytesTransferred: start,
            bytesTotal: file.size,
          }));

          const chunkBuffer = await file.slice(start, end).arrayBuffer();
          if (signal.aborted) throw new Error("CANCELLED");
          chunkChecksums.push(await computeSHA256Hex(chunkBuffer));
          const encryptedChunk = await encryptChunk(
            aesKey,
            chunkBuffer,
            baseNonce,
            i
          );
          if (signal.aborted) throw new Error("CANCELLED");

          setState((prev) => ({
            ...prev,
            chunkProgress: {
              phase: "upload",
              done: i,
              total: totalChunks,
              currentMB: chunkSizeMB,
            },
            bytesTransferred: start,
          }));
          await uploadChunk(
            blob_name,
            i,
            encryptedChunk,
            (loaded, total) =>
              setState((prev) => ({
                ...prev,
                bytesTransferred: start + Math.round((loaded / total) * chunkPlainBytes),
              })),
            signal
          );
          setState((prev) => ({
            ...prev,
            bytesTransferred: end,
          }));
        }

        const partialMeta = {
          isChunked: true as const,
          chunkSize: DEFAULT_CHUNK_SIZE,
          chunkCount: totalChunks,
          chunkBlobFormat: "azure_blocks" as const,
          baseNonce: toBase64(baseNonce),
          ephemeralPublicKey: toBase64(ephemeralPublicKey),
          nonce: toBase64(baseNonce),
          fileName: file.name,
          fileSize: file.size,
          mimeType: file.type || "application/octet-stream",
          chunkChecksums,
        };

        const manifest = buildChunkedManifest(partialMeta);
        const sig = signManifest(manifest, myKeys.ed25519.privateKey);

        const metadata: ChunkedEncryptionMetadata = {
          ...partialMeta,
          signature: toBase64(sig),
          signerPublicKey: toBase64(myKeys.ed25519.publicKey),
        };

        const multipartRecipients =
          purpose === "share" && r
            ? buildRecipientPayloads([r], [metadata as object])
            : [];

        const vaultMeta =
          purpose === "vault"
            ? { ...metadata, storage_mode: "vault" as const }
            : metadata;

        const result = await finalizeMultipartUpload(
          blob_name,
          totalChunks,
          vaultMeta,
          multipartRecipients,
          storageOpts,
          signal
        );

        setState((prev) => ({
          ...prev,
          sasUrl: result.sas_url,
          chunkProgress: null,
          stage: "done",
          plaintextChecksum: `${totalChunks} chunk checksums — xem manifest`,
        }));
      }
    } catch (e) {
      if (isAbortError(e) || (e as Error)?.message === "CANCELLED") {
        cancel();
        throw new Error("CANCELLED");
      }
      const msg = apiErrorDetail(e, t("common.unknownError"));
      setState((prev) => ({
        ...prev,
        error: msg,
        stage: "error",
        chunkProgress: null,
      }));
      throw new Error(msg);
    } finally {
      abortRef.current = null;
    }
  }

  function reset() {
    abortRef.current?.abort();
    abortRef.current = null;
    setCurrentFile(null);
    setState(initialState);
  }

  return {
    ...state,
    isChunkedMode,
    chunkCount,
    transferStats,
    encryptAndUpload,
    cancel,
    reset,
  };
}
