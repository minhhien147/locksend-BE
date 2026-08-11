import { useRef, useState } from "react";
import {
  decryptFile,
  decryptFileChunked,
  decryptChunkedToWritable,
  downloadBlob,
  shouldStreamDecrypt,
  type ChunkedEncryptionMetadata,
  type EncryptionMetadata,
} from "../utils/crypto";
import {
  closeSaveFile,
  pickSaveFile,
  supportsStreamingFileSave,
} from "../utils/fileSave";
import { getKeys } from "../utils/keyVault";
import {
  downloadCiphertext,
  downloadCiphertextChunk,
  downloadVaultCiphertext,
  recordDownloadLog,
  resolveCiphertextInfoBySas,
} from "../utils/api";
import { saveDownloadEntry } from "../utils/downloadHistory";
import { useT } from "../i18n/context";
import { useTransferTimer } from "./useTransferTimer";
import { computeTransferStats, type TransferStats } from "../utils/transferStats";
import { wipeBytes } from "../utils/fileRisk";

export type DownloadStage =
  | "idle"
  | "downloading"
  | "decrypting"
  | "done"
  | "error";

export interface ChunkDecryptProgress {
  done: number;
  total: number;
}

interface PendingPlaintext {
  data: Uint8Array;
  fileName: string;
  mimeType: string;
}

interface UseDownloadState {
  stage: DownloadStage;
  error: string;
  fileName: string;
  chunkProgress: ChunkDecryptProgress | null;
  isChunkedFile: boolean;
  verifiedMeta: EncryptionMetadata | null;
  plaintextChecksum: string;
  bytesTransferred: number;
  bytesTotal: number;
  /** Plaintext held in RAM awaiting explicit Save (non-streaming path). */
  pendingSave: boolean;
  /** Streaming large-file path wrote plaintext to disk during decrypt. */
  wroteToDiskDuringDecrypt: boolean;
}

export interface UseDownloadReturn extends UseDownloadState {
  transferStats: TransferStats | null;
  downloadAndDecrypt: (
    sasUrl: string,
    fallbackMetadata?: Record<string, unknown>
  ) => Promise<void>;
  downloadVaultFile: (
    fileId: string,
    encryptionMetadata: Record<string, unknown>
  ) => Promise<void>;
  savePendingFile: () => boolean;
  discardPendingFile: () => void;
  cancel: () => void;
  reset: () => void;
}

const initialState: UseDownloadState = {
  stage: "idle",
  error: "",
  fileName: "",
  chunkProgress: null,
  isChunkedFile: false,
  verifiedMeta: null,
  plaintextChecksum: "",
  bytesTransferred: 0,
  bytesTotal: 0,
  pendingSave: false,
  wroteToDiskDuringDecrypt: false,
};

function mergeMetadata(
  primary: Record<string, unknown>,
  fallback?: Record<string, unknown>
): EncryptionMetadata {
  return { ...(fallback ?? {}), ...primary } as unknown as EncryptionMetadata;
}

export function useDownload(): UseDownloadReturn {
  const t = useT();
  const [state, setState] = useState<UseDownloadState>(initialState);
  const abortRef = useRef<AbortController | null>(null);
  const pendingRef = useRef<PendingPlaintext | null>(null);
  const transferActive =
    state.stage === "downloading" || state.stage === "decrypting";
  const { startedAt, tick } = useTransferTimer(transferActive);
  const transferStats = computeTransferStats(
    state.bytesTransferred,
    state.bytesTotal,
    startedAt,
    tick
  );

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

  function clearPendingPlaintext() {
    if (pendingRef.current) {
      wipeBytes(pendingRef.current.data);
      pendingRef.current = null;
    }
  }

  function cancel() {
    abortRef.current?.abort();
    abortRef.current = null;
    clearPendingPlaintext();
    setState(initialState);
  }

  function discardPendingFile() {
    clearPendingPlaintext();
    setState((prev) => ({
      ...prev,
      pendingSave: false,
    }));
  }

  function savePendingFile(): boolean {
    const pending = pendingRef.current;
    if (!pending) return false;
    downloadBlob(pending.data, pending.fileName, pending.mimeType);
    clearPendingPlaintext();
    setState((prev) => ({
      ...prev,
      pendingSave: false,
    }));
    return true;
  }

  async function finishDownload(
    metadata: EncryptionMetadata,
    fileSizeBytes: number,
    logSasUrl: string,
    serverFileId?: string,
    opts?: { pendingSave?: boolean; wroteToDiskDuringDecrypt?: boolean }
  ): Promise<void> {
    const isChunked = (metadata as ChunkedEncryptionMetadata).isChunked ?? false;
    // A02: sasUrl không được lưu vào lịch sử (xem downloadHistory.ts) — chỉ dùng
    // cho lần ghi log này rồi bỏ.
    saveDownloadEntry({
      fileName: metadata.fileName,
      mimeType: metadata.mimeType,
      fileSizeBytes,
      checksum: metadata.plaintextChecksum ?? undefined,
      isChunked,
      serverFileId,
    });
    void recordDownloadLog({ sasUrl: logSasUrl, serverFileId });
    setState({
      stage: "done",
      error: "",
      fileName: metadata.fileName,
      chunkProgress: null,
      isChunkedFile: isChunked,
      verifiedMeta: metadata,
      plaintextChecksum: metadata.plaintextChecksum ?? "",
      bytesTransferred: fileSizeBytes,
      bytesTotal: fileSizeBytes,
      pendingSave: opts?.pendingSave ?? false,
      wroteToDiskDuringDecrypt: opts?.wroteToDiskDuringDecrypt ?? false,
    });
  }

  async function runStreamingDecrypt(
    fileId: string,
    metadata: ChunkedEncryptionMetadata,
    logSasUrl: string,
    signal: AbortSignal
  ): Promise<void> {
    const myKeys = getKeys();
    if (!myKeys) {
      setState((prev) => ({
        ...prev,
        error: t("download.keysLocked"),
      }));
      return;
    }

    if (!supportsStreamingFileSave()) {
      setState((prev) => ({
        ...prev,
        error: t("download.largeFileBrowser"),
        stage: "error",
      }));
      return;
    }

    setState({
      stage: "decrypting",
      error: "",
      fileName: metadata.fileName,
      chunkProgress: { done: 0, total: metadata.chunkCount },
      isChunkedFile: true,
      verifiedMeta: null,
      plaintextChecksum: "",
      bytesTransferred: 0,
      bytesTotal: metadata.fileSize,
      pendingSave: false,
      wroteToDiskDuringDecrypt: false,
    });

    let session: Awaited<ReturnType<typeof pickSaveFile>> | null = null;
    try {
      if (signal.aborted) throw new Error("CANCELLED");
      session = await pickSaveFile(metadata.fileName);
      const fileSizeBytes = await decryptChunkedToWritable(
        metadata,
        myKeys.x25519.privateKey,
        (chunkIndex) =>
          downloadCiphertextChunk(
            fileId,
            chunkIndex,
            logSasUrl.startsWith("https://") ? logSasUrl : undefined,
            signal
          ),
        session,
        (done, total) =>
          setState((prev) => ({
            ...prev,
            chunkProgress: { done, total },
            bytesTransferred: Math.min(
              metadata.fileSize,
              done * metadata.chunkSize
            ),
          }))
      );
      await closeSaveFile(session.writable);
      session = null;
      await finishDownload(metadata, fileSizeBytes, logSasUrl, fileId, {
        pendingSave: false,
        wroteToDiskDuringDecrypt: true,
      });
    } catch (e) {
      if (isAbortError(e) || (e as Error)?.message === "CANCELLED") {
        cancel();
        throw new Error("CANCELLED");
      }
      if (session?.writable) {
        try {
          await session.writable.abort();
        } catch {
          /* ignore */
        }
      }
      setState((prev) => ({
        ...prev,
        error: (e as Error)?.message ?? t("common.unknownError"),
        stage: "error",
        chunkProgress: null,
      }));
    }
  }

  async function runDecryptPipeline(
    load: () => Promise<{
      ciphertext: Uint8Array;
      metadata: EncryptionMetadata;
      serverFileId?: string;
    }>,
    logSasUrl: string,
    signal: AbortSignal
  ): Promise<void> {
    const myKeys = getKeys();
    if (!myKeys) {
      setState((prev) => ({
        ...prev,
        error: t("download.keysLocked"),
      }));
      return;
    }

    setState({
      stage: "downloading",
      error: "",
      fileName: "",
      chunkProgress: null,
      isChunkedFile: false,
      verifiedMeta: null,
      plaintextChecksum: "",
      bytesTransferred: 0,
      bytesTotal: 0,
      pendingSave: false,
      wroteToDiskDuringDecrypt: false,
    });

    try {
      if (signal.aborted) throw new Error("CANCELLED");
      const { ciphertext, metadata, serverFileId } = await load();
      if (signal.aborted) throw new Error("CANCELLED");

      setState((prev) => ({
        ...prev,
        stage: "decrypting",
        fileName: metadata.fileName,
        bytesTotal: metadata.fileSize,
        bytesTransferred: prev.bytesTransferred || ciphertext.byteLength,
      }));

      let plaintext: Uint8Array;

      if ((metadata as ChunkedEncryptionMetadata).isChunked) {
        const chunkedMeta = metadata as ChunkedEncryptionMetadata;
        setState((prev) => ({
          ...prev,
          isChunkedFile: true,
          chunkProgress: { done: 0, total: chunkedMeta.chunkCount },
        }));

        plaintext = await decryptFileChunked(
          ciphertext,
          chunkedMeta,
          myKeys.x25519.privateKey,
          (done, total) =>
            setState((prev) => ({
              ...prev,
              chunkProgress: { done, total },
              bytesTransferred: Math.min(
                chunkedMeta.fileSize,
                Math.round((done / total) * chunkedMeta.fileSize)
              ),
            }))
        );
      } else {
        plaintext = await decryptFile(
          ciphertext,
          metadata,
          myKeys.x25519.privateKey
        );
      }
      if (signal.aborted) throw new Error("CANCELLED");

      // P1: hold plaintext in RAM — do not auto-write to disk until user Saves.
      clearPendingPlaintext();
      pendingRef.current = {
        data: plaintext,
        fileName: metadata.fileName,
        mimeType: metadata.mimeType || "application/octet-stream",
      };
      await finishDownload(
        metadata,
        plaintext.byteLength,
        logSasUrl,
        serverFileId,
        { pendingSave: true, wroteToDiskDuringDecrypt: false }
      );
    } catch (e) {
      if (isAbortError(e) || (e as Error)?.message === "CANCELLED") {
        cancel();
        throw new Error("CANCELLED");
      }
      setState((prev) => ({
        ...prev,
        error: (e as Error)?.message ?? t("common.unknownError"),
        stage: "error",
        chunkProgress: null,
      }));
    }
  }

  async function downloadAndDecrypt(
    sasUrl: string,
    fallbackMetadata?: Record<string, unknown>
  ): Promise<void> {
    if (!sasUrl.trim()) {
      setState((prev) => ({
        ...prev,
        error: t("download.sasRequired"),
      }));
      return;
    }

    const trimmed = sasUrl.trim();
    abortRef.current?.abort();
    abortRef.current = new AbortController();
    const signal = abortRef.current.signal;
    try {
      const info = await resolveCiphertextInfoBySas(trimmed);
      const metadata = mergeMetadata(info.metadata, fallbackMetadata);
      if (shouldStreamDecrypt(metadata)) {
        await runStreamingDecrypt(
          info.file_id,
          metadata as ChunkedEncryptionMetadata,
          trimmed,
          signal
        );
        return;
      }
    } catch {
      /* fallback: file nhỏ hoặc endpoint cũ */
    }

    await runDecryptPipeline(
      () =>
        downloadCiphertext(
          trimmed,
          fallbackMetadata,
          (loaded, total) =>
            setState((prev) => ({
              ...prev,
              bytesTransferred: loaded,
              bytesTotal: total ?? prev.bytesTotal,
            })),
          signal
        ),
      trimmed,
      signal
    );
  }

  async function downloadVaultFile(
    fileId: string,
    encryptionMetadata: Record<string, unknown>
  ): Promise<void> {
    abortRef.current?.abort();
    abortRef.current = new AbortController();
    const signal = abortRef.current.signal;
    const metadata = encryptionMetadata as unknown as EncryptionMetadata;
    if (shouldStreamDecrypt(metadata)) {
      await runStreamingDecrypt(
        fileId,
        metadata as ChunkedEncryptionMetadata,
        `vault://${fileId}`,
        signal
      );
      return;
    }

    await runDecryptPipeline(
      () =>
        downloadVaultCiphertext(
          fileId,
          encryptionMetadata,
          (loaded, total) =>
            setState((prev) => ({
              ...prev,
              bytesTransferred: loaded,
              bytesTotal: total ?? prev.bytesTotal,
            })),
          signal
        ),
      `vault://${fileId}`,
      signal
    );
  }

  function reset() {
    abortRef.current?.abort();
    abortRef.current = null;
    clearPendingPlaintext();
    setState(initialState);
  }

  return {
    ...state,
    transferStats,
    downloadAndDecrypt,
    downloadVaultFile,
    savePendingFile,
    discardPendingFile,
    cancel,
    reset,
  };
}
