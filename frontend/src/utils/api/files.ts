/** files.ts — Upload, download, multipart, file history, shared-with-me API. */

import { api } from "./client";
import { DEFAULT_CHUNK_SIZE, type EncryptionMetadata, type ChunkedEncryptionMetadata } from "../crypto";

/** Chunk/finalize upload: không giới hạn timeout (mạng chậm + chunk 64MB có thể > 5 phút). */
const UPLOAD_XFER_TIMEOUT_MS = 0;

// ── Types ─────────────────────────────────────────────────────────────────────

export type StorageMode = "share" | "vault";

export interface UploadResponse {
  sas_url: string;
  blob_name: string;
  expires_at: string;
  file_id?: string | null;
}

export interface MultipartInitResponse {
  blob_name: string;
  upload_id: string;
}

export interface RecipientPayload {
  recipient_id: string;
  wrapped_file_key: string;
  wrapped_key_alg?: string;
  key_id?: string | null;
  wrapped_key_version?: number;
}

export interface FreshSasResponse {
  file_id: string;
  blob_name: string;
  sas_url: string;
  expires_at: string;
}

export interface RecipientInfo {
  recipient_id: string;
  email: string | null;
  display_name: string | null;
  status: string;
  granted_at: string;
}

export interface FileHistoryItem {
  file_id: string;
  blob_name: string;
  original_filename: string;
  content_type: string | null;
  file_size_bytes: number;
  encryption_alg: string;
  chunk_count: number;
  created_at: string;
  updated_at: string;
  recipients: RecipientInfo[];
  storage_mode?: string;
  folder_id?: string | null;
  shared_count?: number;
}

export interface SharedFileItem {
  file_id: string;
  blob_name: string;
  original_filename: string;
  content_type: string | null;
  file_size_bytes: number;
  encryption_alg: string;
  granted_at: string;
  wrapped_file_key: string;
  wrapped_key_alg: string;
  key_id: string | null;
  wrapped_key_version: number;
  sender_name: string | null;
  sender_email: string | null;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Lấy blob path (không gồm container) từ SAS URL Azure Blob. */
export function parseBlobNameFromSasUrl(sasUrl: string): string | null {
  try {
    const u = new URL(sasUrl.trim());
    const segs = u.pathname.split("/").filter(Boolean);
    if (segs.length < 2) return null;
    return segs.slice(1).map((s) => decodeURIComponent(s)).join("/");
  } catch {
    return null;
  }
}

function _headerCi(
  headers: Record<string, unknown>,
  nameLower: string
): string | undefined {
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === nameLower && v != null) {
      return String(v);
    }
  }
  return undefined;
}

function _parseEncryptionMetadataFromHeaders(
  headers: Record<string, unknown>,
  fallback?: Record<string, unknown>
): EncryptionMetadata {
  const b64Header =
    _headerCi(headers, "x-encryption-metadata-b64") ??
    _headerCi(headers, "x-ms-meta-encryption_metadata_b64");
  const rawHeader = _headerCi(headers, "x-ms-meta-encryption_metadata");

  let metadataJson: string | null = null;
  if (b64Header) {
    metadataJson = atob(b64Header);
  } else if (rawHeader) {
    metadataJson = decodeURIComponent(rawHeader);
  } else if (fallback && Object.keys(fallback).length > 0) {
    return fallback as unknown as EncryptionMetadata;
  }

  if (!metadataJson) {
    throw new Error("Không tìm thấy metadata mã hóa.");
  }
  return JSON.parse(metadataJson) as EncryptionMetadata;
}

// ── Single-shot upload ────────────────────────────────────────────────────────

export async function uploadEncryptedFile(
  ciphertext: Uint8Array,
  metadata: EncryptionMetadata,
  fileName: string,
  onProgress?: (loaded: number, total: number) => void,
  recipients?: RecipientPayload[],
  options?: { storageMode?: StorageMode; folderId?: string | null },
  signal?: AbortSignal
): Promise<UploadResponse> {
  const formData = new FormData();
  const blob = new Blob([new Uint8Array(ciphertext)], {
    type: "application/octet-stream",
  });
  formData.append("file", blob, fileName + ".lsc");
  formData.append("metadata_json", JSON.stringify(metadata));
  formData.append("storage_mode", options?.storageMode ?? "share");
  if (options?.storageMode === "vault" && options.folderId) {
    formData.append("folder_id", options.folderId);
  }
  if (recipients && recipients.length > 0) {
    formData.append("recipients_json", JSON.stringify(recipients));
  }

  const response = await api.post<UploadResponse>("/upload", formData, {
    headers: { "Content-Type": "multipart/form-data" },
    timeout: UPLOAD_XFER_TIMEOUT_MS,
    onUploadProgress: onProgress
      ? (e) => onProgress(e.loaded, e.total ?? ciphertext.byteLength)
      : undefined,
    signal,
  });
  return response.data;
}

// ── Multipart upload ──────────────────────────────────────────────────────────

export async function initMultipartUpload(
  fileName: string,
  signal?: AbortSignal,
  chunkSizeBytes: number = DEFAULT_CHUNK_SIZE
): Promise<MultipartInitResponse> {
  const formData = new FormData();
  formData.append("filename", fileName);
  formData.append("chunk_size_bytes", String(chunkSizeBytes));
  const response = await api.post<MultipartInitResponse>(
    "/upload/multipart/init",
    formData,
    { signal }
  );
  return response.data;
}

export async function uploadChunk(
  blobName: string,
  chunkIndex: number,
  chunkData: Uint8Array,
  onProgress?: (loaded: number, total: number) => void,
  signal?: AbortSignal
): Promise<void> {
  const formData = new FormData();
  // Dùng Uint8Array view — .buffer có thể lớn hơn chunk thật (byteOffset/byteLength).
  const blob = new Blob([chunkData], { type: "application/octet-stream" });
  formData.append("chunk", blob, `chunk_${chunkIndex}`);

  await api.put(
    `/upload/multipart/${encodeURIComponent(blobName)}/chunk/${chunkIndex}`,
    formData,
    {
      headers: { "Content-Type": "multipart/form-data" },
      timeout: UPLOAD_XFER_TIMEOUT_MS,
      onUploadProgress: onProgress
        ? (e) => onProgress(e.loaded, e.total ?? chunkData.byteLength)
        : undefined,
      signal,
    }
  );
}

export async function finalizeMultipartUpload(
  blobName: string,
  chunkCount: number,
  metadata: ChunkedEncryptionMetadata,
  recipients?: RecipientPayload[],
  options?: { storageMode?: StorageMode; folderId?: string | null },
  signal?: AbortSignal
): Promise<UploadResponse> {
  const response = await api.post<UploadResponse>(
    `/upload/multipart/${encodeURIComponent(blobName)}/finalize`,
    {
      chunk_count: chunkCount,
      metadata_json: JSON.stringify(metadata),
      recipients: recipients ?? [],
      storage_mode: options?.storageMode ?? "share",
      folder_id: options?.storageMode === "vault" ? options.folderId ?? null : null,
      file_size_bytes: metadata.fileSize,
      chunk_size_bytes: metadata.chunkSize,
      original_filename: metadata.fileName,
    },
    { signal, timeout: UPLOAD_XFER_TIMEOUT_MS }
  );
  return response.data;
}

// ── Download ──────────────────────────────────────────────────────────────────

/** Ghi download_logs trên server (best-effort, không throw). */
export async function recordDownloadLog(params: {
  sasUrl: string;
  serverFileId?: string | null;
}): Promise<void> {
  const body: { file_id?: string; blob_name?: string } = {};
  if (params.serverFileId) {
    body.file_id = params.serverFileId;
  } else {
    const bn = parseBlobNameFromSasUrl(params.sasUrl);
    if (bn) body.blob_name = bn;
  }
  if (!body.file_id && !body.blob_name) return;
  try {
    await api.post("/files/download-log", body);
  } catch {
    // best-effort
  }
}

/** Metadata + file_id từ SAS URL (không tải blob). */
export async function resolveCiphertextInfoBySas(sasUrl: string): Promise<{
  file_id: string;
  original_filename: string;
  metadata: Record<string, unknown>;
}> {
  const response = await api.post<{
    file_id: string;
    original_filename: string;
    metadata: Record<string, unknown>;
  }>("/files/ciphertext/info-by-sas", { sas_url: sasUrl });
  return response.data;
}

/** Tải một encrypted chunk (file lớn — peak RAM thấp). */
export async function downloadCiphertextChunk(
  fileId: string,
  chunkIndex: number,
  sasUrl?: string,
  signal?: AbortSignal
): Promise<Uint8Array> {
  const response = await api.get(`/files/${fileId}/ciphertext/chunks/${chunkIndex}`, {
    responseType: "arraybuffer",
    params: sasUrl ? { sas_url: sasUrl } : undefined,
    signal,
  });
  return new Uint8Array(response.data as ArrayBuffer);
}

/** Tải ciphertext từ SAS URL qua backend proxy (tránh CORS Azure). */
export async function downloadCiphertext(
  sasUrl: string,
  fallbackMetadata?: Record<string, unknown>,
  onProgress?: (loaded: number, total: number | null) => void,
  signal?: AbortSignal
): Promise<{
  ciphertext: Uint8Array;
  metadata: EncryptionMetadata;
  serverFileId?: string;
}> {
  const response = await api.post(
    "/files/ciphertext/by-sas",
    { sas_url: sasUrl },
    {
      responseType: "arraybuffer",
      onDownloadProgress: onProgress
        ? (e) => onProgress(e.loaded, e.total ?? null)
        : undefined,
      signal,
    }
  );
  const headers = response.headers as Record<string, unknown>;
  const metadata =
    fallbackMetadata && Object.keys(fallbackMetadata).length > 0
      ? (fallbackMetadata as unknown as EncryptionMetadata)
      : _parseEncryptionMetadataFromHeaders(headers, fallbackMetadata);
  const ciphertext = new Uint8Array(response.data);
  const serverFileId = _headerCi(headers, "x-file-id");
  return { ciphertext, metadata, serverFileId };
}

/** Tải ciphertext file kho qua backend (tránh CORS Azure). */
export async function downloadVaultCiphertext(
  fileId: string,
  fallbackMetadata?: Record<string, unknown>,
  onProgress?: (loaded: number, total: number | null) => void,
  signal?: AbortSignal
): Promise<{
  ciphertext: Uint8Array;
  metadata: EncryptionMetadata;
  serverFileId?: string;
}> {
  const response = await api.get(`/vault/files/${fileId}/ciphertext`, {
    responseType: "arraybuffer",
    onDownloadProgress: onProgress
      ? (e) => onProgress(e.loaded, e.total ?? null)
      : undefined,
    signal,
  });
  const headers = response.headers as Record<string, unknown>;
  const metadata = _parseEncryptionMetadataFromHeaders(headers, fallbackMetadata);
  const ciphertext = new Uint8Array(response.data as ArrayBuffer);
  const serverFileId = _headerCi(headers, "x-file-id") ?? fileId;
  return { ciphertext, metadata, serverFileId };
}

// ── File history & sharing ────────────────────────────────────────────────────

export async function getMyFiles(): Promise<FileHistoryItem[]> {
  const res = await api.get<FileHistoryItem[]>("/files/my-files");
  return res.data;
}

export async function refreshSasUrl(fileId: string): Promise<FreshSasResponse> {
  const res = await api.get<FreshSasResponse>(`/files/${fileId}/sas`);
  return res.data;
}

export async function revokeRecipient(fileId: string, recipientId: string): Promise<void> {
  await api.post(`/files/${fileId}/revoke/${recipientId}`, {});
}

export async function getSharedWithMe(): Promise<SharedFileItem[]> {
  const res = await api.get<SharedFileItem[]>("/files/shared-with-me");
  return res.data;
}

export async function getSharedFileSas(fileId: string): Promise<FreshSasResponse> {
  const res = await api.get<FreshSasResponse>(`/files/shared/${fileId}/sas`);
  return res.data;
}
