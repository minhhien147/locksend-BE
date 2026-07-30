/**
 * crypto.ts — Client-side Cryptography Module
 *
 * Toàn bộ mã hóa/giải mã diễn ra tại đây, hoàn toàn ở trình duyệt.
 * Server/Azure KHÔNG BAO GIỜ nhận plaintext.
 *
 * Stack: X25519 (Key Exchange) + HKDF-SHA256 (KDF) + AES-256-GCM (Encrypt) + Ed25519 (Sign)
 *
 * Chunked mode: chia file thành các khối ~64MB, mã hóa độc lập với nonce tăng dần.
 * Nonce mỗi chunk = baseNonce[0:8] || uint32_big_endian(chunkIndex)
 * Signature bảo vệ manifest metadata (không cần load toàn bộ ciphertext vào RAM).
 */

import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import {
  writeChunk,
  isFileSystemInvalidStateError,
  recreateWritableAt,
} from "./fileSave";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface KeyPair {
  privateKey: Uint8Array; // 32 bytes
  publicKey: Uint8Array;  // 32 bytes
}

export interface EncryptionMetadata {
  ephemeralPublicKey: string; // base64 — X25519 ephemeral pubkey
  nonce: string;              // base64 — 12 bytes AES-GCM nonce (single-shot) hoặc baseNonce (chunked)
  signature: string;          // base64 — Ed25519 sig
  signerPublicKey: string;    // base64 — Ed25519 pubkey của sender
  fileName: string;
  fileSize: number;
  mimeType: string;
  /** SHA-256 hex của plaintext gốc — dùng để verify toàn vẹn sau khi giải mã */
  plaintextChecksum?: string;
  /** Envelope: bọc content key riêng cho từng người nhận (gửi nhiều người, một ciphertext) */
  envelopeMode?: boolean;
  contentKeyEnvelope?: string;
  storage_mode?: "vault" | "share";
}

/** Metadata mở rộng cho chunked encryption */
export interface ChunkedEncryptionMetadata extends EncryptionMetadata {
  isChunked: true;
  chunkSize: number;   // bytes mỗi chunk (thường 64MB)
  chunkCount: number;  // tổng số chunk
  baseNonce: string;   // base64 — 8 bytes, dùng để sinh per-chunk nonce
  /** SHA-256 hex của từng plaintext chunk — được ký bởi Ed25519 manifest */
  chunkChecksums?: string[];
  /**
   * azure_blocks: multipart Azure nối ciphertext từng chunk (upload hiện tại).
   * packed: [u32 count][u32 len][bytes]… (legacy / tương lai).
   */
  chunkBlobFormat?: "azure_blocks" | "packed";
}

export interface EncryptResult {
  ciphertext: Uint8Array;
  metadata: EncryptionMetadata;
}

export interface MultiRecipientEncryptResult {
  ciphertext: Uint8Array;
  plaintextChecksum: string;
  /** Một metadata / wrapped key cho mỗi người nhận */
  perRecipientMetadata: EncryptionMetadata[];
}

// ─── Key Generation ───────────────────────────────────────────────────────────

/** Tạo X25519 keypair để trao đổi khóa */
export function generateX25519KeyPair(): KeyPair {
  const privateKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/** Tạo Ed25519 keypair để ký/xác thực */
export function generateEd25519KeyPair(): KeyPair {
  const privateKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

// ─── HKDF Key Derivation ──────────────────────────────────────────────────────

/** Helper: copy Uint8Array vào ArrayBuffer riêng (tránh shared backing buffer issues) */
function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

/**
 * Dùng HKDF-SHA256 để biến shared secret (32 bytes) thành:
 * - AES-256 key (32 bytes)
 * - Nonce (12 bytes)
 * Dùng cho single-shot encryption.
 */
async function deriveKeyAndNonce(
  sharedSecret: Uint8Array,
  salt: Uint8Array,
  info: string = "secure-file-sharing"
): Promise<{ aesKey: CryptoKey; nonce: Uint8Array }> {
  const infoBytes = new TextEncoder().encode(info);

  const rawKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(sharedSecret),
    { name: "HKDF" },
    false,
    ["deriveKey", "deriveBits"]
  );

  const derived = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toArrayBuffer(salt),
      info: toArrayBuffer(infoBytes),
    },
    rawKey,
    (32 + 12) * 8
  );

  const derivedBytes = new Uint8Array(derived);
  const keyBytes = derivedBytes.slice(0, 32);
  const nonce = derivedBytes.slice(32, 44);

  const aesKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(keyBytes),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  return { aesKey, nonce };
}

/**
 * Dùng HKDF-SHA256 để dẫn xuất chỉ AES-256 key (32 bytes).
 * Dùng cho chunked encryption — nonce được sinh per-chunk.
 */
async function deriveAesKeyOnly(
  sharedSecret: Uint8Array,
  salt: Uint8Array,
  info: string = "secure-file-sharing-chunked"
): Promise<CryptoKey> {
  const infoBytes = new TextEncoder().encode(info);
  const rawKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(sharedSecret),
    { name: "HKDF" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toArrayBuffer(salt),
      info: toArrayBuffer(infoBytes),
    },
    rawKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// ─── Encryption (Upload) ──────────────────────────────────────────────────────

/**
 * Mã hóa file hoàn toàn ở client-side.
 *
 * Quy trình:
 * 1. Tạo ephemeral X25519 keypair (mới mỗi file → Forward Secrecy)
 * 2. Tính shared secret với recipientPublicKey
 * 3. HKDF → AES-256 key + nonce
 * 4. AES-256-GCM encrypt
 * 5. Ed25519 sign ciphertext
 */
export async function encryptFile(
  file: File,
  recipientX25519PublicKey: Uint8Array,
  senderEd25519PrivateKey: Uint8Array,
  senderEd25519PublicKey: Uint8Array
): Promise<EncryptResult> {
  // 1. Ephemeral keypair — tạo mới cho mỗi file
  const ephemeral = generateX25519KeyPair();

  // 2. Shared secret = X25519(ephemeral_private, recipient_public)
  const sharedSecret = x25519.getSharedSecret(
    ephemeral.privateKey,
    recipientX25519PublicKey
  );

  // 3. Salt = ephemeral public key (public, không cần bí mật)
  const salt = ephemeral.publicKey;

  // 4. HKDF → AES key + nonce
  const { aesKey, nonce } = await deriveKeyAndNonce(sharedSecret, salt);

  // 5. Đọc file thành ArrayBuffer
  const plaintext = await file.arrayBuffer();

  // 6. Tính SHA-256 của plaintext trước khi mã hóa (checksum anti-malware)
  const plaintextChecksum = await computeSHA256Hex(plaintext);

  // 7. AES-256-GCM encrypt
  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(nonce) },
    aesKey,
    plaintext
  );
  const ciphertext = new Uint8Array(ciphertextBuffer);

  // 8. Ed25519 sign ciphertext (đảm bảo integrity)
  const signature = ed25519.sign(ciphertext, senderEd25519PrivateKey);

  const metadata: EncryptionMetadata = {
    ephemeralPublicKey: toBase64(ephemeral.publicKey),
    nonce: toBase64(nonce),
    signature: toBase64(signature),
    signerPublicKey: toBase64(senderEd25519PublicKey),
    fileName: file.name,
    fileSize: file.size,
    mimeType: file.type || "application/octet-stream",
    plaintextChecksum,
  };

  return { ciphertext, metadata };
}

const ENVELOPE_WRAP_INFO = "locksend-envelope-wrap-v1";

/**
 * Mã hóa một lần, bọc content key cho nhiều người nhận (cùng một ciphertext trên blob).
 */
export async function encryptFileForRecipients(
  file: File,
  recipientPublicKeys: Uint8Array[],
  senderEd25519PrivateKey: Uint8Array,
  senderEd25519PublicKey: Uint8Array
): Promise<MultiRecipientEncryptResult> {
  if (recipientPublicKeys.length === 0) {
    throw new Error("Cần ít nhất một người nhận");
  }

  const plaintext = await file.arrayBuffer();
  const plaintextChecksum = await computeSHA256Hex(plaintext);

  const contentSecret = crypto.getRandomValues(new Uint8Array(32));
  const contentNonce = crypto.getRandomValues(new Uint8Array(12));
  const contentAesKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(contentSecret),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(contentNonce) },
    contentAesKey,
    plaintext
  );
  const ciphertext = new Uint8Array(ciphertextBuffer);
  const signature = ed25519.sign(ciphertext, senderEd25519PrivateKey);

  const baseMeta = {
    signature: toBase64(signature),
    signerPublicKey: toBase64(senderEd25519PublicKey),
    fileName: file.name,
    fileSize: file.size,
    mimeType: file.type || "application/octet-stream",
    plaintextChecksum,
    envelopeMode: true as const,
  };

  const envelopePlain = new Uint8Array(44);
  envelopePlain.set(contentSecret, 0);
  envelopePlain.set(contentNonce, 32);

  const perRecipientMetadata: EncryptionMetadata[] = [];

  for (const recipientPub of recipientPublicKeys) {
    const ephemeral = generateX25519KeyPair();
    const sharedSecret = x25519.getSharedSecret(ephemeral.privateKey, recipientPub);
    const { aesKey: wrapKey, nonce: wrapNonce } = await deriveKeyAndNonce(
      sharedSecret,
      ephemeral.publicKey,
      ENVELOPE_WRAP_INFO
    );
    const wrapped = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: toArrayBuffer(wrapNonce) },
      wrapKey,
      toArrayBuffer(envelopePlain)
    );
    perRecipientMetadata.push({
      ...baseMeta,
      ephemeralPublicKey: toBase64(ephemeral.publicKey),
      nonce: toBase64(wrapNonce),
      contentKeyEnvelope: toBase64(new Uint8Array(wrapped)),
    });
  }

  return { ciphertext, plaintextChecksum, perRecipientMetadata };
}

/** Mở envelope content key (vault owner) — không giải mã ciphertext. */
export async function unwrapEnvelopeContentKey(
  metadata: EncryptionMetadata,
  recipientX25519PrivateKey: Uint8Array
): Promise<{ contentSecret: Uint8Array; contentNonce: Uint8Array }> {
  if (!metadata.envelopeMode || !metadata.contentKeyEnvelope) {
    throw new Error("File không dùng envelope mode");
  }
  const ephemeralPublicKey = fromBase64(metadata.ephemeralPublicKey);
  const sharedSecret = x25519.getSharedSecret(
    recipientX25519PrivateKey,
    ephemeralPublicKey
  );
  const { aesKey: wrapKey, nonce: wrapNonce } = await deriveKeyAndNonce(
    sharedSecret,
    ephemeralPublicKey,
    ENVELOPE_WRAP_INFO
  );
  const storedWrapNonce = fromBase64(metadata.nonce);
  if (!timingSafeEqual(wrapNonce, storedWrapNonce)) {
    throw new Error("Nonce bọc khóa không khớp");
  }
  const unwrapped = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toArrayBuffer(storedWrapNonce) },
    wrapKey,
    toArrayBuffer(fromBase64(metadata.contentKeyEnvelope))
  );
  const unwrappedBytes = new Uint8Array(unwrapped);
  if (unwrappedBytes.length !== 44) {
    throw new Error("Envelope khóa nội dung không hợp lệ");
  }
  return {
    contentSecret: unwrappedBytes.slice(0, 32),
    contentNonce: unwrappedBytes.slice(32, 44),
  };
}

/** Bọc content key cho một recipient (chia sẻ từ kho, không upload lại blob). */
export async function wrapEnvelopeForRecipient(
  baseMeta: EncryptionMetadata,
  contentSecret: Uint8Array,
  contentNonce: Uint8Array,
  recipientPublicKey: Uint8Array
): Promise<EncryptionMetadata> {
  const envelopePlain = new Uint8Array(44);
  envelopePlain.set(contentSecret, 0);
  envelopePlain.set(contentNonce, 32);

  const ephemeral = generateX25519KeyPair();
  const sharedSecret = x25519.getSharedSecret(ephemeral.privateKey, recipientPublicKey);
  const { aesKey: wrapKey, nonce: wrapNonce } = await deriveKeyAndNonce(
    sharedSecret,
    ephemeral.publicKey,
    ENVELOPE_WRAP_INFO
  );
  const wrapped = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(wrapNonce) },
    wrapKey,
    toArrayBuffer(envelopePlain)
  );
  return {
    ephemeralPublicKey: toBase64(ephemeral.publicKey),
    nonce: toBase64(wrapNonce),
    signature: baseMeta.signature,
    signerPublicKey: baseMeta.signerPublicKey,
    fileName: baseMeta.fileName,
    fileSize: baseMeta.fileSize,
    mimeType: baseMeta.mimeType,
    plaintextChecksum: baseMeta.plaintextChecksum,
    envelopeMode: true,
    contentKeyEnvelope: toBase64(new Uint8Array(wrapped)),
  };
}

// ─── Decryption (Download) ────────────────────────────────────────────────────

/**
 * Giải mã file hoàn toàn ở client-side.
 *
 * Quy trình:
 * 1. Tải ciphertext + metadata
 * 2. Xác thực chữ ký Ed25519
 * 3. Tính shared secret với private key của mình
 * 4. HKDF → AES key + nonce
 * 5. AES-256-GCM decrypt + kiểm tra GCM tag
 */
export async function decryptFile(
  ciphertext: Uint8Array,
  metadata: EncryptionMetadata,
  recipientX25519PrivateKey: Uint8Array
): Promise<Uint8Array> {
  // 1. Xác thực chữ ký Ed25519
  const signerPublicKey = fromBase64(metadata.signerPublicKey);
  const signature = fromBase64(metadata.signature);
  const isValid = ed25519.verify(signature, ciphertext, signerPublicKey);
  if (!isValid) {
    throw new Error("Chữ ký Ed25519 không hợp lệ — file có thể bị giả mạo!");
  }

  const ephemeralPublicKey = fromBase64(metadata.ephemeralPublicKey);
  const sharedSecret = x25519.getSharedSecret(
    recipientX25519PrivateKey,
    ephemeralPublicKey
  );

  let plaintextBuffer: ArrayBuffer;

  if (metadata.envelopeMode && metadata.contentKeyEnvelope) {
    const { aesKey: wrapKey, nonce: wrapNonce } = await deriveKeyAndNonce(
      sharedSecret,
      ephemeralPublicKey,
      ENVELOPE_WRAP_INFO
    );
    const storedWrapNonce = fromBase64(metadata.nonce);
    if (!timingSafeEqual(wrapNonce, storedWrapNonce)) {
      throw new Error("Nonce bọc khóa không khớp — metadata bị sửa đổi!");
    }
    let unwrapped: ArrayBuffer;
    try {
      unwrapped = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: toArrayBuffer(storedWrapNonce) },
        wrapKey,
        toArrayBuffer(fromBase64(metadata.contentKeyEnvelope))
      );
    } catch {
      throw new Error("Không mở được khóa nội dung — sai key người nhận?");
    }
    const unwrappedBytes = new Uint8Array(unwrapped);
    if (unwrappedBytes.length !== 44) {
      throw new Error("Envelope khóa nội dung không hợp lệ");
    }
    const contentSecret = unwrappedBytes.slice(0, 32);
    const contentNonce = unwrappedBytes.slice(32, 44);
    const contentAesKey = await crypto.subtle.importKey(
      "raw",
      toArrayBuffer(contentSecret),
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
    try {
      plaintextBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: toArrayBuffer(contentNonce) },
        contentAesKey,
        toArrayBuffer(ciphertext)
      );
    } catch {
      throw new Error("Giải mã thất bại — sai khóa hoặc dữ liệu bị hỏng!");
    }
  } else {
    const { aesKey, nonce: derivedNonce } = await deriveKeyAndNonce(
      sharedSecret,
      ephemeralPublicKey
    );
    const storedNonce = fromBase64(metadata.nonce);
    if (!timingSafeEqual(derivedNonce, storedNonce)) {
      throw new Error("Nonce không khớp — metadata bị sửa đổi!");
    }
    try {
      plaintextBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: toArrayBuffer(storedNonce) },
        aesKey,
        toArrayBuffer(ciphertext)
      );
    } catch {
      throw new Error("Giải mã thất bại — sai khóa hoặc dữ liệu bị hỏng!");
    }
  }

  // 5. Verify SHA-256 plaintext checksum (phát hiện thay thế nội dung / mã độc)
  if (metadata.plaintextChecksum) {
    const computed = await computeSHA256Hex(plaintextBuffer);
    if (computed !== metadata.plaintextChecksum) {
      throw new Error(
        `SHA-256 không khớp — file có thể bị thay nội dung hoặc nhiễm mã độc!\n` +
        `Mong đợi: ${metadata.plaintextChecksum}\nThực tế: ${computed}`
      );
    }
  }

  return new Uint8Array(plaintextBuffer);
}

// ─── Chunked Encryption ───────────────────────────────────────────────────────

/**
 * Kích thước mặc định mỗi chunk: 4MB.
 * Nhỏ hơn 64MB để BE/Azure chịu được burst nhiều request hơn (xem capacity summary).
 */
export const DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024;

/**
 * Ngưỡng tự động chuyển sang chế độ chunked.
 * File > 64MB → dùng chunked encryption + multipart upload.
 */
export const CHUNKED_THRESHOLD = 64 * 1024 * 1024;

/** Số chunk upload song song (direct Azure / proxy). */
export const UPLOAD_CHUNK_CONCURRENCY = 3;

/** File chunked ≥ ngưỡng này → download theo từng chunk, lưu thẳng ra đĩa. */
export const STREAMING_DOWNLOAD_THRESHOLD = CHUNKED_THRESHOLD;

/**
 * Sinh nonce 12-byte cho chunk thứ i:
 *   nonce[0:8]  = baseNonce (8 bytes ngẫu nhiên, cố định cho toàn session)
 *   nonce[8:12] = chunkIndex (uint32 big-endian)
 *
 * Mỗi chunk dùng nonce riêng biệt → không có nonce reuse giữa các chunk.
 */
export function buildChunkNonce(baseNonce: Uint8Array, chunkIndex: number): Uint8Array {
  const nonce = new Uint8Array(12);
  nonce.set(baseNonce.slice(0, 8), 0);
  new DataView(nonce.buffer).setUint32(8, chunkIndex, false);
  return nonce;
}

/** Sinh base nonce ngẫu nhiên 8 bytes cho một session chunked encryption */
export function generateBaseNonce(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(8));
}

/**
 * Chuẩn bị session chunked encryption: Key Exchange + HKDF → AES key.
 * Trả về aesKey, ephemeralPublicKey và baseNonce để upload page dùng.
 */
export async function prepareChunkedEncryption(
  recipientX25519PublicKey: Uint8Array
): Promise<{
  aesKey: CryptoKey;
  ephemeralPublicKey: Uint8Array;
  baseNonce: Uint8Array;
}> {
  const ephemeral = generateX25519KeyPair();
  const sharedSecret = x25519.getSharedSecret(ephemeral.privateKey, recipientX25519PublicKey);
  const aesKey = await deriveAesKeyOnly(sharedSecret, ephemeral.publicKey);
  const baseNonce = generateBaseNonce();
  return { aesKey, ephemeralPublicKey: ephemeral.publicKey, baseNonce };
}

/** Mã hóa một chunk với AES-256-GCM. Peak memory = 2 × chunkSize. */
export async function encryptChunk(
  aesKey: CryptoKey,
  chunkBuffer: ArrayBuffer,
  baseNonce: Uint8Array,
  chunkIndex: number
): Promise<Uint8Array> {
  const nonce = buildChunkNonce(baseNonce, chunkIndex);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(nonce) },
    aesKey,
    chunkBuffer
  );
  return new Uint8Array(encrypted);
}

/** Giải mã một chunk với AES-256-GCM (bao gồm kiểm tra GCM auth tag). */
export async function decryptChunk(
  aesKey: CryptoKey,
  encryptedChunk: Uint8Array,
  baseNonce: Uint8Array,
  chunkIndex: number
): Promise<Uint8Array> {
  const nonce = buildChunkNonce(baseNonce, chunkIndex);
  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toArrayBuffer(nonce) },
      aesKey,
      toArrayBuffer(encryptedChunk)
    );
    return new Uint8Array(decrypted);
  } catch {
    throw new Error(`Chunk ${chunkIndex}: GCM auth tag sai — dữ liệu bị hỏng hoặc sai khóa!`);
  }
}

/**
 * Xây dựng manifest string để ký/xác thực với Ed25519.
 * Manifest bao gồm tất cả các trường quan trọng (trừ signature).
 * JSON.stringify với key cố định → string deterministic.
 */
export function buildChunkedManifest(m: {
  ephemeralPublicKey: string;
  baseNonce: string;
  chunkCount: number;
  chunkSize: number;
  fileName: string;
  fileSize: number;
  mimeType: string;
  chunkChecksums?: string[];
}): string {
  return JSON.stringify({
    ephemeralPublicKey: m.ephemeralPublicKey,
    baseNonce: m.baseNonce,
    chunkCount: m.chunkCount,
    chunkSize: m.chunkSize,
    fileName: m.fileName,
    fileSize: m.fileSize,
    mimeType: m.mimeType,
    ...(m.chunkChecksums ? { chunkChecksums: m.chunkChecksums } : {}),
  });
}

/** Ký manifest bằng Ed25519 private key của sender */
export function signManifest(manifest: string, edPrivKey: Uint8Array): Uint8Array {
  return ed25519.sign(new TextEncoder().encode(manifest), edPrivKey);
}

/** Xác thực chữ ký manifest — trả false nếu invalid */
export function verifyManifest(
  manifest: string,
  signature: Uint8Array,
  edPubKey: Uint8Array
): boolean {
  try {
    return ed25519.verify(signature, new TextEncoder().encode(manifest), edPubKey);
  } catch {
    return false;
  }
}

/** Kích thước ciphertext AES-GCM = plaintext + 16 byte tag. */
function encryptedChunkByteLength(
  metadata: ChunkedEncryptionMetadata,
  chunkIndex: number
): number {
  const plainLen =
    chunkIndex < metadata.chunkCount - 1
      ? metadata.chunkSize
      : metadata.fileSize - (metadata.chunkCount - 1) * metadata.chunkSize;
  return plainLen + 16;
}

function isPackedChunkBlob(
  blob: Uint8Array,
  metadata: ChunkedEncryptionMetadata
): boolean {
  if (metadata.chunkBlobFormat === "packed") return true;
  if (metadata.chunkBlobFormat === "azure_blocks") return false;
  if (blob.length < 8 || metadata.chunkCount <= 0) return false;
  const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const headCount = dv.getUint32(0, false);
  if (headCount !== metadata.chunkCount) return false;
  const firstLen = dv.getUint32(4, false);
  const expectedFirst = encryptedChunkByteLength(metadata, 0);
  return firstLen === expectedFirst && 8 + firstLen <= blob.length;
}

/**
 * Giải mã file chunked đã tải về.
 *
 * Hỗ trợ hai layout blob:
 * - azure_blocks: ciphertext các chunk nối liền (multipart Azure — upload hiện tại)
 * - packed: [u32 count][u32 len][bytes]…
 */
export async function decryptFileChunked(
  packedBlob: Uint8Array,
  metadata: ChunkedEncryptionMetadata,
  recipientX25519PrivateKey: Uint8Array,
  onProgress?: (done: number, total: number) => void
): Promise<Uint8Array> {
  // 1. Xác thực manifest signature
  const signerPublicKey = fromBase64(metadata.signerPublicKey);
  const signature = fromBase64(metadata.signature);
  const manifest = buildChunkedManifest({
    ephemeralPublicKey: metadata.ephemeralPublicKey,
    baseNonce: metadata.baseNonce,
    chunkCount: metadata.chunkCount,
    chunkSize: metadata.chunkSize,
    fileName: metadata.fileName,
    fileSize: metadata.fileSize,
    mimeType: metadata.mimeType,
    chunkChecksums: metadata.chunkChecksums,
  });

  if (!verifyManifest(manifest, signature, signerPublicKey)) {
    throw new Error("Chữ ký Ed25519 không hợp lệ — metadata bị giả mạo!");
  }

  // 2. Dẫn xuất AES key
  const ephemeralPublicKey = fromBase64(metadata.ephemeralPublicKey);
  const sharedSecret = x25519.getSharedSecret(recipientX25519PrivateKey, ephemeralPublicKey);
  const aesKey = await deriveAesKeyOnly(sharedSecret, ephemeralPublicKey);
  const baseNonce = fromBase64(metadata.baseNonce);

  const plaintextChunks: Uint8Array[] = [];
  const packed = isPackedChunkBlob(packedBlob, metadata);
  let offset = packed ? 4 : 0;

  if (packed) {
    const dv = new DataView(packedBlob.buffer, packedBlob.byteOffset, packedBlob.byteLength);
    const storedChunkCount = dv.getUint32(0, false);
    if (storedChunkCount !== metadata.chunkCount) {
      throw new Error("Số chunk không khớp metadata — dữ liệu bị sửa đổi!");
    }
    for (let i = 0; i < storedChunkCount; i++) {
      if (offset + 4 > packedBlob.length) {
        throw new Error(`Dữ liệu bị cắt ngắn tại chunk ${i}`);
      }
      const chunkLen = dv.getUint32(offset, false);
      offset += 4;
      const encryptedChunk = packedBlob.slice(offset, offset + chunkLen);
      offset += chunkLen;
      const plaintextChunk = await decryptChunk(
        aesKey,
        encryptedChunk,
        baseNonce,
        i
      );
      if (metadata.chunkChecksums && metadata.chunkChecksums.length > i) {
        const computed = await computeSHA256Hex(plaintextChunk);
        if (computed !== metadata.chunkChecksums[i]) {
          throw new Error(`Chunk ${i}: SHA-256 không khớp.`);
        }
      }
      plaintextChunks.push(plaintextChunk);
      onProgress?.(i + 1, storedChunkCount);
    }
  } else {
    let expectedTotal = 0;
    for (let i = 0; i < metadata.chunkCount; i++) {
      expectedTotal += encryptedChunkByteLength(metadata, i);
    }
    if (packedBlob.length !== expectedTotal) {
      throw new Error(
        `Kích thước blob (${packedBlob.length}) không khớp ${metadata.chunkCount} chunk (${expectedTotal}).`
      );
    }
    for (let i = 0; i < metadata.chunkCount; i++) {
      const chunkLen = encryptedChunkByteLength(metadata, i);
      const encryptedChunk = packedBlob.slice(offset, offset + chunkLen);
      offset += chunkLen;
      const plaintextChunk = await decryptChunk(
        aesKey,
        encryptedChunk,
        baseNonce,
        i
      );
      if (metadata.chunkChecksums && metadata.chunkChecksums.length > i) {
        const computed = await computeSHA256Hex(plaintextChunk);
        if (computed !== metadata.chunkChecksums[i]) {
          throw new Error(`Chunk ${i}: SHA-256 không khớp.`);
        }
      }
      plaintextChunks.push(plaintextChunk);
      onProgress?.(i + 1, metadata.chunkCount);
    }
  }

  // 4. Reassemble plaintext
  const totalSize = plaintextChunks.reduce((acc, c) => acc + c.length, 0);
  const result = new Uint8Array(totalSize);
  let pos = 0;
  for (const chunk of plaintextChunks) {
    result.set(chunk, pos);
    pos += chunk.length;
  }
  return result;
}

/** Xác thực manifest + dẫn xuất AES key cho giải mã chunked. */
export async function prepareChunkedDecryption(
  metadata: ChunkedEncryptionMetadata,
  recipientX25519PrivateKey: Uint8Array
): Promise<{ aesKey: CryptoKey; baseNonce: Uint8Array }> {
  const signerPublicKey = fromBase64(metadata.signerPublicKey);
  const signature = fromBase64(metadata.signature);
  const manifest = buildChunkedManifest({
    ephemeralPublicKey: metadata.ephemeralPublicKey,
    baseNonce: metadata.baseNonce,
    chunkCount: metadata.chunkCount,
    chunkSize: metadata.chunkSize,
    fileName: metadata.fileName,
    fileSize: metadata.fileSize,
    mimeType: metadata.mimeType,
    chunkChecksums: metadata.chunkChecksums,
  });

  if (!verifyManifest(manifest, signature, signerPublicKey)) {
    throw new Error("Chữ ký Ed25519 không hợp lệ — metadata bị giả mạo!");
  }

  const ephemeralPublicKey = fromBase64(metadata.ephemeralPublicKey);
  const sharedSecret = x25519.getSharedSecret(
    recipientX25519PrivateKey,
    ephemeralPublicKey
  );
  const aesKey = await deriveAesKeyOnly(sharedSecret, ephemeralPublicKey);
  const baseNonce = fromBase64(metadata.baseNonce);
  return { aesKey, baseNonce };
}

/**
 * Giải mã chunked từng phần — peak RAM ≈ 2 × chunkSize (không ghép toàn bộ file).
 * Ghi qua File System Access API; tự recover khi Chrome invalidate writable stream.
 */
export async function decryptChunkedToWritable(
  metadata: ChunkedEncryptionMetadata,
  recipientX25519PrivateKey: Uint8Array,
  getEncryptedChunk: (chunkIndex: number) => Promise<Uint8Array>,
  session: {
    handle: FileSystemFileHandle;
    writable: FileSystemWritableFileStream;
  },
  onProgress?: (done: number, total: number) => void
): Promise<number> {
  const { aesKey, baseNonce } = await prepareChunkedDecryption(
    metadata,
    recipientX25519PrivateKey
  );

  let totalWritten = 0;
  for (let i = 0; i < metadata.chunkCount; i++) {
    const encryptedChunk = await getEncryptedChunk(i);
    const plaintextChunk = await decryptChunk(aesKey, encryptedChunk, baseNonce, i);
    if (metadata.chunkChecksums && metadata.chunkChecksums.length > i) {
      const computed = await computeSHA256Hex(plaintextChunk);
      if (computed !== metadata.chunkChecksums[i]) {
        throw new Error(`Chunk ${i}: SHA-256 không khớp.`);
      }
    }

    // Copy sở hữu riêng trước khi ghi; bỏ ref ciphertext để GC kịp reclaim.
    const payload = plaintextChunk.slice();
    let wrote = false;
    for (let attempt = 0; attempt < 3 && !wrote; attempt++) {
      try {
        await writeChunk(session.writable, payload);
        wrote = true;
      } catch (err) {
        if (!isFileSystemInvalidStateError(err) || attempt === 2) {
          if (isFileSystemInvalidStateError(err)) {
            throw new Error(
              "Trình duyệt mất kết nối tới file đang lưu (file lớn / thiếu dung lượng đĩa). " +
                "Đóng DevTools nếu đang mở, kiểm tra dung lượng trống, rồi tải lại."
            );
          }
          throw err;
        }
        try {
          await session.writable.abort();
        } catch {
          /* ignore */
        }
        session.writable = await recreateWritableAt(session.handle, totalWritten);
      }
    }

    totalWritten += payload.byteLength;
    onProgress?.(i + 1, metadata.chunkCount);
    // Nhường event loop + giúp GC reclaim buffer chunk trước đó.
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }

  if (totalWritten !== metadata.fileSize) {
    throw new Error(
      `Kích thước plaintext (${totalWritten}) không khớp metadata (${metadata.fileSize}).`
    );
  }
  return totalWritten;
}

export function isChunkedMetadata(
  metadata: EncryptionMetadata
): metadata is ChunkedEncryptionMetadata {
  return Boolean((metadata as ChunkedEncryptionMetadata).isChunked);
}

export function shouldStreamDecrypt(metadata: EncryptionMetadata): boolean {
  if (!isChunkedMetadata(metadata)) return false;
  return metadata.fileSize >= STREAMING_DOWNLOAD_THRESHOLD;
}

// ─── Key Types ────────────────────────────────────────────────────────────────

export interface StoredKeyPair {
  x25519: { privateKey: string; publicKey: string };
  ed25519: { privateKey: string; publicKey: string };
}

export type UnlockedKeyPairs = {
  x25519: KeyPair;
  ed25519: KeyPair;
};

/** Format blob lưu trên server: PBKDF2 + AES-256-GCM bọc private key. */
export interface EncryptedKeyEnvelope {
  v: 1;
  kdf: "PBKDF2";
  hash: "SHA-256";
  iterations: number;
  salt: string;
  cipher: "AES-GCM";
  iv: string;
  ciphertext: string; // JSON(StoredKeyPair) đã mã hóa
}

const PBKDF2_ITERATIONS = 310_000;
const MIN_PASSPHRASE_LEN = 8;

export function validatePassphrase(passphrase: string): string | null {
  if (passphrase.length < MIN_PASSPHRASE_LEN) {
    return "PASSPHRASE_TOO_SHORT";
  }
  return null;
}

// ─── Passphrase KDF ───────────────────────────────────────────────────────────

async function _derivePassphraseKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number
): Promise<CryptoKey> {
  const km = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: toArrayBuffer(salt), iterations, hash: "SHA-256" },
    km,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// ─── Server-stored encrypted blob API ────────────────────────────────────────

/**
 * Mã hóa keypair bằng passphrase → trả về JSON string (EncryptedKeyEnvelope)
 * sẵn sàng upload lên server.
 * Server chỉ lưu blob này, không bao giờ thấy private key hay passphrase.
 */
export async function encryptKeyBlob(
  x25519Keys: KeyPair,
  ed25519Keys: KeyPair,
  passphrase: string
): Promise<string> {
  const err = validatePassphrase(passphrase);
  if (err) throw new Error(err);

  const payload: StoredKeyPair = {
    x25519: {
      privateKey: toBase64(x25519Keys.privateKey),
      publicKey: toBase64(x25519Keys.publicKey),
    },
    ed25519: {
      privateKey: toBase64(ed25519Keys.privateKey),
      publicKey: toBase64(ed25519Keys.publicKey),
    },
  };

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await _derivePassphraseKey(passphrase, salt, PBKDF2_ITERATIONS);
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(iv) },
    aesKey,
    plaintext
  );

  const envelope: EncryptedKeyEnvelope = {
    v: 1,
    kdf: "PBKDF2",
    hash: "SHA-256",
    iterations: PBKDF2_ITERATIONS,
    salt: toBase64(salt),
    cipher: "AES-GCM",
    iv: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(encrypted)),
  };
  return JSON.stringify(envelope);
}

/**
 * Giải mã blob (EncryptedKeyEnvelope JSON) bằng passphrase.
 * Dùng khi user đăng nhập và nhập passphrase để lấy private key.
 * Throws "WRONG_PASSPHRASE" | "INVALID_BLOB" khi thất bại.
 */
export async function decryptKeyBlob(
  blobJson: string,
  passphrase: string
): Promise<UnlockedKeyPairs> {
  let envelope: EncryptedKeyEnvelope;
  try {
    envelope = JSON.parse(blobJson) as EncryptedKeyEnvelope;
    if (envelope.v !== 1 || envelope.cipher !== "AES-GCM") {
      throw new Error("bad format");
    }
  } catch {
    throw new Error("INVALID_BLOB");
  }

  const salt = fromBase64(envelope.salt);
  const iv = fromBase64(envelope.iv);
  const aesKey = await _derivePassphraseKey(passphrase, salt, envelope.iterations);

  let decrypted: ArrayBuffer;
  try {
    decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv) },
      aesKey,
      toArrayBuffer(fromBase64(envelope.ciphertext))
    );
  } catch {
    throw new Error("WRONG_PASSPHRASE");
  }

  const payload = JSON.parse(new TextDecoder().decode(decrypted)) as StoredKeyPair;
  if (
    typeof payload.x25519?.privateKey !== "string" ||
    typeof payload.ed25519?.privateKey !== "string"
  ) {
    throw new Error("INVALID_BLOB");
  }

  return {
    x25519: {
      privateKey: fromBase64(payload.x25519.privateKey),
      publicKey: fromBase64(payload.x25519.publicKey),
    },
    ed25519: {
      privateKey: fromBase64(payload.ed25519.privateKey),
      publicKey: fromBase64(payload.ed25519.publicKey),
    },
  };
}

// ─── Legacy localStorage helpers (dùng cho migration) ────────────────────────

const _LEGACY_KEY = "secure_file_sharing_keys";

/** Detect legacy localStorage key để offer migration. */
export function hasLegacyLocalStorageKey(): boolean {
  try { return localStorage.getItem(_LEGACY_KEY) !== null; } catch { return false; }
}

/** Đọc legacy blob từ localStorage để migrate. Returns null nếu không có. */
export function getLegacyLocalStorageBlob(): string | null {
  try { return localStorage.getItem(_LEGACY_KEY); } catch { return null; }
}

/** Xóa legacy key khỏi localStorage sau khi đã migrate xong. */
export function clearLegacyLocalStorage(): void {
  try { localStorage.removeItem(_LEGACY_KEY); } catch { /* ignore */ }
}

/**
 * Đọc và giải mã legacy localStorage key (PBKDF2+AES-GCM format cũ).
 * Dùng cho migration path: đọc key cũ → upload lên server → xóa localStorage.
 * Throws "NO_LEGACY" | "WRONG_PASSPHRASE" | "INVALID_STORAGE"
 */
export async function decryptLegacyLocalStorage(
  passphrase: string
): Promise<UnlockedKeyPairs> {
  const raw = localStorage.getItem(_LEGACY_KEY);
  if (!raw) throw new Error("NO_LEGACY");

  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error("INVALID_STORAGE"); }

  const env = parsed as EncryptedKeyEnvelope;
  if (env?.v === 1 && env?.cipher === "AES-GCM") {
    return decryptKeyBlob(raw, passphrase);
  }

  // Legacy plaintext format (không mã hóa) — direct migration
  const plain = parsed as StoredKeyPair;
  if (typeof plain?.x25519?.privateKey === "string") {
    return {
      x25519: {
        privateKey: fromBase64(plain.x25519.privateKey),
        publicKey: fromBase64(plain.x25519.publicKey),
      },
      ed25519: {
        privateKey: fromBase64(plain.ed25519.privateKey),
        publicKey: fromBase64(plain.ed25519.publicKey),
      },
    };
  }

  throw new Error("INVALID_STORAGE");
}

// ─── Checksum ─────────────────────────────────────────────────────────────────

/**
 * Tính SHA-256 của dữ liệu và trả về chuỗi hex.
 * Dùng để tạo fingerprint plaintext trước khi mã hóa và verify sau khi giải mã.
 */
export async function computeSHA256Hex(data: ArrayBuffer | Uint8Array): Promise<string> {
  const buffer = data instanceof Uint8Array
    ? data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer
    : data;
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ─── Utilities ────────────────────────────────────────────────────────────────

export function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

export function fromBase64(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function downloadBlob(data: Uint8Array, fileName: string, mimeType: string): void {
  const blob = new Blob([new Uint8Array(data)], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  a.click();
  URL.revokeObjectURL(url);
}
