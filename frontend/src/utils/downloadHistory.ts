/**
 * downloadHistory.ts
 * Lưu lịch sử tải file vào localStorage (download xảy ra hoàn toàn client-side,
 * backend không biết → chỉ có thể lưu tại trình duyệt).
 *
 * A02: KHÔNG lưu SAS URL. SAS là bearer credential đọc được blob trên Azure cho
 * tới khi hết hạn; giữ 200 URL trong localStorage biến mọi XSS hay extension độc
 * hại thành rò rỉ nội dung file. Muốn tải lại thì xin SAS mới qua
 * GET /files/{id}/sas.
 */

const STORAGE_KEY = "sfs_download_history";
const MAX_ENTRIES = 200;

export interface DownloadHistoryItem {
  id: string;
  fileName: string;
  mimeType: string | undefined;
  fileSizeBytes: number | undefined;
  checksum: string | undefined;   // SHA-256 plaintext
  isChunked: boolean;
  downloadedAt: string;           // ISO 8601
  /** Khớp files.id trên server (nếu blob có metadata file_id) */
  serverFileId?: string;
}

function persist(items: DownloadHistoryItem[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
  } catch {
    // localStorage đầy hoặc private mode — bỏ qua lỗi
  }
}

export function getDownloadHistory(): DownloadHistoryItem[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as (DownloadHistoryItem & { sasUrl?: string })[];

    // A02: dữ liệu do bản cũ ghi vẫn còn SAS URL trên đĩa — loại bỏ và ghi lại
    // ngay lần đọc đầu tiên để secret không tồn tại lâu hơn cần thiết.
    const hadSas = parsed.some((e) => e && typeof e.sasUrl === "string");
    const cleaned = parsed.map(({ sasUrl: _sasUrl, ...rest }) => rest as DownloadHistoryItem);
    if (hadSas) persist(cleaned);
    return cleaned;
  } catch {
    return [];
  }
}

export function saveDownloadEntry(entry: Omit<DownloadHistoryItem, "id" | "downloadedAt">): void {
  const history = getDownloadHistory();
  const newEntry: DownloadHistoryItem = {
    ...entry,
    id: crypto.randomUUID(),
    downloadedAt: new Date().toISOString(),
  };
  persist([newEntry, ...history].slice(0, MAX_ENTRIES));
}

export function deleteDownloadEntry(id: string): void {
  persist(getDownloadHistory().filter((e) => e.id !== id));
}

export function clearDownloadHistory(): void {
  localStorage.removeItem(STORAGE_KEY);
}
