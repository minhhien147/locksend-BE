/** Lưu file lớn trực tiếp ra đĩa qua File System Access API (Chrome/Edge). */

type SaveFilePickerWindow = Window & {
  showSaveFilePicker?: (options: {
    suggestedName: string;
  }) => Promise<FileSystemFileHandle>;
};

export type SaveFileSession = {
  handle: FileSystemFileHandle;
  writable: FileSystemWritableFileStream;
};

export function supportsStreamingFileSave(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof (window as SaveFilePickerWindow).showSaveFilePicker === "function"
  );
}

export async function pickSaveFile(
  suggestedName: string
): Promise<SaveFileSession> {
  const picker = (window as SaveFilePickerWindow).showSaveFilePicker;
  if (!picker) {
    throw new Error(
      "Trình duyệt không hỗ trợ lưu file lớn trực tiếp. Dùng Chrome hoặc Edge."
    );
  }
  const handle = await picker({ suggestedName });
  const writable = await handle.createWritable();
  return { handle, writable };
}

/** Copy dữ liệu trước khi ghi — tránh InvalidStateError do buffer bị detach/GC. */
export async function writeChunk(
  writable: FileSystemWritableFileStream,
  data: Uint8Array
): Promise<void> {
  const copy = data.byteLength ? data.slice() : new Uint8Array(0);
  await writable.write(copy);
}

/**
 * Chrome đôi khi invalidate FileSystemWritableFileStream khi ghi rất lớn
 * ("state cached … changed since it was read from disk"). Mở lại stream
 * giữ dữ liệu đã ghi, seek tới offset, rồi ghi tiếp.
 */
export async function recreateWritableAt(
  handle: FileSystemFileHandle,
  offset: number
): Promise<FileSystemWritableFileStream> {
  const writable = await handle.createWritable({ keepExistingData: true });
  if (offset > 0) {
    await writable.seek(offset);
  }
  return writable;
}

export function isFileSystemInvalidStateError(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const e = err as { name?: string; message?: string };
  if (e.name === "InvalidStateError") return true;
  const msg = String(e.message ?? "");
  return (
    msg.includes("state cached in an interface object") ||
    msg.includes("state had changed since it was read from disk")
  );
}

export async function closeSaveFile(
  writable: FileSystemWritableFileStream
): Promise<void> {
  await writable.close();
}
