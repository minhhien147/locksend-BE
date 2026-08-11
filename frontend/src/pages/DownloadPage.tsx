import { useEffect, useState } from "react";
import { useDownload } from "../hooks/useDownload";
import { useClearPageDraft, useDraftState } from "../hooks/useDraftState";
import { purgeStorageField, takeLegacyScalar } from "../utils/pageDraft";

const PAGE_KEY = "download";
import { LoadingSpinner } from "../components/LoadingSpinner";
import KeyUnlockBanner from "../components/KeyUnlockBanner";
import PageHeader from "../components/ui/PageHeader";
import Card from "../components/ui/Card";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import PostDecryptSafetyPanel from "../components/PostDecryptSafetyPanel";
import TransferProgressPanel from "../components/TransferProgressPanel";
import { useT } from "../i18n/context";
import { label, textareaBase } from "../styles/theme";

export default function DownloadPage() {
  const t = useT();
  const clearDownloadDraft = useClearPageDraft(PAGE_KEY);
  // A02: SAS URL là bearer credential của blob — giữ trong RAM, không ghi vào
  // sessionStorage (mọi script cùng origin đọc được cho tới khi đóng tab).
  const [sasUrl, setSasUrl] = useDraftState(PAGE_KEY, "sasUrl", "", "memory");

  useEffect(() => {
    // Dọn SAS mà bản cũ đã persist, và không ghi lại xuống sessionStorage.
    purgeStorageField(PAGE_KEY, "sasUrl");
    const legacy = takeLegacyScalar("sfs_download_sas_draft");
    if (legacy) setSasUrl(legacy);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- migration once on mount
  }, []);
  const [, setUnlockTick] = useState(0);
  const {
    stage,
    error,
    fileName,
    chunkProgress,
    isChunkedFile,
    plaintextChecksum,
    transferStats,
    pendingSave,
    wroteToDiskDuringDecrypt,
    downloadAndDecrypt,
    savePendingFile,
    discardPendingFile,
    cancel,
    reset,
  } = useDownload();

  const isBusy = stage === "downloading" || stage === "decrypting";

  return (
    <div className="w-full max-w-2xl mx-auto space-y-5">
      <PageHeader title={t("download.title")} />

      <KeyUnlockBanner onUnlocked={() => setUnlockTick((n) => n + 1)} />

      <Card className="space-y-4">
        <div className="w-full">
          <label className={label}>
            {t("download.sasLabel")} <span className="text-rose-600 dark:text-rose-400">*</span>
          </label>
          <textarea
            value={sasUrl}
            onChange={(e) => setSasUrl(e.target.value)}
            placeholder={t("download.sasPlaceholder")}
            rows={4}
            disabled={isBusy}
            className={`mt-1.5 font-mono ${textareaBase}`}
          />
        </div>

        {error && <Alert tone="error">{error}</Alert>}

        {isBusy && transferStats && (
          <TransferProgressPanel
            stats={transferStats}
            label={
              stage === "downloading"
                ? t("download.downloading")
                : chunkProgress
                  ? t("download.decryptChunk", {
                      done: chunkProgress.done,
                      total: chunkProgress.total,
                    })
                  : t("download.decrypting")
            }
            showSpeed={stage === "downloading" || isChunkedFile}
            showBar
            barClassName={
              stage === "downloading"
                ? "bg-blue-700 dark:bg-blue-600"
                : "bg-amber-500"
            }
          />
        )}

        {stage === "decrypting" && !isChunkedFile && !transferStats && (
          <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400">
            <LoadingSpinner size="sm" />
            {t("download.decrypting")}
          </div>
        )}

        {stage === "downloading" && !transferStats && (
          <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400">
            <LoadingSpinner size="sm" />
            {t("download.downloading")}
          </div>
        )}

        {stage === "done" && (
          <>
            <Alert tone="success">{fileName || t("download.success")}</Alert>
            <PostDecryptSafetyPanel
              fileName={fileName}
              sha256={plaintextChecksum}
              pendingSave={pendingSave}
              wroteToDiskDuringDecrypt={wroteToDiskDuringDecrypt}
              onSave={() => {
                savePendingFile();
              }}
              onDiscard={() => {
                discardPendingFile();
              }}
            />
          </>
        )}

        <div className="flex w-full gap-3 pt-1">
          <Button
            fullWidth
            className="flex-1"
            loading={isBusy}
            disabled={isBusy || !sasUrl.trim()}
            onClick={() => void downloadAndDecrypt(sasUrl).catch(() => {})}
          >
            {stage === "downloading"
              ? t("download.downloading")
              : stage === "decrypting"
                ? t("download.decrypting")
                : t("download.downloadDecrypt")}
          </Button>
          {isBusy && (
            <Button variant="secondary" className="shrink-0" onClick={cancel}>
              {t("common.cancel")}
            </Button>
          )}
          {stage === "done" && (
            <Button
              variant="secondary"
              className="shrink-0"
              onClick={() => {
                clearDownloadDraft();
                reset();
              }}
            >
              {t("common.new")}
            </Button>
          )}
        </div>
      </Card>
    </div>
  );
}
