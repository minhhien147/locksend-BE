import { useEffect, useState } from "react";
import { useDownload } from "../hooks/useDownload";
import { useClearPageDraft, useDraftState } from "../hooks/useDraftState";
import { migrateLegacyScalar } from "../utils/pageDraft";

const PAGE_KEY = "download";
import { LoadingSpinner } from "../components/LoadingSpinner";
import KeyUnlockBanner from "../components/KeyUnlockBanner";
import PageHeader from "../components/ui/PageHeader";
import Card from "../components/ui/Card";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import VirusTotalCheck from "../components/VirusTotalCheck";
import TransferProgressPanel from "../components/TransferProgressPanel";
import { useT } from "../i18n/context";
import { inputBase, label } from "../styles/theme";

export default function DownloadPage() {
  const t = useT();
  const clearDownloadDraft = useClearPageDraft(PAGE_KEY);
  const [sasUrl, setSasUrl] = useDraftState(PAGE_KEY, "sasUrl", "");

  useEffect(() => {
    const legacy = migrateLegacyScalar("sfs_download_sas_draft", PAGE_KEY, "sasUrl");
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
    downloadAndDecrypt,
    cancel,
    reset,
  } = useDownload();

  const isBusy = stage === "downloading" || stage === "decrypting";

  return (
    <div className="max-w-2xl mx-auto space-y-5">
      <PageHeader title={t("download.title")} />

      <KeyUnlockBanner onUnlocked={() => setUnlockTick((n) => n + 1)} />

      <Card className="space-y-4">
        <div>
          <label className={label}>
            {t("download.sasLabel")} <span className="text-rose-600 dark:text-rose-400">*</span>
          </label>
          <textarea
            value={sasUrl}
            onChange={(e) => setSasUrl(e.target.value)}
            placeholder={t("download.sasPlaceholder")}
            rows={4}
            disabled={isBusy}
            className={`w-full mt-1.5 font-mono text-sm resize-none ${inputBase}`}
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
            <VirusTotalCheck sha256={plaintextChecksum} />
          </>
        )}

        <div className="flex gap-3 pt-1">
          <Button
            fullWidth
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
            <Button variant="secondary" onClick={cancel}>
              {t("common.cancel")}
            </Button>
          )}
          {stage === "done" && (
            <Button
              variant="secondary"
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
