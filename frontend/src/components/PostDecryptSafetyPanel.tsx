import { useState } from "react";
import Button from "./ui/Button";
import Alert from "./ui/Alert";
import VirusTotalCheck from "./VirusTotalCheck";
import { useT } from "../i18n/context";
import { isHighRiskFilename } from "../utils/fileRisk";
import type { VirusTotalHashResult } from "../utils/api";

interface Props {
  fileName: string;
  sha256: string;
  pendingSave: boolean;
  wroteToDiskDuringDecrypt: boolean;
  onSave: () => void;
  onDiscard: () => void;
}

/**
 * P0–P2 post-decrypt safety gate: hash-only VT, no auto-open, block save on malicious.
 */
export default function PostDecryptSafetyPanel({
  fileName,
  sha256,
  pendingSave,
  wroteToDiskDuringDecrypt,
  onSave,
  onDiscard,
}: Props) {
  const t = useT();
  const [vt, setVt] = useState<VirusTotalHashResult | null>(null);
  const highRisk = isHighRiskFilename(fileName);
  const malicious = vt?.reputation === "malicious";
  const suspicious = vt?.reputation === "suspicious";

  function handleSave() {
    if (malicious) {
      alert(t("virusTotal.blockSaveMalicious"));
      return;
    }
    if (suspicious && !confirm(t("virusTotal.confirmSaveSuspicious"))) return;
    if (highRisk && !vt && !confirm(t("virusTotal.confirmSaveHighRiskNoScan"))) return;
    if (highRisk && vt?.reputation === "unknown" && !confirm(t("virusTotal.confirmSaveUnknown"))) {
      return;
    }
    onSave();
  }

  return (
    <div className="space-y-3">
      <Alert tone="warning">
        <p className="font-medium text-sm">{t("virusTotal.safetyTitle")}</p>
        <ul className="mt-1.5 text-xs space-y-1 list-disc pl-4 opacity-95">
          <li>{t("virusTotal.safetyHashOnly")}</li>
          <li>{t("virusTotal.safetyNotAv")}</li>
          <li>{t("virusTotal.safetyDontOpen")}</li>
          {wroteToDiskDuringDecrypt ? (
            <li>{t("virusTotal.safetyStreamedToDisk")}</li>
          ) : (
            <li>{t("virusTotal.safetyHeldInRam")}</li>
          )}
          {highRisk && <li>{t("virusTotal.safetyHighRiskExt")}</li>}
        </ul>
      </Alert>

      {pendingSave && (
        <Alert tone="info">
          <p className="text-sm">{t("virusTotal.pendingSaveHint")}</p>
        </Alert>
      )}

      {wroteToDiskDuringDecrypt && (
        <Alert tone="warning">
          <p className="text-sm">{t("virusTotal.streamedAvHint")}</p>
        </Alert>
      )}

      <VirusTotalCheck sha256={sha256} onResult={setVt} autoPrompt />

      {malicious && (
        <Alert tone="error">
          <p className="text-sm font-medium">{t("virusTotal.maliciousAction")}</p>
        </Alert>
      )}

      <div className="flex flex-wrap gap-2">
        {pendingSave && (
          <>
            <Button
              onClick={handleSave}
              disabled={malicious}
              title={malicious ? t("virusTotal.blockSaveMalicious") : undefined}
            >
              {t("virusTotal.saveFile")}
            </Button>
            <Button variant="secondary" onClick={onDiscard}>
              {t("virusTotal.discardPlaintext")}
            </Button>
          </>
        )}
        {wroteToDiskDuringDecrypt && !pendingSave && (
          <p className="text-xs text-slate-500 dark:text-slate-400">
            {t("virusTotal.p2SandboxNote")}
          </p>
        )}
      </div>
    </div>
  );
}
