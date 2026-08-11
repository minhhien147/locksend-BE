import { useEffect, useState } from "react";
import Button from "./ui/Button";
import Alert from "./ui/Alert";
import { LoadingSpinner } from "./LoadingSpinner";
import {
  apiErrorDetail,
  checkHashVirusTotal,
  getIntegrationsStatus,
  type VirusTotalHashResult,
} from "../utils/api";
import { useT } from "../i18n/context";
import { text } from "../styles/theme";

interface Props {
  sha256: string;
  onResult?: (result: VirusTotalHashResult | null) => void;
  /** Show expanded privacy / residual-risk copy (P0). */
  autoPrompt?: boolean;
}

/**
 * A03: React không sanitize thuộc tính href. Nếu backend (hoặc integration bị
 * cấu hình sai) trả về `javascript:...` hay một domain phishing thì click sẽ
 * thực thi script / dẫn user ra ngoài. Chỉ chấp nhận HTTPS trên host VirusTotal.
 */
const VT_ALLOWED_HOSTS = new Set(["virustotal.com", "www.virustotal.com"]);

function safeVirusTotalUrl(raw: string | null | undefined): string | null {
  if (!raw) return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== "https:") return null;
    if (!VT_ALLOWED_HOSTS.has(url.hostname.toLowerCase())) return null;
    return url.toString();
  } catch {
    return null;
  }
}

export default function VirusTotalCheck({ sha256, onResult, autoPrompt }: Props) {
  const t = useT();
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VirusTotalHashResult | null>(null);
  const [error, setError] = useState("");
  const [privacyAck, setPrivacyAck] = useState(false);

  useEffect(() => {
    void getIntegrationsStatus()
      .then((s) => setEnabled(s.virustotal))
      .catch(() => setEnabled(false));
  }, []);

  if (!sha256) {
    return (
      <div className="space-y-1 pt-2 border-t border-slate-200 dark:border-white/10">
        <p className={`text-xs ${text.muted}`}>{t("virusTotal.noHash")}</p>
      </div>
    );
  }

  if (enabled === null) {
    return (
      <div className={`flex items-center gap-2 text-xs pt-2 ${text.muted}`}>
        <LoadingSpinner size="sm" />
        {t("virusTotal.checking")}
      </div>
    );
  }

  if (enabled === false) {
    return (
      <Alert tone="warning">{t("virusTotal.disabled")}</Alert>
    );
  }

  async function handleCheck() {
    if (autoPrompt && !privacyAck) {
      if (!confirm(t("virusTotal.privacyConfirm"))) return;
      setPrivacyAck(true);
    }
    setLoading(true);
    setError("");
    setResult(null);
    onResult?.(null);
    try {
      const res = await checkHashVirusTotal(sha256);
      setResult(res);
      onResult?.(res);
    } catch (e) {
      setError(apiErrorDetail(e, t("virusTotal.failed")));
    } finally {
      setLoading(false);
    }
  }

  const tone =
    result?.reputation === "malicious"
      ? "error"
      : result?.reputation === "suspicious"
        ? "warning"
        : result?.reputation === "clean"
          ? "success"
          : "info";

  const reputationLabel =
    result?.reputation === "clean"
      ? t("virusTotal.clean")
      : result?.reputation === "suspicious"
        ? t("virusTotal.suspicious")
        : result?.reputation === "malicious"
          ? t("virusTotal.malicious")
          : result?.reputation === "unknown"
            ? t("virusTotal.unknown")
            : "";

  const safePermalink = safeVirusTotalUrl(result?.permalink);

  return (
    <div className="space-y-2 pt-2 border-t border-slate-200 dark:border-white/10">
      <p className={`text-[11px] leading-relaxed ${text.muted}`}>
        {t("virusTotal.hashOnlyNote")}. {t("virusTotal.privacyHint")}
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="secondary" loading={loading} onClick={() => void handleCheck()}>
          {t("virusTotal.scan")}
        </Button>
      </div>

      {error && <Alert tone="error">{error}</Alert>}

      {result && (
        <Alert tone={tone}>
          <p className="font-medium">{reputationLabel}</p>
          {result.known && (
            <p className="text-xs mt-1 opacity-90">
              {t("virusTotal.engines", {
                malicious: result.malicious,
                total: result.total_engines,
              })}
            </p>
          )}
          {!result.known && result.message && (
            <p className="text-xs mt-1 opacity-90">{result.message}</p>
          )}
          {safePermalink && (
            <a
              href={safePermalink}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs underline mt-1 inline-block"
            >
              {t("virusTotal.viewReport")}
            </a>
          )}
        </Alert>
      )}

      {loading && (
        <div className={`flex items-center gap-2 text-xs ${text.muted}`}>
          <LoadingSpinner size="sm" />
          {t("virusTotal.scanning")}
        </div>
      )}
    </div>
  );
}
