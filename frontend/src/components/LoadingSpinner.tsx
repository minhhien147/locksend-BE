/** Spinner thống nhất — một màu, không gradient. */

type SpinnerSize = "xs" | "sm" | "md" | "lg";

const SPINNER_BOX: Record<SpinnerSize, string> = {
  xs: "h-3.5 w-3.5",
  sm: "h-4 w-4",
  md: "h-10 w-10",
  lg: "h-14 w-14",
};

const SPINNER_RING: Record<SpinnerSize, string> = {
  xs: "border-[1.5px]",
  sm: "border-2",
  md: "border-[3px]",
  lg: "border-[3px]",
};

type LoadingSpinnerProps = {
  size?: SpinnerSize;
  className?: string;
  /** Khi false, không set aria-hidden (để bọc trong role="status" có nhãn riêng) */
  decorative?: boolean;
};

export function LoadingSpinner({ size = "md", className = "", decorative = true }: LoadingSpinnerProps) {
  return (
    <div
      className={`relative inline-flex shrink-0 ${SPINNER_BOX[size]} ${className}`}
      {...(decorative ? { "aria-hidden": true as const } : {})}
    >
      <div
        className={`absolute inset-0 rounded-full ${SPINNER_RING[size]} border-slate-300/70 dark:border-slate-700/90`}
      />
      <div
        className={`absolute inset-0 animate-spin rounded-full ${SPINNER_RING[size]} border-transparent border-t-indigo-500 border-r-cyan-400 motion-reduce:animate-none will-change-transform`}
        style={{ animationDuration: "0.75s" }}
      />
    </div>
  );
}

type PageLoaderProps = {
  /** Tiêu đề chính */
  title: string;
  /** Dòng phụ (tuỳ chọn) */
  description?: string;
  /** fullscreen: bootstrap phiên; embedded: trong card / tab */
  variant?: "fullscreen" | "embedded";
  className?: string;
};

export default function PageLoader({
  title,
  description,
  variant = "embedded",
  className = "",
}: PageLoaderProps) {
  const shell =
    variant === "fullscreen"
      ? "min-h-screen flex flex-col items-center justify-center gap-6 bg-[#e8eaef] dark:bg-[#0b0d12] px-6"
      : "flex flex-col items-center justify-center gap-4 py-16 sm:py-20";

  return (
    <div
      className={`${shell} ${className}`}
      role="status"
      aria-live="polite"
      aria-busy="true"
    >
      <span className="sr-only">{title}</span>
      <div className="relative flex items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
      <div className="max-w-sm text-center space-y-1.5">
        <p className="text-sm font-medium tracking-tight text-slate-800 dark:text-slate-200">{title}</p>
        {description ? (
          <p className="text-xs leading-relaxed text-slate-500 dark:text-slate-400">{description}</p>
        ) : null}
      </div>
    </div>
  );
}
