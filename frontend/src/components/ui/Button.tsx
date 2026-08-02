import { btn } from "../../styles/theme";
import { LoadingSpinner } from "../LoadingSpinner";

type Variant = "primary" | "secondary" | "danger" | "ghost";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  loading?: boolean;
  fullWidth?: boolean;
}

const variants: Record<Variant, string> = {
  primary: btn.primary,
  secondary: btn.secondary,
  danger: btn.danger,
  ghost: btn.ghost,
};

export default function Button({
  variant = "primary",
  loading,
  fullWidth,
  children,
  className = "",
  disabled,
  ...rest
}: ButtonProps) {
  return (
    <button
      type="button"
      disabled={disabled || loading}
      className={`${variants[variant]} ${fullWidth ? "w-full min-w-0" : ""} ${className}`.trim()}
      {...rest}
    >
      {loading ? <LoadingSpinner size="sm" /> : null}
      {children}
    </button>
  );
}
