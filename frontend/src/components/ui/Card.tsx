import { surfaceCard } from "../../styles/theme";

interface CardProps {
  children: React.ReactNode;
  className?: string;
  padding?: "none" | "sm" | "md";
}

const pad = { none: "", sm: "p-4", md: "p-5" };

export default function Card({ children, className = "", padding = "md" }: CardProps) {
  return (
    <div className={`w-full ${surfaceCard} ${pad[padding]} ${className}`.trim()}>
      {children}
    </div>
  );
}
