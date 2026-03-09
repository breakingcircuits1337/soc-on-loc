import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "@/lib/router";
import { cn } from "@/lib/utils";

export type MetricCardVariant = "default" | "critical" | "high" | "cyber" | "intel" | "success";

interface MetricCardProps {
  icon: LucideIcon;
  value: string | number;
  label: string;
  description?: ReactNode;
  to?: string;
  onClick?: () => void;
  variant?: MetricCardVariant;
}

const variantStyles: Record<MetricCardVariant, {
  card: string;
  value: string;
  icon: string;
  glow: string;
}> = {
  default: {
    card: "border-border hover:border-border/80",
    value: "text-foreground",
    icon: "text-muted-foreground/50",
    glow: "",
  },
  critical: {
    card: "border-red-500/30 dark:border-red-500/25",
    value: "text-red-500 dark:text-red-400",
    icon: "text-red-500/60 dark:text-red-400/60",
    glow: "dark:card-glow-critical",
  },
  high: {
    card: "border-orange-500/30 dark:border-orange-500/25",
    value: "text-orange-500 dark:text-orange-400",
    icon: "text-orange-500/60 dark:text-orange-400/60",
    glow: "dark:card-glow-high",
  },
  cyber: {
    card: "border-cyan-500/30 dark:border-cyan-500/25",
    value: "text-cyan-600 dark:text-cyan-400",
    icon: "text-cyan-500/60 dark:text-cyan-400/60",
    glow: "dark:card-glow-cyber",
  },
  intel: {
    card: "border-purple-500/30 dark:border-purple-500/25",
    value: "text-purple-600 dark:text-purple-400",
    icon: "text-purple-500/60 dark:text-purple-400/60",
    glow: "dark:card-glow-intel",
  },
  success: {
    card: "border-emerald-500/30 dark:border-emerald-500/25",
    value: "text-emerald-600 dark:text-emerald-400",
    icon: "text-emerald-500/60 dark:text-emerald-400/60",
    glow: "dark:card-glow-success",
  },
};

export function MetricCard({ icon: Icon, value, label, description, to, onClick, variant = "default" }: MetricCardProps) {
  const isClickable = !!(to || onClick);
  const styles = variantStyles[variant];

  const inner = (
    <div className={cn(
      "h-full px-4 py-4 sm:px-5 sm:py-5 border rounded-lg transition-all duration-200",
      styles.card,
      styles.glow,
      isClickable && "hover:bg-accent/40 cursor-pointer",
      "dark:bg-card/60 dark:backdrop-blur-sm",
    )}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <p className={cn(
            "text-2xl sm:text-3xl font-mono font-bold tracking-tight tabular-nums value-pop",
            styles.value,
          )}>
            {value}
          </p>
          <p className="text-[10px] sm:text-xs font-semibold text-muted-foreground mt-1.5 uppercase tracking-widest">
            {label}
          </p>
          {description && (
            <div className="text-[10px] text-muted-foreground/60 mt-1.5 hidden sm:block font-mono">
              {description}
            </div>
          )}
        </div>
        <Icon className={cn("h-4 w-4 shrink-0 mt-1.5", styles.icon)} />
      </div>
    </div>
  );

  if (to) {
    return (
      <Link to={to} className="no-underline text-inherit h-full" onClick={onClick}>
        {inner}
      </Link>
    );
  }

  if (onClick) {
    return (
      <div className="h-full" onClick={onClick}>
        {inner}
      </div>
    );
  }

  return inner;
}
