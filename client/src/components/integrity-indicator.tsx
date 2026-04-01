import { cn } from "@/lib/utils";

export function IntegrityIndicator({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color = pct < 50 ? "text-red-500" : pct < 75 ? "text-amber-500" : "text-emerald-500";
  const bg = pct < 50 ? "bg-red-500" : pct < 75 ? "bg-amber-500" : "bg-emerald-500";

  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
        <div
          className={cn("h-full rounded-full", bg)}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className={cn("text-xs font-mono font-medium", color)}>
        {pct}%
      </span>
    </div>
  );
}
