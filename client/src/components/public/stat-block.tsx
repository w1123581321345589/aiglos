export default function StatBlock({
  value,
  label,
  className = "",
}: {
  value: string;
  label: string;
  className?: string;
}) {
  return (
    <div className={`text-center ${className}`}>
      <div className="font-pub-mono text-[clamp(28px,4vw,48px)] font-bold text-white leading-none mb-2">
        {value}
      </div>
      <div className="text-xs text-pub-dim tracking-[0.1em] uppercase">{label}</div>
    </div>
  );
}
