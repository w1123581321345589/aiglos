export interface FeatureItem {
  title: string;
  desc: string;
  mono?: string;
}

export default function FeatureGrid({
  items,
  columns = 3,
}: {
  items: FeatureItem[];
  columns?: 2 | 3 | 4;
}) {
  const colClass =
    columns === 2
      ? "grid-cols-2 pub-grid-2"
      : columns === 4
      ? "grid-cols-4 pub-grid-4"
      : "grid-cols-3 pub-grid-3";

  return (
    <div className={`grid ${colClass} gap-px bg-white/[0.06] rounded-lg overflow-hidden`}>
      {items.map((item) => (
        <div key={item.title} className="bg-pub-card p-7">
          {item.mono && (
            <div className="font-pub-mono text-[10px] tracking-[0.2em] uppercase text-pub-dim mb-3">
              {item.mono}
            </div>
          )}
          <div className="text-sm font-semibold mb-2 text-white">{item.title}</div>
          <div className="text-[13px] text-white/50 leading-[1.6]">{item.desc}</div>
        </div>
      ))}
    </div>
  );
}
