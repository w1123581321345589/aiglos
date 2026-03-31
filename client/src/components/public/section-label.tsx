export default function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="font-pub-mono text-[10px] tracking-[0.25em] uppercase text-pub-ice mb-4">
      {children}
    </div>
  );
}
