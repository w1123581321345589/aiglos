export default function RuleTag({ rule }: { rule: string }) {
  return (
    <span className="bg-pub-card border border-white/[0.08] text-pub-dim py-px px-[7px] rounded-sm text-[9px] tracking-[0.1em] font-pub-mono">
      {rule}
    </span>
  );
}
