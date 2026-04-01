export default function CodeWindow({
  filename,
  children,
  className = "max-w-[680px]",
}: {
  filename?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`bg-[var(--pub-code-bg)] border border-pub-strong rounded-lg overflow-hidden mb-5 ${className}`}
    >
      {filename && (
        <div className="bg-[var(--pub-code-bar)] px-4 py-2.5 border-b border-pub flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-[#ff5f57]" />
          <span className="w-2.5 h-2.5 rounded-full bg-[#febc2e]" />
          <span className="w-2.5 h-2.5 rounded-full bg-[#28c840]" />
          <span className="font-pub-mono text-[11px] text-pub-dim ml-2">{filename}</span>
        </div>
      )}
      <div className="p-6 overflow-x-auto">
        <pre className="font-pub-mono text-[13.5px] leading-[1.75] text-[#e6edf3] m-0">
          {children}
        </pre>
      </div>
    </div>
  );
}
