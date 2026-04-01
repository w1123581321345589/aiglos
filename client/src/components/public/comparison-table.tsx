export interface ComparisonColumn {
  key: string;
  label: string;
  highlight?: boolean;
}

export interface ComparisonRow {
  label: string;
  values: Record<string, string>;
}

export default function ComparisonTable({
  columns,
  rows,
  "data-testid": testId,
}: {
  columns: ComparisonColumn[];
  rows: ComparisonRow[];
  "data-testid"?: string;
}) {
  return (
    <div data-testid={testId} className="w-full overflow-x-auto">
      <table className="w-full border-collapse text-[13px]">
        <thead>
          <tr>
            <th className="font-pub-mono text-[10px] tracking-[0.15em] uppercase text-pub-dim py-3 px-4 text-left border-b-2 border-white/10">
              Capability
            </th>
            {columns.map((col) => (
              <th
                key={col.key}
                className="font-pub-mono text-[10px] tracking-[0.15em] uppercase text-pub-dim py-3 px-4 text-left border-b-2 border-white/10"
              >
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.label}>
              <td className="py-3.5 px-4 border-b border-white/[0.06] font-medium text-white align-top min-w-[160px]">
                {row.label}
              </td>
              {columns.map((col) => (
                <td
                  key={col.key}
                  className={`py-3.5 px-4 border-b border-white/[0.06] align-top min-w-[160px] ${
                    col.highlight ? "bg-pub-blue/[0.04] text-white" : "text-white/60"
                  }`}
                >
                  {row.values[col.key] || ""}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
