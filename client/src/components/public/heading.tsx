export default function Heading({
  children,
  as: Tag = "h2",
  className = "",
  "data-testid": testId,
}: {
  children: React.ReactNode;
  as?: "h1" | "h2" | "h3";
  className?: string;
  "data-testid"?: string;
}) {
  const sizeClass =
    Tag === "h1"
      ? "text-[clamp(28px,4vw,48px)]"
      : Tag === "h3"
      ? "text-[clamp(20px,2.5vw,28px)]"
      : "text-[clamp(24px,3vw,36px)]";

  return (
    <Tag
      data-testid={testId}
      className={`font-bold tracking-tight leading-[1.1] ${sizeClass} ${className}`}
    >
      {children}
    </Tag>
  );
}
