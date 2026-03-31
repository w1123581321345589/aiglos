import SectionLabel from "./section-label";

export default function PubSection({
  label,
  title,
  description,
  children,
  id,
  border = true,
}: {
  label?: string;
  title?: string;
  description?: string;
  children: React.ReactNode;
  id?: string;
  border?: boolean;
}) {
  return (
    <section
      id={id}
      className={`py-20 px-12 max-w-[1100px] mx-auto ${border ? "border-t border-pub" : ""}`}
    >
      {label && <SectionLabel>{label}</SectionLabel>}
      {title && (
        <h2 className="text-[clamp(28px,4vw,44px)] font-bold tracking-tight leading-[1.1] mb-4">
          {title}
        </h2>
      )}
      {description && (
        <p className="text-base text-pub-muted leading-[1.7] max-w-[560px] mb-12">
          {description}
        </p>
      )}
      {children}
    </section>
  );
}
