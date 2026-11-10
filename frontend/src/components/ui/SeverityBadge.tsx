import type { Criticidad } from "../../lib/types";
import { CLASES_CRITICIDAD } from "../../lib/format";

export function SeverityBadge({
  criticidad,
  size = "md",
}: {
  criticidad: Criticidad;
  size?: "sm" | "md";
}) {
  const pad = size === "sm" ? "px-2 py-0.5 text-[11px]" : "px-2.5 py-1 text-xs";
  return (
    <span
      className={`inline-flex items-center rounded-full border font-semibold uppercase tracking-wide ${pad} ${CLASES_CRITICIDAD[criticidad]}`}
    >
      {criticidad}
    </span>
  );
}
