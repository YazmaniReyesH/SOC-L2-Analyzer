import { useMemo, useState } from "react";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnFiltersState,
  type SortingState,
} from "@tanstack/react-table";
import {
  Search,
  ChevronLeft,
  ChevronRight,
  ArrowUpDown,
  Globe,
} from "lucide-react";
import type { LogEvent } from "../lib/types";
import { Card } from "./ui/Card";

const col = createColumnHelper<LogEvent>();

function SelectFiltro({
  valor,
  onChange,
  opciones,
  label,
}: {
  valor: string;
  onChange: (v: string) => void;
  opciones: string[];
  label: string;
}) {
  return (
    <select
      value={valor}
      onChange={(e) => onChange(e.target.value)}
      className="rounded-lg border border-border bg-card px-2.5 py-1.5 text-sm outline-none focus:border-primary"
    >
      <option value="">{label}: todos</option>
      {opciones.map((o) => (
        <option key={o} value={o}>
          {o}
        </option>
      ))}
    </select>
  );
}

export function LogsTable({ eventos }: { eventos: LogEvent[] }) {
  const [globalFilter, setGlobalFilter] = useState("");
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  const [sorting, setSorting] = useState<SortingState>([]);

  const unicos = useMemo(() => {
    const u = (key: keyof LogEvent) =>
      Array.from(new Set(eventos.map((e) => String(e[key] ?? "")).filter(Boolean))).sort();
    return {
      event_id: u("event_id"),
      severity: u("severity"),
      hostname: u("hostname"),
      user: u("user"),
    };
  }, [eventos]);

  const columns = useMemo(
    () => [
      col.accessor("log_id", { header: "Log_ID", cell: (i) => <span className="font-mono text-xs">{i.getValue()}</span> }),
      col.accessor("timestamp_str", { header: "Timestamp", cell: (i) => <span className="whitespace-nowrap text-xs">{i.getValue()}</span> }),
      col.accessor("hostname", { header: "Hostname", filterFn: "equalsString" }),
      col.accessor("event_id", { header: "Event_ID", filterFn: "equalsString", cell: (i) => <span className="font-mono text-xs">{i.getValue()}</span> }),
      col.accessor("user", { header: "User", filterFn: "equalsString", cell: (i) => <span className="text-xs">{i.getValue()}</span> }),
      col.accessor("source_ip", {
        header: "Source_IP",
        cell: (i) => (
          <span className="flex items-center gap-1 font-mono text-xs">
            {i.getValue()}
            {i.row.original.ip_externa && (
              <Globe className="h-3 w-3 text-alto" aria-label="IP externa" />
            )}
          </span>
        ),
      }),
      col.accessor("destination", { header: "Destination", cell: (i) => <span className="font-mono text-xs">{i.getValue() || "—"}</span> }),
      col.accessor("result", { header: "Result", cell: (i) => <span className="text-xs">{i.getValue()}</span> }),
      col.accessor("severity", { header: "Severity", filterFn: "equalsString" }),
      col.accessor("event_description", { header: "Descripción", cell: (i) => <span className="text-xs text-muted-foreground">{i.getValue()}</span> }),
    ],
    []
  );

  const table = useReactTable({
    data: eventos,
    columns,
    state: { globalFilter, columnFilters, sorting },
    onGlobalFilterChange: setGlobalFilter,
    onColumnFiltersChange: setColumnFilters,
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 15 } },
  });

  const setCol = (id: string, v: string) =>
    setColumnFilters((prev) => {
      const otros = prev.filter((f) => f.id !== id);
      return v ? [...otros, { id, value: v }] : otros;
    });
  const getCol = (id: string) =>
    (columnFilters.find((f) => f.id === id)?.value as string) ?? "";

  return (
    <Card className="p-4">
      {/* Controles */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <input
            value={globalFilter}
            onChange={(e) => setGlobalFilter(e.target.value)}
            placeholder="Buscar en todos los campos…"
            className="w-full rounded-lg border border-border bg-card py-1.5 pl-9 pr-3 text-sm outline-none focus:border-primary"
          />
        </div>
        <SelectFiltro label="Event_ID" valor={getCol("event_id")} onChange={(v) => setCol("event_id", v)} opciones={unicos.event_id} />
        <SelectFiltro label="Severity" valor={getCol("severity")} onChange={(v) => setCol("severity", v)} opciones={unicos.severity} />
        <SelectFiltro label="Hostname" valor={getCol("hostname")} onChange={(v) => setCol("hostname", v)} opciones={unicos.hostname} />
        <SelectFiltro label="User" valor={getCol("user")} onChange={(v) => setCol("user", v)} opciones={unicos.user} />
      </div>

      {/* Tabla */}
      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full border-collapse text-left text-sm">
          <thead className="bg-muted/50">
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((h) => (
                  <th
                    key={h.id}
                    onClick={h.column.getToggleSortingHandler()}
                    className="cursor-pointer select-none whitespace-nowrap px-3 py-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground"
                  >
                    <span className="inline-flex items-center gap-1">
                      {flexRender(h.column.columnDef.header, h.getContext())}
                      {h.column.getCanSort() && <ArrowUpDown className="h-3 w-3 opacity-50" />}
                    </span>
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row) => (
              <tr key={row.id} className="border-t border-border hover:bg-muted/30">
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className="max-w-[260px] truncate px-3 py-2 align-top">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
            {table.getRowModel().rows.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="px-3 py-10 text-center text-muted-foreground">
                  Sin resultados para los filtros aplicados.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Paginación */}
      <div className="mt-3 flex items-center justify-between text-sm text-muted-foreground">
        <span>
          {table.getFilteredRowModel().rows.length} de {eventos.length} eventos
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
            className="rounded-lg border border-border p-1.5 disabled:opacity-40"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <span>
            Página {table.getState().pagination.pageIndex + 1} de {table.getPageCount()}
          </span>
          <button
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
            className="rounded-lg border border-border p-1.5 disabled:opacity-40"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </Card>
  );
}
