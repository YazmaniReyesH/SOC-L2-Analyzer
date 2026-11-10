import { Activity, Siren, Globe2, ArrowDownRight } from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { Estadisticas, Finding, Incidente } from "../lib/types";
import { COLOR_CRITICIDAD, PALETA } from "../lib/format";
import { Card } from "./ui/Card";

const EJE = "hsl(215 20% 60%)";
const GRID = "hsl(215 20% 40% / 0.2)";

function Kpi({
  icon,
  titulo,
  valor,
  detalle,
  acento,
}: {
  icon: React.ReactNode;
  titulo: string;
  valor: string | number;
  detalle?: React.ReactNode;
  acento?: string;
}) {
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          {titulo}
        </span>
        <span className={acento ?? "text-primary"}>{icon}</span>
      </div>
      <div className="mt-2 text-3xl font-bold">{valor}</div>
      {detalle && <div className="mt-1 text-xs text-muted-foreground">{detalle}</div>}
    </Card>
  );
}

function Panel({
  titulo,
  children,
}: {
  titulo: string;
  children: React.ReactNode;
}) {
  return (
    <Card className="p-4">
      <h3 className="mb-3 text-sm font-semibold">{titulo}</h3>
      {children}
    </Card>
  );
}

const tooltipStyle = {
  backgroundColor: "hsl(222 40% 11%)",
  border: "1px solid hsl(217 33% 25%)",
  borderRadius: 8,
  color: "hsl(210 40% 98%)",
  fontSize: 12,
};

export function Dashboard({
  estadisticas,
  incidentes,
  hallazgos,
}: {
  estadisticas: Estadisticas;
  incidentes: Incidente[];
  hallazgos: Finding[];
}) {
  const crit = estadisticas.por_criticidad_hallazgos.map((c) => ({
    name: c.etiqueta,
    valor: c.valor,
  }));
  const timeline = estadisticas.linea_tiempo.map((p) => ({
    hora: p.hora.slice(11),
    eventos: p.conteo,
  }));
  const topIps = estadisticas.top_ips_externas.map((c) => ({
    ip: c.etiqueta,
    conteo: c.valor,
  }));
  const eventos = estadisticas.por_event_id.slice(0, 8).map((c) => ({
    name: c.etiqueta,
    value: c.valor,
  }));
  const hosts = estadisticas.por_hostname.slice(0, 10).map((c) => ({
    host: c.etiqueta,
    eventos: c.valor,
  }));

  const nCriticos = incidentes.filter((i) => i.criticidad === "Crítico").length;

  return (
    <div className="space-y-5">
      {/* KPIs */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Kpi
          icon={<Activity className="h-5 w-5" />}
          titulo="Eventos analizados"
          valor={estadisticas.total_eventos}
          detalle={`${estadisticas.hosts_afectados.length} hosts`}
        />
        <Kpi
          icon={<Siren className="h-5 w-5" />}
          titulo="Incidentes"
          valor={incidentes.length}
          detalle={`${nCriticos} crítico(s) · ${hallazgos.length} hallazgos`}
          acento="text-critico"
        />
        <Kpi
          icon={<Globe2 className="h-5 w-5" />}
          titulo="IPs ext. origen"
          valor={estadisticas.ips_externas_origen.length}
          detalle={estadisticas.ips_externas_origen.join(", ") || "—"}
          acento="text-alto"
        />
        <Kpi
          icon={<ArrowDownRight className="h-5 w-5" />}
          titulo="IPs ext. destino/exfil"
          valor={estadisticas.ips_externas_destino.length}
          detalle={estadisticas.ips_externas_destino.join(", ") || "—"}
          acento="text-critico"
        />
      </div>

      {/* Criticidad + Timeline */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Panel titulo="Hallazgos por criticidad">
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={crit}>
              <CartesianGrid strokeDasharray="3 3" stroke={GRID} />
              <XAxis dataKey="name" tick={{ fill: EJE, fontSize: 12 }} />
              <YAxis allowDecimals={false} tick={{ fill: EJE, fontSize: 12 }} />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "transparent" }} />
              <Bar dataKey="valor" radius={[6, 6, 0, 0]}>
                {crit.map((c) => (
                  <Cell
                    key={c.name}
                    fill={COLOR_CRITICIDAD[c.name as keyof typeof COLOR_CRITICIDAD] ?? PALETA[0]}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Panel>

        <Panel titulo="Línea de tiempo de eventos">
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={timeline}>
              <CartesianGrid strokeDasharray="3 3" stroke={GRID} />
              <XAxis dataKey="hora" tick={{ fill: EJE, fontSize: 10 }} interval="preserveStartEnd" />
              <YAxis allowDecimals={false} tick={{ fill: EJE, fontSize: 12 }} />
              <Tooltip contentStyle={tooltipStyle} />
              <Line type="monotone" dataKey="eventos" stroke="hsl(217 91% 60%)" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </Panel>

        <Panel titulo="Distribución por tipo de evento">
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie data={eventos} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} innerRadius={45}>
                {eventos.map((_, idx) => (
                  <Cell key={idx} fill={PALETA[idx % PALETA.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
              <Legend wrapperStyle={{ fontSize: 11, color: EJE }} />
            </PieChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      {/* Top IPs + Hosts */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel titulo="Top IPs externas (origen + destino)">
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={topIps} layout="vertical" margin={{ left: 30 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={GRID} />
              <XAxis type="number" allowDecimals={false} tick={{ fill: EJE, fontSize: 12 }} />
              <YAxis type="category" dataKey="ip" width={110} tick={{ fill: EJE, fontSize: 11 }} />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "transparent" }} />
              <Bar dataKey="conteo" fill="hsl(25 95% 53%)" radius={[0, 6, 6, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Panel>

        <Panel titulo="Hosts afectados (por volumen de eventos)">
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={hosts}>
              <CartesianGrid strokeDasharray="3 3" stroke={GRID} />
              <XAxis dataKey="host" tick={{ fill: EJE, fontSize: 10 }} angle={-25} textAnchor="end" height={60} />
              <YAxis allowDecimals={false} tick={{ fill: EJE, fontSize: 12 }} />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "transparent" }} />
              <Bar dataKey="eventos" fill="hsl(199 89% 48%)" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Panel>
      </div>
    </div>
  );
}
