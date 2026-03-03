"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
  Cell,
} from "recharts";

interface EntropyChartProps {
  entropy: number;
}

export default function EntropyChart({ entropy }: EntropyChartProps) {
  const data = [
    { name: "File", value: parseFloat(entropy.toFixed(4)) },
  ];

  const barColor =
    entropy > 7.5 ? "#ef4444" : entropy > 5.5 ? "#eab308" : "#22c55e";

  /** Reference zones for context */
  const zones = [
    { y: 4.5, label: "Text ~4.5", color: "#22c55e" },
    { y: 7.0, label: "Compressed ~7.0", color: "#eab308" },
    { y: 7.5, label: "Suspicious >7.5", color: "#ef4444" },
  ];

  return (
    <div>
      <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-gray-400">
        Shannon Entropy
      </h3>
      <div className="rounded-lg bg-gray-900/80 p-4 ring-1 ring-gray-800">
        <div className="mb-2 flex items-baseline justify-between">
          <span className="text-3xl font-bold text-white font-mono">
            {entropy.toFixed(4)}
          </span>
          <span className="text-xs text-gray-500">/ 8.0 max</span>
        </div>

        <div className="h-40">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical" margin={{ left: 0, right: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis type="number" domain={[0, 8]} tick={{ fill: "#9ca3af", fontSize: 12 }} />
              <YAxis type="category" dataKey="name" hide />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#1f2937",
                  border: "1px solid #374151",
                  borderRadius: "8px",
                  color: "#e5e7eb",
                }}
              />
              {zones.map((z) => (
                <ReferenceLine
                  key={z.label}
                  x={z.y}
                  stroke={z.color}
                  strokeDasharray="4 4"
                  label={{
                    value: z.label,
                    fill: z.color,
                    fontSize: 10,
                    position: "top",
                  }}
                />
              ))}
              <Bar dataKey="value" radius={[0, 6, 6, 0]} barSize={30}>
                {data.map((_, i) => (
                  <Cell key={i} fill={barColor} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Legend */}
        <div className="mt-3 flex flex-wrap gap-4 text-xs text-gray-500">
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full bg-emerald-500" />
            0–5.5 Normal
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full bg-yellow-500" />
            5.5–7.5 Compressed
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full bg-red-500" />
            &gt;7.5 Suspicious
          </span>
        </div>
      </div>
    </div>
  );
}
