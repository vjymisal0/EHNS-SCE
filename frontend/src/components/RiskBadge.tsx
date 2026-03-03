import type { RiskLevel } from "@/types/analysis";

const styles: Record<RiskLevel, { bg: string; text: string; ring: string; label: string }> = {
  LOW: {
    bg: "bg-emerald-500/15",
    text: "text-emerald-400",
    ring: "ring-emerald-500/30",
    label: "LOW RISK",
  },
  MEDIUM: {
    bg: "bg-yellow-500/15",
    text: "text-yellow-400",
    ring: "ring-yellow-500/30",
    label: "MEDIUM RISK",
  },
  HIGH: {
    bg: "bg-red-500/15",
    text: "text-red-400",
    ring: "ring-red-500/30",
    label: "HIGH RISK",
  },
};

interface RiskBadgeProps {
  level: RiskLevel;
  score: number;
}

export default function RiskBadge({ level, score }: RiskBadgeProps) {
  const s = styles[level];

  return (
    <div
      className={`inline-flex items-center gap-3 rounded-xl px-5 py-3 ring-1 ${s.bg} ${s.ring}`}
    >
      {/* Pulsing dot */}
      <span className="relative flex h-3 w-3">
        <span
          className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-75 ${s.bg}`}
        />
        <span
          className={`relative inline-flex h-3 w-3 rounded-full ${
            level === "LOW"
              ? "bg-emerald-400"
              : level === "MEDIUM"
              ? "bg-yellow-400"
              : "bg-red-400"
          }`}
        />
      </span>

      <div>
        <p className={`text-sm font-bold tracking-wider ${s.text}`}>
          {s.label}
        </p>
        <p className="text-xs text-gray-400">Score: {score}/115</p>
      </div>
    </div>
  );
}
