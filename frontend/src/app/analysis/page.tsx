"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import type { AnalysisResult } from "@/types/analysis";
import RiskBadge from "@/components/RiskBadge";
import HashDisplay from "@/components/HashDisplay";
import EntropyChart from "@/components/EntropyChart";
import IndicatorsList from "@/components/IndicatorsList";

export default function AnalysisPage() {
  const router = useRouter();
  const [result, setResult] = useState<AnalysisResult | null>(null);

  useEffect(() => {
    const stored = sessionStorage.getItem("analysisResult");
    if (!stored) {
      router.push("/");
      return;
    }
    setResult(JSON.parse(stored) as AnalysisResult);
  }, [router]);

  if (!result) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
      </div>
    );
  }

  const fileSizeKB = (result.file_size / 1024).toFixed(1);

  return (
    <main className="min-h-screen">
      {/* Header */}
      <header className="sticky top-0 z-30 border-b border-gray-800 bg-gray-950/90 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-3">
            <button
              onClick={() => router.push("/")}
              className="flex h-8 w-8 items-center justify-center rounded-lg text-gray-400 hover:bg-gray-800 hover:text-white transition-colors"
            >
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18" />
              </svg>
            </button>
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/10 ring-1 ring-cyan-500/30">
              <svg className="h-4 w-4 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
            <span className="text-sm font-semibold text-white">Security Analysis Report</span>
          </div>
          <button
            onClick={() => router.push("/")}
            className="rounded-lg bg-cyan-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-cyan-500 transition-colors"
          >
            New Scan
          </button>
        </div>
      </header>

      <div className="mx-auto max-w-6xl px-6 py-8">
        {/* Top: File info + Risk badge */}
        <div className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-xl font-bold text-white truncate max-w-md" title={result.filename}>
              {result.filename}
            </h1>
            <div className="mt-1 flex flex-wrap gap-3 text-xs text-gray-500">
              <span>{fileSizeKB} KB</span>
              <span className="text-gray-700">|</span>
              <span className="font-mono">{result.mime_type}</span>
            </div>
          </div>
          <RiskBadge level={result.risk_level} score={result.risk_score} />
        </div>

        {/* Dashboard grid */}
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Left column */}
          <div className="space-y-6">
            <HashDisplay hashes={result.hashes} />
            <EntropyChart entropy={result.entropy} />
          </div>

          {/* Right column */}
          <div className="space-y-6">
            {/* Quick stats */}
            <div>
              <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-gray-400">
                Quick Stats
              </h3>
              <div className="grid grid-cols-2 gap-3">
                <StatCard label="File Size" value={`${fileSizeKB} KB`} />
                <StatCard label="MIME Type" value={result.mime_type} mono />
                <StatCard label="Entropy" value={result.entropy.toFixed(4)} />
                <StatCard label="Indicators" value={String(result.suspicious_indicators.length)} />
              </div>
            </div>

            <IndicatorsList indicators={result.suspicious_indicators} />

            {/* Risk breakdown */}
            <div>
              <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-gray-400">
                Risk Score Breakdown
              </h3>
              <div className="rounded-lg bg-gray-900/80 p-4 ring-1 ring-gray-800">
                <div className="space-y-3">
                  <ScoreBar label="MIME Mismatch" max={40} active={result.suspicious_indicators.some(i => i.includes("MIME mismatch"))} points={40} />
                  <ScoreBar label="High Entropy" max={30} active={result.entropy > 7.5} points={30} />
                  <ScoreBar label="Suspicious Strings" max={25} active={result.suspicious_indicators.some(i => i.includes("Suspicious string"))} points={25} />
                  <ScoreBar label="Double Extension" max={20} active={result.suspicious_indicators.some(i => i.includes("Double extension"))} points={20} />
                </div>
                <div className="mt-4 flex items-center justify-between border-t border-gray-800 pt-3">
                  <span className="text-sm font-medium text-gray-300">Total Score</span>
                  <span className="text-lg font-bold text-white">{result.risk_score} / 115</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}

/* ── Helper sub-components ── */

function StatCard({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg bg-gray-900/80 p-3 ring-1 ring-gray-800">
      <p className="text-xs text-gray-500 mb-1">{label}</p>
      <p className={`text-sm font-semibold text-white truncate ${mono ? "font-mono text-xs" : ""}`}>
        {value}
      </p>
    </div>
  );
}

function ScoreBar({ label, max, active, points }: { label: string; max: number; active: boolean; points: number }) {
  const pct = active ? 100 : 0;
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs">
        <span className="text-gray-400">{label}</span>
        <span className={active ? "text-red-400 font-semibold" : "text-gray-600"}>
          {active ? `+${points}` : "0"} / {max}
        </span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-gray-800">
        <div
          className={`h-full rounded-full transition-all duration-500 ${
            active ? "bg-red-500" : "bg-gray-700"
          }`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
