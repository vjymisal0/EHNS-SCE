"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import FileUpload from "@/components/FileUpload";
import { analyzeFile } from "@/lib/api";
import type { AnalysisResult } from "@/types/analysis";

export default function Home() {
  const router = useRouter();
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const handleFile = async (file: File) => {
    setError(null);
    setUploading(true);
    setProgress(0);

    try {
      const result: AnalysisResult = await analyzeFile(file, setProgress);
      // Store result in sessionStorage and navigate to dashboard
      sessionStorage.setItem("analysisResult", JSON.stringify(result));
      router.push("/analysis");
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : "Analysis failed. Please try again.";
      // Try to extract backend detail
      if (typeof err === "object" && err !== null && "response" in err) {
        const axiosErr = err as { response?: { data?: { detail?: string } } };
        setError(axiosErr.response?.data?.detail || msg);
      } else {
        setError(msg);
      }
    } finally {
      setUploading(false);
      setProgress(0);
    }
  };

  return (
    <main className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-950/80 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center gap-3 px-6 py-4">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-500/10 ring-1 ring-cyan-500/30">
            <svg className="h-5 w-5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">File Security Analyzer</h1>
            <p className="text-xs text-gray-500">Static analysis &middot; Threat detection &middot; Risk scoring</p>
          </div>
        </div>
      </header>

      {/* Main content */}
      <div className="flex flex-1 items-center justify-center px-6 py-16">
        <div className="w-full max-w-xl">
          <div className="mb-8 text-center">
            <h2 className="text-2xl font-bold text-white mb-2">
              Upload a file for security analysis
            </h2>
            <p className="text-gray-400 text-sm">
              Get instant insights on file integrity, MIME validation, entropy,
              suspicious patterns, and heuristic risk scoring.
            </p>
          </div>

          <FileUpload
            onFileSelected={handleFile}
            uploading={uploading}
            progress={progress}
          />

          {error && (
            <div className="mt-4 rounded-lg bg-red-500/10 p-4 ring-1 ring-red-500/30">
              <p className="text-sm text-red-400">{error}</p>
            </div>
          )}

          {/* Feature cards */}
          <div className="mt-10 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { icon: "🔐", label: "Hash Verify" },
              { icon: "📊", label: "Entropy" },
              { icon: "🛡️", label: "MIME Check" },
              { icon: "⚠️", label: "Risk Score" },
            ].map((f) => (
              <div
                key={f.label}
                className="rounded-lg bg-gray-900/60 p-3 text-center ring-1 ring-gray-800"
              >
                <span className="text-xl">{f.icon}</span>
                <p className="mt-1 text-xs text-gray-400">{f.label}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </main>
  );
}
