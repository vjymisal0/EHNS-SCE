import axios from "axios";
import type { AnalysisResult } from "@/types/analysis";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const api = axios.create({
  baseURL: API_BASE,
  timeout: 60_000,
});

/**
 * Upload a file for security analysis.
 * Returns the full analysis report from the backend.
 */
export async function analyzeFile(
  file: File,
  onProgress?: (pct: number) => void
): Promise<AnalysisResult> {
  const form = new FormData();
  form.append("file", file);

  const { data } = await api.post<AnalysisResult>("/api/v1/analyze", form, {
    headers: { "Content-Type": "multipart/form-data" },
    onUploadProgress(evt) {
      if (evt.total && onProgress) {
        onProgress(Math.round((evt.loaded * 100) / evt.total));
      }
    },
  });

  return data;
}

/**
 * Fetch recent analysis history.
 */
export async function fetchHistory(
  limit: number = 20
): Promise<AnalysisResult[]> {
  const { data } = await api.get<AnalysisResult[]>("/api/v1/history", {
    params: { limit },
  });
  return data;
}
