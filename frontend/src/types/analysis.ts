/** Type definitions for the File Security Analyzer API */

export interface Hashes {
  md5: string;
  sha1: string;
  sha256: string;
}

export interface AnalysisResult {
  filename: string;
  file_size: number;
  mime_type: string;
  hashes: Hashes;
  entropy: number;
  suspicious_indicators: string[];
  risk_score: number;
  risk_level: "LOW" | "MEDIUM" | "HIGH";
}

export type RiskLevel = AnalysisResult["risk_level"];
