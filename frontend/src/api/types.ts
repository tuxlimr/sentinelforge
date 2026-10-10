/** Shapes returned by the SentinelForge API. Mirrors backend/sentinelforge/models. */

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type Verdict = "pass" | "warn" | "fail";
export type Outcome = "passed" | "failed" | "skipped" | "error";
export type TargetKind = "vulnerable_demo" | "safe_demo" | "http";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];
export const SEVERITY_RANK: Record<Severity, number> = { informational: 0, low: 1, medium: 2, high: 3, critical: 4 };

export interface Evidence {
  prompt: string;
  response: string;
  tool_calls: { name: string; args: Record<string, unknown> }[];
  assertion: string;
}

export interface Finding {
  id: string;
  case_id: string;
  status: string;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  evidence_quality: "deterministic" | "heuristic";
  title: string;
  pack: string;
  category: string;
  risk: string;
  expected: string;
  evidence: Evidence;
  reproductions: string;
  mitigation: string;
  limitations: string;
}

export interface CaseResult {
  case_id: string;
  name: string;
  pack: string;
  category: string;
  severity: Severity;
  outcome: Outcome;
  duration_ms: number;
  note: string;
}

export interface Run {
  id: string;
  label: string | null;
  started_at: string;
  duration_ms: number;
  tool_version: string;
  pack_version: string;
  config_hash: string;
  target: string;
  target_kind: TargetKind;
  packs: string[];
  exit_status: number;
  verdict: Verdict;
  counts: Record<Outcome, number>;
  severity_counts: Record<Severity, number>;
  budget: { requests: number; cases_run: number; max_cases: number };
  results: CaseResult[];
  findings: Finding[];
  skipped: { case_id: string; reason: string }[];
  warnings: string[];
  sanitization: string;
}

export interface PackInfo {
  id: string;
  title: string;
  description: string;
  owasp: string;
  cases: number;
}

export interface TargetSpec {
  kind: TargetKind;
  url?: string;
}

export interface RunRequest {
  target: TargetSpec;
  scope?: { authorization_confirmed: boolean; allowed_hosts: string[] };
  packs: string[];
}

export interface Regression {
  id: string;
  case_id: string;
  name: string;
  pack: string;
  severity: Severity;
  mutation: string | null;
  source: string;
  prompt: string;
  check: { type: string };
}

export interface SaveRegression {
  case_id: string;
  source: string;
  prompt?: string;
  mutation?: string;
}

export interface ReplayResult {
  id: string;
  status: "passing" | "blocked" | "error";
  duration_ms: number;
  message: string;
}

export interface TestCaseInfo {
  id: string;
  name: string;
  description: string;
  pack: string;
  category: string;
  severity: Severity;
  prompt: string;
  expected: string;
  risk: string;
  tags: string[];
}

export interface Mutation {
  id: string;
  label: string;
  description: string;
}

export interface FuzzResult {
  mutation: string;
  label: string;
  prompt: string;
  outcome: "exploited" | "resisted" | "error";
  response: string;
  tool_calls: { name: string }[];
  assertion: string;
  duration_ms: number;
}

export interface BenchmarkSuite {
  pack: string;
  title: string;
  cases: number;
  tp: number;
  fn: number;
  fp: number;
  tn: number;
  precision: number | null;
  recall: number | null;
}

export interface Benchmark {
  fixtures: number;
  repeats: number;
  engine: string;
  llm_judge: string;
  precision: number | null;
  recall: number | null;
  accuracy: number | null;
  instability: number;
  avg_latency_ms: number;
  totals: { tp: number; fn: number; fp: number; tn: number };
  suites: BenchmarkSuite[];
  discrepancies: { case_id: string; name: string; fixture: string; expected: string; observed: string }[];
}

export interface Settings {
  allowed_tools: string[];
  canaries: string[];
  max_cases: number;
  timeout_seconds: number;
  verify_repeats: number;
  fail_on: Severity;
}

export interface Health {
  status: string;
  version: string;
  pack_version: string;
}
