import { SEVERITY_RANK, type Run, type Severity, type Verdict } from "./api/types";

/** CSS color variable for each severity / verdict, used as the `--tone` of badges and bars. */
export const SEVERITY_TONE: Record<Severity, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  informational: "var(--informational)",
};

export const VERDICT_TONE: Record<Verdict, string> = { pass: "var(--pass)", warn: "var(--warn)", fail: "var(--fail)" };

export const TARGET_LABEL: Record<string, string> = {
  vulnerable_demo: "Vulnerable demo",
  safe_demo: "Safe demo",
  http: "HTTP endpoint",
};

/** Percentage of executed cases that passed (0-100). */
export function passRate(run: Run): number {
  const executed = run.counts.passed + run.counts.failed + run.counts.error;
  return executed === 0 ? 0 : Math.round((run.counts.passed / executed) * 1000) / 10;
}

/** CI gate: blocked when any confirmed finding is at or above the `failOn` severity. */
export function isBlocked(run: Run, failOn: Severity): boolean {
  return run.findings.some((f) => f.status === "confirmed" && SEVERITY_RANK[f.severity] >= SEVERITY_RANK[failOn]);
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function formatDuration(ms: number): string {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

/** Trigger a browser download of text content. */
export function download(filename: string, content: string, type = "text/plain"): void {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export async function copyText(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
}

/** Last path segment of a safe filename, for downloads. */
export const safeName = (value: string) => value.replace(/[^a-zA-Z0-9._-]+/g, "_");

const LOOPBACK = ["localhost", "127.0.0.1", "::1"];

/** The CLI command that reproduces a run, or null when the CLI cannot (HTTP targets are configured in the UI/API). */
export function cliCommand(run: Run | undefined, failOn: Severity): string | null {
  const kind: string = run?.target_kind ?? "vulnerable_demo";
  if (kind === "vulnerable_demo" || kind === "safe_demo") return `sentinelforge test --target ${kind} --fail-on ${failOn}`;
  if (kind === "network" && run) {
    const expected = run.results.filter((r) => r.note === "expected").map((r) => ` --expect ${r.case_id.replace("SF-NX-", "")}`);
    const authorized = LOOPBACK.includes(run.target) ? "" : " --authorized";
    return `sentinelforge exposure ${run.target}${expected.join("")}${authorized} --fail-on ${failOn}`;
  }
  if (kind === "web" && run) {
    const host = new URL(run.target).hostname.replace(/^\[|\]$/g, "");
    return `sentinelforge webscan ${run.target}${LOOPBACK.includes(host) ? "" : " --authorized"} --fail-on ${failOn}`;
  }
  return null;
}

/** Green only at 100%; any failure is amber, and nothing passing is red. */
export function passRateTone(rate: number): string {
  if (rate >= 100) return "var(--pass)";
  return rate <= 0 ? "var(--fail)" : "var(--warn)";
}
