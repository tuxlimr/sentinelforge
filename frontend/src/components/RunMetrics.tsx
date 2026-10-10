import type { Run, Severity } from "../api/types";
import { formatDuration, isBlocked, passRate, passRateTone } from "../format";
import { Metric } from "./Metric";

/** The four headline metrics for a run, as on the Stitch dashboard. */
export function RunMetrics({ run, failOn }: { run: Run; failOn: Severity }) {
  const confirmed = run.findings.filter((f) => f.status === "confirmed").length;
  const potential = run.findings.length - confirmed;
  const blocked = isBlocked(run, failOn);
  const rate = passRate(run);
  // No confirmed finding, but cases errored: nothing really ran, so the green "PASSED" would mislead.
  const inconclusive = !blocked && run.counts.error > 0;
  const gate = blocked
    ? { value: "BLOCKED", icon: "cancel" as const, tone: "var(--fail)", hint: `Rule: no confirmed finding ≥ ${failOn} · exit 1` }
    : inconclusive
      ? { value: "INCONCLUSIVE", icon: "help" as const, tone: "var(--warn)",
          hint: `${run.counts.error} case(s) errored — review before trusting · exit 0` }
      : { value: "PASSED", icon: "check_circle" as const, tone: "var(--pass)", hint: `Rule: no confirmed finding ≥ ${failOn} · exit 0` };

  return (
    <div className="grid grid-4">
      <Metric label="Findings detected" icon="policy" value={confirmed} unit="confirmed"
        tone={confirmed ? "var(--fail)" : "var(--pass)"}
        hint={`${potential} potential · ${run.counts.error} inconclusive`} />
      <Metric label="Deterministic assertions" icon="verified" value={`${rate}%`} unit="pass rate" tone={passRateTone(rate)}
        hint="No LLM judge: every verdict is reproducible" />
      <Metric label="Budget & limits" icon="speed" value={run.budget.requests} unit="requests"
        hint={`${run.budget.cases_run}/${run.budget.max_cases} cases · ${formatDuration(run.duration_ms)}`} />
      <Metric label="CI policy gate" icon={gate.icon} value={gate.value} tone={gate.tone} blocked={blocked}
        hint={gate.hint} />
    </div>
  );
}
