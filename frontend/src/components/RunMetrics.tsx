import type { Run, Severity } from "../api/types";
import { formatDuration, isBlocked, passRate, passRateTone } from "../format";
import { Metric } from "./Metric";

/** The four headline metrics for a run, as on the Stitch dashboard. */
export function RunMetrics({ run, failOn }: { run: Run; failOn: Severity }) {
  const confirmed = run.findings.filter((f) => f.status === "confirmed").length;
  const potential = run.findings.length - confirmed;
  const blocked = isBlocked(run, failOn);
  const rate = passRate(run);

  return (
    <div className="grid grid-4">
      <Metric label="Findings detected" icon="policy" value={confirmed} unit="confirmed"
        tone={confirmed ? "var(--fail)" : "var(--pass)"}
        hint={`${potential} potential · ${run.counts.error} inconclusive`} />
      <Metric label="Deterministic assertions" icon="verified" value={`${rate}%`} unit="pass rate" tone={passRateTone(rate)}
        hint="No LLM judge: every verdict is reproducible" />
      <Metric label="Budget & limits" icon="speed" value={run.budget.requests} unit="requests"
        hint={`${run.budget.cases_run}/${run.budget.max_cases} cases · ${formatDuration(run.duration_ms)}`} />
      <Metric label="CI policy gate" icon={blocked ? "cancel" : "check_circle"} value={blocked ? "BLOCKED" : "PASSED"}
        tone={blocked ? "var(--fail)" : "var(--pass)"} blocked={blocked}
        hint={`Rule: no confirmed finding ≥ ${failOn} · exit ${blocked ? 1 : 0}`} />
    </div>
  );
}
