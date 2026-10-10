import { useState } from "react";
import { api } from "../api/client";
import type { Benchmark } from "../api/types";
import { Badge } from "../components/Badges";
import { Icon } from "../components/Icon";
import { Metric } from "../components/Metric";
import { ErrorBox, Empty } from "../components/States";
import { download } from "../format";

const pct = (value: number | null) => (value === null ? "n/a" : `${value}%`);

export function Evaluation() {
  const [repeats, setRepeats] = useState(5);
  const [result, setResult] = useState<Benchmark | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setRunning(true);
    setError(null);
    try {
      setResult(await api.runBenchmark(repeats));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning(false);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs"><span>Evaluation benchmarks</span><span>/</span><span>Ground-truth assertion matrix</span></div>
          <h1>Evaluation matrix</h1>
          <p>How accurate are the deterministic checks? Each case runs against a known-vulnerable and a known-safe fixture.</p>
        </div>
        <div className="row">
          <label className="row small muted" htmlFor="repeats">Repeats
            <input id="repeats" className="input" type="number" min={1} max={20} value={repeats} style={{ width: 70 }}
              onChange={(e) => setRepeats(Math.max(1, Math.min(20, Number(e.target.value) || 1)))} />
          </label>
          <button className="btn" disabled={!result} onClick={() => result && download("benchmark.json", JSON.stringify(result, null, 2), "application/json")}>
            <Icon name="file_download" size={16} />Export matrix
          </button>
          <button className="btn btn-primary" disabled={running} onClick={run}>
            <Icon name="play_arrow" size={16} />{running ? "Running…" : "Run benchmark"}
          </button>
        </div>
      </div>

      {error && <ErrorBox message={error} />}
      {!result && !error && (
        <div className="panel"><Empty title="No benchmark yet">Run the benchmark to measure precision, recall and run-to-run stability.</Empty></div>
      )}

      {result && (
        <>
          <div className="grid grid-4">
            <Metric label="Precision" icon="target" value={pct(result.precision)} tone="var(--pass)"
              hint={`${result.totals.fp} false alarms on the safe fixture`} />
            <Metric label="Recall" icon="radar" value={pct(result.recall)} tone="var(--pass)"
              hint={`${result.totals.fn} vulnerabilities missed`} />
            <Metric label="Inter-run instability" icon="monitoring" value={`${result.instability}%`}
              tone={result.instability ? "var(--warn)" : "var(--pass)"} hint={`${result.repeats} repeats per fixture · ${result.instability ? "flaky" : "stable"}`} />
            <Metric label="Avg check latency" icon="speed" value={result.avg_latency_ms} unit="ms"
              hint={`${result.fixtures} labeled fixtures · engine: ${result.engine}`} />
          </div>

          <section className="panel">
            <div className="panel-head">
              <h2><Icon name="rule_folder" />Evaluator suites</h2>
              <Badge tone="var(--outline)">LLM judge: {result.llm_judge}</Badge>
            </div>
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Suite</th><th>Cases</th><th>Detected (TP)</th><th>Missed (FN)</th><th>False alarms (FP)</th><th>Clean (TN)</th><th>Precision</th><th>Recall</th></tr></thead>
                <tbody>
                  {result.suites.map((suite) => (
                    <tr key={suite.pack}>
                      <td><strong>{suite.title}</strong><div className="small dim">Deterministic · zero variance</div></td>
                      <td className="mono">{suite.cases}</td>
                      <td className="mono" style={{ color: "var(--pass)" }}>{suite.tp}</td>
                      <td className="mono" style={{ color: suite.fn ? "var(--fail)" : undefined }}>{suite.fn}</td>
                      <td className="mono" style={{ color: suite.fp ? "var(--fail)" : undefined }}>{suite.fp}</td>
                      <td className="mono">{suite.tn}</td>
                      <td className="mono">{pct(suite.precision)}</td>
                      <td className="mono">{pct(suite.recall)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <div className="grid grid-4" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))" }}>
            <section className="panel">
              <div className="panel-head"><h2><Icon name="grid_on" />Confusion matrix</h2></div>
              <div className="panel-body">
                <div className="matrix" style={{ gridTemplateColumns: "1fr 1fr" }}>
                  {([
                    ["True positives", result.totals.tp, "var(--pass)"],
                    ["False negatives", result.totals.fn, "var(--fail)"],
                    ["False positives", result.totals.fp, "var(--fail)"],
                    ["True negatives", result.totals.tn, "var(--pass)"],
                  ] as const).map(([label, value, tone]) => (
                    <div className="cell" key={label} style={{ "--tone": tone } as React.CSSProperties}>
                      <span className="label">{label}</span>
                      <span style={{ fontSize: 24, fontWeight: 700 }}>{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </section>

            <section className="panel">
              <div className="panel-head"><h2><Icon name="difference" />Discrepancies</h2><span className="label">{result.discrepancies.length}</span></div>
              <div className="panel-body stack">
                {result.discrepancies.length === 0 && <p className="muted">Every check matched its ground-truth label.</p>}
                {result.discrepancies.map((d) => (
                  <div className="callout warn small" key={`${d.case_id}-${d.fixture}`}>
                    <strong>{d.case_id}</strong> {d.name}: expected {d.expected}, observed {d.observed} on {d.fixture}.
                  </div>
                ))}
                <div className="callout small">
                  <strong>Deterministic first.</strong> An assertion failure always supersedes any model judge. Ground truth here is two labeled demo apps, so
                  these numbers measure the bundled checks, not your application.
                </div>
              </div>
            </section>
          </div>
        </>
      )}
    </>
  );
}
