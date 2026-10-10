import { useState, type CSSProperties } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { SEVERITIES, type Severity } from "../api/types";
import { SeverityBadge, toneVars } from "../components/Badges";
import { Empty, ErrorBox, Loading } from "../components/States";
import { FindingDetail } from "../components/FindingDetail";
import { Icon } from "../components/Icon";
import { RunMetrics } from "../components/RunMetrics";
import { download, formatDate, safeName, SEVERITY_TONE, TARGET_LABEL } from "../format";
import { useAsync } from "../hooks/useAsync";

export function Findings() {
  const [params, setParams] = useSearchParams();
  const runs = useAsync(api.listRuns);
  const regressions = useAsync(api.listRegressions);
  const settings = useAsync(api.getSettings);
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [pack, setPack] = useState("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  if (runs.loading || settings.loading) return <Loading />;
  if (runs.error || !runs.data || !settings.data) return <ErrorBox message={runs.error ?? settings.error ?? "Could not load runs"} />;
  if (runs.data.length === 0) return <div className="panel"><Empty title="No runs yet">Start a scan from the Security Scans page.</Empty></div>;

  const run = runs.data.find((r) => r.id === params.get("run")) ?? runs.data[0];
  const packs = [...new Set(run.findings.map((f) => f.pack))];
  const visible = run.findings.filter((f) => (severity === "all" || f.severity === severity) && (pack === "all" || f.pack === pack));
  const selected = visible.find((f) => f.id === selectedId) ?? visible[0];
  const savedFor = (caseId: string) => regressions.data?.find((r) => r.id === caseId);

  async function saveRegression(caseId: string) {
    await api.saveRegression({ case_id: caseId, source: run.id });
    regressions.reload();
  }

  async function remove() {
    if (!window.confirm("Delete this run permanently?")) return;
    await api.deleteRun(run.id);
    setParams({});
    runs.reload();
  }

  const cliCommand = `sentinelforge test --target ${run.target_kind} --fail-on ${settings.data.fail_on}`;

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs"><span>Findings & Verification</span><span>/</span><span className="mono">{run.id}</span></div>
          <h1>{TARGET_LABEL[run.target_kind] ?? run.target}</h1>
          <p>{formatDate(run.started_at)} · {run.results.length} tests evaluated across {run.packs.length} packs</p>
        </div>
        <div className="row">
          <select className="select" style={{ width: 220 }} value={run.id} aria-label="Select run" onChange={(e) => setParams({ run: e.target.value })}>
            {runs.data.map((r) => <option key={r.id} value={r.id}>{r.id}</option>)}
          </select>
          <button className="btn" onClick={() => download(`${safeName(run.id)}.json`, JSON.stringify(run, null, 2), "application/json")}>
            <Icon name="data_object" size={16} />JSON
          </button>
          <button className="btn btn-danger" onClick={remove}><Icon name="delete" size={16} />Delete</button>
        </div>
      </div>

      <RunMetrics run={run} failOn={settings.data.fail_on} />

      <div className="grid grid-split">
        <section className="panel">
          <div className="panel-head">
            <h2><Icon name="list_alt" />Vulnerability stream</h2>
            <span className="label">{visible.length} findings</span>
          </div>
          <div className="panel-body stack" style={{ paddingBottom: 12 }}>
            <div className="filters">
              <button className={`chip ${pack === "all" ? "active" : ""}`} onClick={() => setPack("all")}>All ({run.findings.length})</button>
              {packs.map((p) => (
                <button key={p} className={`chip ${pack === p ? "active" : ""}`} onClick={() => setPack(p)}>
                  {p.replace(/_/g, " ")} ({run.findings.filter((f) => f.pack === p).length})
                </button>
              ))}
            </div>
            <select className="select" value={severity} aria-label="Filter severity" onChange={(e) => setSeverity(e.target.value as Severity | "all")}>
              <option value="all">All severities</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div className="stream">
            {visible.length === 0 && <Empty title="No findings">Nothing matches these filters.</Empty>}
            {visible.map((finding) => (
              <button key={finding.id} className={`stream-item ${finding.id === selected?.id ? "selected" : ""}`}
                style={{ "--tone": SEVERITY_TONE[finding.severity] } as CSSProperties} onClick={() => setSelectedId(finding.id)}>
                <div className="row" style={{ gap: 8 }}>
                  <SeverityBadge severity={finding.severity} />
                  <span className="mono dim">{finding.case_id}</span>
                  <span className="spacer" />
                  <span style={toneVars(finding.status === "confirmed" ? "var(--fail)" : "var(--warn)")} className="badge">{finding.status}</span>
                </div>
                <span className="stream-title">{finding.title}</span>
                <span className="small muted">{finding.risk}</span>
                <div className="stream-meta">
                  <span>{finding.category}</span>
                  <span>{finding.reproductions}</span>
                  {savedFor(finding.case_id) && <span style={{ color: "var(--pass)" }}>regression saved</span>}
                </div>
              </button>
            ))}
          </div>
        </section>

        {selected ? (
          <FindingDetail finding={selected} saved={savedFor(selected.case_id)} onSaveRegression={() => saveRegression(selected.case_id)} />
        ) : (
          <div className="panel"><Empty title="Select a finding">Choose a finding from the stream to see its evidence.</Empty></div>
        )}
      </div>

      <section className="panel">
        <div className="panel-head"><h2><Icon name="deployed_code" />Test pack health & CI artifacts</h2></div>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Case</th><th>Pack</th><th>Severity</th><th>Outcome</th><th>Time</th></tr></thead>
            <tbody>
              {run.results.map((result) => (
                <tr key={result.case_id}>
                  <td><span className="mono dim">{result.case_id}</span> {result.name}</td>
                  <td className="muted">{result.pack}</td>
                  <td><SeverityBadge severity={result.severity} /></td>
                  <td style={{ color: result.outcome === "passed" ? "var(--pass)" : "var(--fail)" }}>{result.outcome}</td>
                  <td className="mono muted">{result.duration_ms} ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="panel-body stack">
          <div className="terminal"><span className="prompt">$</span>{cliCommand}</div>
          <div className="small dim mono">
            tool {run.tool_version} · packs {run.pack_version} · config {run.config_hash} · {run.sanitization}
          </div>
          {run.warnings.map((w) => <div className="callout warn small" key={w}>{w}</div>)}
        </div>
      </section>
    </>
  );
}
