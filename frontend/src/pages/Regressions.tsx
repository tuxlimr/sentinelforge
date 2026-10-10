import { useState } from "react";
import { api } from "../api/client";
import type { ReplayResult, TargetKind } from "../api/types";
import { Badge, SeverityBadge } from "../components/Badges";
import { CopyButton } from "../components/CopyButton";
import { Icon } from "../components/Icon";
import { Metric } from "../components/Metric";
import { Empty, ErrorBox, Loading } from "../components/States";
import { download } from "../format";
import { useAsync } from "../hooks/useAsync";

type StatusFilter = "all" | "blocked" | "passing" | "pending";

const STATUS_TONE = { blocked: "var(--fail)", passing: "var(--pass)", error: "var(--warn)", pending: "var(--outline)" } as const;
const STATUS_LABEL = { blocked: "CI blocked", passing: "Passing", error: "Error", pending: "Pending replay" } as const;

export function Regressions() {
  const regressions = useAsync(api.listRegressions);
  const code = useAsync(api.exportRegressions, [regressions.data?.length]);
  const [replays, setReplays] = useState<Record<string, ReplayResult>>({});
  const [replayTarget, setReplayTarget] = useState<TargetKind>("safe_demo");
  const [replaying, setReplaying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [packFilter, setPackFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [openId, setOpenId] = useState<string | null>(null);

  if (regressions.loading) return <Loading />;
  if (regressions.error || !regressions.data) return <ErrorBox message={regressions.error ?? "Could not load regressions"} />;

  const items = regressions.data;
  const statusOf = (id: string) => replays[id]?.status ?? "pending";
  const packs = [...new Set(items.map((r) => r.pack))];
  const blocked = items.filter((r) => statusOf(r.id) === "blocked").length;
  const passing = items.filter((r) => statusOf(r.id) === "passing").length;
  const runtime = Object.values(replays).reduce((sum, r) => sum + r.duration_ms, 0);
  const visible = items.filter((r) => (packFilter === "all" || r.pack === packFilter) && (statusFilter === "all" || statusOf(r.id) === statusFilter));

  async function replay() {
    setReplaying(true);
    setError(null);
    try {
      const results = await api.replayRegressions({ kind: replayTarget });
      setReplays(Object.fromEntries(results.map((r) => [r.id, r])));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setReplaying(false);
    }
  }

  async function remove(id: string) {
    await api.removeRegression(id);
    regressions.reload();
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Regression test suite</h1>
          <p>Findings you saved become immutable test cases, so fixes stay fixed.</p>
        </div>
        <div className="row">
          <select className="select" style={{ width: 170 }} value={replayTarget} aria-label="Replay target" onChange={(e) => setReplayTarget(e.target.value as TargetKind)}>
            <option value="safe_demo">Replay on safe demo</option>
            <option value="vulnerable_demo">Replay on vulnerable demo</option>
          </select>
          <button className="btn btn-primary" disabled={items.length === 0 || replaying} onClick={replay}>
            <Icon name="sync" size={16} />{replaying ? "Replaying…" : "Replay suite"}
          </button>
          <button className="btn" disabled={items.length === 0} onClick={async () => download("test_sentinelforge_regressions.py", await api.exportRegressions(), "text/x-python")}>
            <Icon name="download" size={16} />Export pytest
          </button>
        </div>
      </div>

      <div className="terminal"><span className="prompt">$</span>sentinelforge regressions export --format pytest --output tests/security/</div>
      {error && <div className="error" role="alert">{error}</div>}

      <div className="grid grid-4">
        <Metric label="Active regressions" icon="rule_folder" value={items.length} unit="cases locked" />
        <Metric label="Assertion model" icon="lock" value="100%" unit="deterministic" tone="var(--pass)" hint="Zero LLM evaluator dependencies" />
        <Metric label="CI gate status" icon={blocked ? "gpp_bad" : "gpp_good"} value={Object.keys(replays).length ? blocked : "—"} unit={blocked === 1 ? "failure" : "failures"}
          tone={blocked ? "var(--fail)" : "var(--pass)"} blocked={blocked > 0} hint={Object.keys(replays).length ? `${passing} passing` : "Replay the suite to check"} />
        <Metric label="Replay runtime" icon="speed" value={runtime} unit="ms total" hint="Local runner, no API cost" />
      </div>

      <div className="grid grid-split">
        <section className="panel">
          <div className="panel-head">
            <h2><Icon name="checklist" />Specifications</h2>
            <span className="label">Showing {visible.length} of {items.length}</span>
          </div>
          <div className="panel-body stack" style={{ paddingBottom: 8 }}>
            <div className="filters">
              <span className="label">Pack</span>
              {["all", ...packs].map((p) => (
                <button key={p} className={`chip ${packFilter === p ? "active" : ""}`} onClick={() => setPackFilter(p)}>{p === "all" ? "All" : p.replace(/_/g, " ")}</button>
              ))}
            </div>
            <div className="filters">
              <span className="label">Status</span>
              {(["all", "blocked", "passing", "pending"] as StatusFilter[]).map((s) => (
                <button key={s} className={`chip ${statusFilter === s ? "active" : ""}`} onClick={() => setStatusFilter(s)}>{s}</button>
              ))}
            </div>
          </div>
          {items.length === 0 && <Empty title="No regression tests">Save a finding from Findings & Verification, or a payload from the Exploit Lab.</Empty>}
          <div className="stream">
            {visible.map((item) => {
              const status = statusOf(item.id);
              const open = openId === item.id;
              return (
                <div key={item.id} style={{ borderBottom: "1px solid var(--outline-variant)" }}>
                  <button className="stream-item" style={{ borderBottom: 0 }} onClick={() => setOpenId(open ? null : item.id)} aria-expanded={open}>
                    <div className="row" style={{ gap: 8 }}>
                      <Badge tone={STATUS_TONE[status]}>{STATUS_LABEL[status]}</Badge>
                      <span className="mono dim">{item.id}</span>
                      <span className="spacer" />
                      <SeverityBadge severity={item.severity} />
                    </div>
                    <span className="stream-title">{item.name}{item.mutation ? ` · ${item.mutation}` : ""}</span>
                    <div className="stream-meta"><span>{item.pack.replace(/_/g, " ")}</span><span>Assert: {item.check.type}</span><span>From: {item.source}</span></div>
                  </button>
                  {open && (
                    <div className="panel-body stack" style={{ paddingTop: 0 }}>
                      <pre className="codebox mono">{item.prompt}</pre>
                      {replays[item.id] && <div className={`callout small ${status === "blocked" ? "warn" : ""}`}>{replays[item.id].message}</div>}
                      <div><button className="btn btn-sm btn-danger" onClick={() => remove(item.id)}><Icon name="delete" size={14} />Remove</button></div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2><Icon name="code" />tests/security/test_security_regressions.py</h2>
            <div className="row">
              <CopyButton text={code.data ?? ""} />
            </div>
          </div>
          <div className="panel-body">
            <pre className="codebox mono" style={{ maxHeight: 640 }}>{code.data ?? "Loading…"}</pre>
          </div>
        </section>
      </div>
    </>
  );
}
