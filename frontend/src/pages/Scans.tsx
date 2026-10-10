import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { ErrorBox, Loading } from "../components/States";
import { Icon } from "../components/Icon";
import { RunLauncher } from "../components/RunLauncher";
import { RunMetrics } from "../components/RunMetrics";
import { RunTable } from "../components/RunTable";
import { TrendChart } from "../components/TrendChart";
import { cliCommand } from "../format";
import { useAsync } from "../hooks/useAsync";

export function Scans() {
  const navigate = useNavigate();
  const runs = useAsync(api.listRuns);
  const packs = useAsync(api.listPacks);
  const settings = useAsync(api.getSettings);

  if (runs.loading || packs.loading || settings.loading) return <Loading />;
  const error = runs.error ?? packs.error ?? settings.error;
  if (error || !runs.data || !packs.data || !settings.data) return <ErrorBox message={error ?? "Could not load data"} />;

  const latest = runs.data[0];
  const failOn = settings.data.fail_on;
  const command = cliCommand(latest, failOn);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Security scans</h1>
          <p>Run deterministic security tests, then verify and regress what they find.</p>
        </div>
        {command && (
          <div className="terminal">
            <span className="prompt">$</span>{command}
          </div>
        )}
      </div>

      {latest ? (
        <>
          <div className="row small muted">
            <Icon name="commit" size={16} />
            <span className="mono">Latest run {latest.id}</span>
            <span>· {latest.results.length} tests across {latest.packs.length} packs</span>
          </div>
          <RunMetrics run={latest} failOn={failOn} />
        </>
      ) : (
        <div className="callout">No scans yet. Start one below. The demo targets run fully offline.</div>
      )}

      <RunLauncher packs={packs.data} onFinished={(run) => navigate(`/findings?run=${run.id}`)} />

      {runs.data.length > 0 && (
        <div className="grid grid-split" style={{ gridTemplateColumns: "minmax(0, 1fr)" }}>
          <section className="panel">
            <div className="panel-head">
              <h2><Icon name="monitoring" />Pass-rate trend</h2>
              <span className="label">{runs.data.length} runs</span>
            </div>
            <div className="panel-body"><TrendChart runs={runs.data} /></div>
          </section>
          <section className="panel">
            <div className="panel-head"><h2><Icon name="history" />Run history</h2></div>
            <RunTable runs={runs.data} onSelect={(run) => navigate(`/findings?run=${run.id}`)} />
          </section>
        </div>
      )}
    </>
  );
}
