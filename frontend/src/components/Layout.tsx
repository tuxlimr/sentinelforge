import { NavLink, Outlet, useLocation } from "react-router-dom";
import { api } from "../api/client";
import { download, safeName, TARGET_LABEL } from "../format";
import { useAsync } from "../hooks/useAsync";
import { toneVars } from "./Badges";
import { Icon } from "./Icon";

const NAV_ITEMS = [
  { to: "/", label: "Security Scans" },
  { to: "/findings", label: "Findings & Verification" },
  { to: "/regressions", label: "Regression Tests" },
  { to: "/evaluation", label: "Evaluation Matrix" },
  { to: "/lab", label: "Exploit Lab" },
  { to: "/settings", label: "Settings" },
];

/** Measures how long the API takes to answer, shown in the sidebar telemetry box. */
async function pingApi() {
  const started = performance.now();
  const health = await api.health();
  return { health, latency: Math.round(performance.now() - started) };
}

export function Layout() {
  const { pathname } = useLocation();
  const ping = useAsync(pingApi, [pathname]);
  const runs = useAsync(api.listRuns, [pathname]);
  const latest = runs.data?.[0];
  const connected = !ping.error;

  const suites = latest
    ? [...new Set(latest.results.map((r) => r.pack))].map((pack) => {
        const results = latest.results.filter((r) => r.pack === pack);
        return { pack, failed: results.filter((r) => r.outcome !== "passed").length, total: results.length };
      })
    : [];
  const passing = suites.filter((s) => s.failed === 0).length;

  async function exportSarif() {
    if (!latest) return;
    download(`${safeName(latest.id)}.sarif`, JSON.stringify(await api.getSarif(latest.id), null, 2), "application/json");
  }

  return (
    <>
      <header className="topbar">
        <div className="brand"><Icon name="shield" filled size={22} />SentinelForge</div>
        {latest && (
          <div className="target-chip" title="Target of the latest run">
            <Icon name="terminal" size={14} />
            TARGET: {TARGET_LABEL[latest.target_kind] ?? latest.target}
          </div>
        )}
        <nav className="topnav" aria-label="Primary">
          {NAV_ITEMS.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.to === "/"}>{item.label}</NavLink>
          ))}
        </nav>
        <div className="topbar-end">
          <span className="row hide-sm small muted" style={toneVars(connected ? "var(--pass)" : "var(--fail)")}>
            <span className="status-dot" />
            {connected ? `API v${ping.data?.health.version} connected` : "API offline"}
          </span>
          <button className="btn btn-sm" onClick={exportSarif} disabled={!latest}>
            <Icon name="download" size={15} />Export SARIF
          </button>
        </div>
      </header>

      <div className="shell">
        <aside className="sidebar">
          <div className="stack" style={{ gap: 8 }}>
            <div className="side-title">
              <span className="label">Vector suites</span>
              <span className="badge-count">{latest ? `${passing}/${suites.length} PASS` : "—"}</span>
            </div>
            <div className="side-list">
              {suites.length === 0 && <span className="small dim" style={{ padding: 8 }}>Run a scan to see suite status.</span>}
              {suites.map((suite) => (
                <div className="side-item" key={suite.pack}>
                  <Icon name={suite.failed ? "gpp_maybe" : "verified_user"} size={17} />
                  <span style={{ textTransform: "capitalize" }}>{suite.pack.replace(/_/g, " ")}</span>
                  <span className="badge-count" style={{ color: suite.failed ? "var(--fail)" : "var(--pass)" }}>
                    {suite.failed ? `${suite.failed} fail` : "pass"}
                  </span>
                </div>
              ))}
            </div>
          </div>
          <div className="telemetry stack" style={{ gap: 4 }}>
            <span className="label">Telemetry bus</span>
            <span className="mono small muted">API latency: {ping.data ? `${ping.data.latency} ms` : "—"}</span>
            <span className="mono small muted">Packs: {ping.data?.health.pack_version ?? "—"}</span>
          </div>
        </aside>
        <main className="main"><Outlet /></main>
      </div>
    </>
  );
}
