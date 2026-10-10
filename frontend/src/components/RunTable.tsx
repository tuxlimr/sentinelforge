import type { Run } from "../api/types";
import { formatDate, passRate, TARGET_LABEL } from "../format";
import { VerdictBadge } from "./Badges";

interface RunTableProps {
  runs: Run[];
  selectedId?: string;
  onSelect: (run: Run) => void;
}

export function RunTable({ runs, selectedId, onSelect }: RunTableProps) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr><th>Run</th><th>Target</th><th>Verdict</th><th>Pass rate</th><th>Findings</th><th>When</th></tr>
        </thead>
        <tbody>
          {runs.map((run) => (
            <tr key={run.id} className={`clickable ${run.id === selectedId ? "selected" : ""}`} onClick={() => onSelect(run)}>
              <td className="mono">{run.id}</td>
              <td>{TARGET_LABEL[run.target_kind] ?? run.target}</td>
              <td><VerdictBadge verdict={run.verdict} /></td>
              <td className="mono">{passRate(run)}%</td>
              <td className="mono">{run.findings.length}</td>
              <td className="muted">{formatDate(run.started_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
