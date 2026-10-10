import type { Run } from "../api/types";
import { passRate } from "../format";

const WIDTH = 600;
const HEIGHT = 90;
const PADDING = 8;

/** Line chart of pass rate across runs, oldest to newest. */
export function TrendChart({ runs }: { runs: Run[] }) {
  if (runs.length < 2) return <p className="muted small">Run at least two scans to see a trend.</p>;

  const oldestFirst = [...runs].reverse().slice(-20);
  const points = oldestFirst.map((run, index) => ({
    run,
    x: PADDING + (index / (oldestFirst.length - 1)) * (WIDTH - 2 * PADDING),
    y: PADDING + (1 - passRate(run) / 100) * (HEIGHT - 2 * PADDING),
  }));
  const line = points.map((p) => `${p.x},${p.y}`).join(" ");
  const area = `${PADDING},${HEIGHT - PADDING} ${line} ${WIDTH - PADDING},${HEIGHT - PADDING}`;

  return (
    <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} width="100%" height={HEIGHT} preserveAspectRatio="none" role="img" aria-label="Pass rate trend">
      <polygon points={area} fill="var(--primary)" opacity="0.1" />
      <polyline points={line} fill="none" stroke="var(--primary)" strokeWidth="2" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
      {points.map((p) => (
        <circle key={p.run.id} cx={p.x} cy={p.y} r="3.5" fill="var(--primary)">
          <title>{`${p.run.target}: ${passRate(p.run)}% passed`}</title>
        </circle>
      ))}
    </svg>
  );
}
