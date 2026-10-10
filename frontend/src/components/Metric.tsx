import type { ReactNode } from "react";
import { toneVars } from "./Badges";
import { Icon } from "./Icon";

interface MetricProps {
  label: string;
  value: ReactNode;
  unit?: string;
  icon?: string;
  tone?: string;
  hint?: ReactNode;
  blocked?: boolean;
}

/** Dashboard metric card: label, big value, optional unit and hint line. */
export function Metric({ label, value, unit, icon, tone, hint, blocked }: MetricProps) {
  return (
    <div className={`panel metric ${blocked ? "gate-blocked" : ""}`} style={tone ? toneVars(tone) : undefined}>
      <div className="metric-top">
        <span className="label">{label}</span>
        {icon && <span className="dim"><Icon name={icon} /></span>}
      </div>
      <div className="metric-value">
        {value}
        {unit && <small>{unit}</small>}
      </div>
      {hint && <div className="small muted">{hint}</div>}
    </div>
  );
}
