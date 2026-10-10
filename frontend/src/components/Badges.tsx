import type { CSSProperties, ReactNode } from "react";
import type { Severity, Verdict } from "../api/types";
import { SEVERITY_TONE, VERDICT_TONE } from "../format";

const toneStyle = (tone: string) => ({ "--tone": tone }) as CSSProperties;

export function Badge({ tone, children }: { tone: string; children: ReactNode }) {
  return <span className="badge" style={toneStyle(tone)}>{children}</span>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge tone={SEVERITY_TONE[severity]}>{severity}</Badge>;
}

const VERDICT_LABEL: Record<Verdict, string> = { pass: "Passed", warn: "Warnings", fail: "Failed" };

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return <Badge tone={VERDICT_TONE[verdict]}>{VERDICT_LABEL[verdict]}</Badge>;
}

export const toneVars = toneStyle;
