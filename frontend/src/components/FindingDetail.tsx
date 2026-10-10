import type { CSSProperties, ReactNode } from "react";
import type { Finding, Regression } from "../api/types";
import { SEVERITY_TONE } from "../format";
import { SeverityBadge } from "./Badges";
import { CopyButton } from "./CopyButton";
import { Icon } from "./Icon";

interface FindingDetailProps {
  finding: Finding;
  saved: Regression | undefined;
  onSaveRegression: () => void;
}

function Section({ icon, title, children }: { icon: string; title: string; children: ReactNode }) {
  return (
    <div className="stack" style={{ gap: 6 }}>
      <div className="label row" style={{ gap: 6 }}><Icon name={icon} size={15} />{title}</div>
      {children}
    </div>
  );
}

/** Find → Verify → Regress lifecycle, as on the Stitch finding detail panel. */
function Lifecycle({ finding, saved }: { finding: Finding; saved: boolean }) {
  const verified = finding.status === "confirmed";
  const steps = [
    { title: "1. Detected in scan", text: `Pack ${finding.pack}`, state: "done" },
    {
      title: verified ? "2. Verified deterministic" : "2. Needs verification",
      text: finding.reproductions,
      state: verified ? "done" : "current",
    },
    {
      title: "3. Export to pytest",
      text: saved ? "Saved as regression test" : "Awaiting regression save",
      state: saved ? "done" : verified ? "current" : "",
    },
  ];
  return (
    <div className="lifecycle">
      {steps.map((step) => (
        <div key={step.title} className={`step ${step.state}`}>
          <span className="step-num">{step.state === "done" ? "✓" : step.title[0]}</span>
          <div>
            <div style={{ fontWeight: 600 }}>{step.title.slice(3)}</div>
            <div className="small muted">{step.text}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

export function FindingDetail({ finding, saved, onSaveRegression }: FindingDetailProps) {
  const { evidence } = finding;
  return (
    <section className="panel" style={{ "--tone": SEVERITY_TONE[finding.severity] } as CSSProperties}>
      <div className="panel-head">
        <div className="row">
          <SeverityBadge severity={finding.severity} />
          <span className="mono muted">{finding.case_id}</span>
        </div>
        <CopyButton text={JSON.stringify(finding, null, 2)} label="Copy JSON" />
      </div>
      <div className="panel-body stack" style={{ gap: 18 }}>
        <div>
          <h2 style={{ fontSize: 18 }}>{finding.title}</h2>
          <p className="muted small" style={{ marginTop: 4 }}>{finding.category} · {finding.risk}</p>
        </div>

        <Lifecycle finding={finding} saved={Boolean(saved)} />

        <Section icon="crisis_alert" title="Attack payload">
          <pre className="codebox mono">{evidence.prompt}</pre>
        </Section>
        <Section icon="bug_report" title="Observed target response">
          <pre className="codebox danger mono">{evidence.response || "(empty response)"}</pre>
          {evidence.tool_calls.length > 0 && (
            <pre className="codebox danger mono">tool calls: {JSON.stringify(evidence.tool_calls)}</pre>
          )}
        </Section>
        <Section icon="rule" title="Expected vs. observed">
          <div className="small"><strong>Expected:</strong> <span className="muted">{finding.expected}</span></div>
          <div className="small"><strong>Assertion:</strong> <span className="muted">{evidence.assertion}</span></div>
          <div className="small muted">
            Confidence {finding.confidence} · evidence {finding.evidence_quality}
          </div>
        </Section>

        <div className="callout"><strong>Remediation.</strong> {finding.mitigation}</div>
        <div className="callout warn small"><strong>Limitations.</strong> {finding.limitations}</div>

        <div className="row">
          <button className="btn btn-primary" disabled={Boolean(saved)} onClick={onSaveRegression}>
            <Icon name={saved ? "check" : "bookmark_add"} size={16} />
            {saved ? "Saved as regression" : "Export to regression suite"}
          </button>
        </div>
      </div>
    </section>
  );
}
