import { useState } from "react";
import { api } from "../api/client";
import type { PackInfo, Run, TargetKind } from "../api/types";
import { Icon } from "./Icon";

const TARGETS: { kind: TargetKind; title: string; description: string }[] = [
  { kind: "vulnerable_demo", title: "Vulnerable demo", description: "Deliberately insecure. Expect findings." },
  { kind: "safe_demo", title: "Safe demo", description: "Hardened. Should pass every test." },
  { kind: "http", title: "HTTP endpoint", description: "Your own authorized test endpoint." },
];

interface RunLauncherProps {
  packs: PackInfo[];
  onFinished: (run: Run) => void;
}

/** Target + pack picker that starts a scan. HTTP targets need explicit authorization. */
export function RunLauncher({ packs, onFinished }: RunLauncherProps) {
  const [kind, setKind] = useState<TargetKind>("vulnerable_demo");
  const [url, setUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [selected, setSelected] = useState<string[]>(packs.map((p) => p.id));
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isHttp = kind === "http";
  const canRun = selected.length > 0 && !running && (!isHttp || (authorized && url.trim() !== ""));
  const toggle = (id: string) => setSelected(selected.includes(id) ? selected.filter((p) => p !== id) : [...selected, id]);

  async function start() {
    setRunning(true);
    setError(null);
    try {
      const target = isHttp ? { kind, url: url.trim() } : { kind };
      const scope = isHttp
        ? { authorization_confirmed: authorized, allowed_hosts: [new URL(url.trim()).hostname] }
        : undefined;
      onFinished(await api.createRun({ target, scope, packs: selected }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning(false);
    }
  }

  return (
    <section className="panel">
      <div className="panel-head"><h2><Icon name="play_circle" />New scan</h2></div>
      <div className="panel-body stack">
        <div className="label">Target</div>
        <div className="choice-grid">
          {TARGETS.map((target) => (
            <button key={target.kind} className={`choice ${kind === target.kind ? "selected" : ""}`} onClick={() => setKind(target.kind)}>
              <strong>{target.title}</strong>
              <span className="small muted">{target.description}</span>
            </button>
          ))}
        </div>

        {isHttp && (
          <>
            <div className="field">
              <label className="label" htmlFor="target-url">Endpoint URL</label>
              <input id="target-url" className="input mono" type="url" placeholder="http://localhost:9000/ask"
                value={url} onChange={(e) => setUrl(e.target.value)} />
              <span className="small dim">POSTs {"{ prompt, context }"}; expects {"{ text, tool_calls }"}. Redirects are blocked.</span>
            </div>
            <label className="check">
              <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
              <span>I am authorized to test this endpoint. Only its host will be contacted.</span>
            </label>
          </>
        )}

        <div className="label">Test packs</div>
        <div className="choice-grid">
          {packs.map((pack) => (
            <button key={pack.id} className={`choice ${selected.includes(pack.id) ? "selected" : ""}`}
              aria-pressed={selected.includes(pack.id)} onClick={() => toggle(pack.id)}>
              <strong>{pack.title}</strong>
              <span className="small muted">{pack.cases} cases · OWASP {pack.owasp}</span>
            </button>
          ))}
        </div>

        {error && <div className="error" role="alert">{error}</div>}
        <div>
          <button className="btn btn-primary" disabled={!canRun} onClick={start}>
            <Icon name="play_arrow" />{running ? "Running…" : "Run security tests"}
          </button>
        </div>
      </div>
    </section>
  );
}
