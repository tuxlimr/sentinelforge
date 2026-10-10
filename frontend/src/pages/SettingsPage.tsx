import { useEffect, useState } from "react";
import { api } from "../api/client";
import { SEVERITIES, type Settings } from "../api/types";
import { Icon } from "../components/Icon";
import { ErrorBox, Loading } from "../components/States";
import { useAsync } from "../hooks/useAsync";

const toList = (text: string) => text.split("\n").map((line) => line.trim()).filter(Boolean);

export function SettingsPage() {
  const loaded = useAsync(api.getSettings);
  const [form, setForm] = useState<Settings | null>(null);
  const [tools, setTools] = useState("");
  const [canaries, setCanaries] = useState("");
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    if (!loaded.data) return;
    setForm(loaded.data);
    setTools(loaded.data.allowed_tools.join("\n"));
    setCanaries(loaded.data.canaries.join("\n"));
  }, [loaded.data]);

  if (loaded.loading || !form) return loaded.error ? <ErrorBox message={loaded.error} /> : <Loading />;

  const update = <K extends keyof Settings>(key: K, value: Settings[K]) => setForm({ ...form, [key]: value });

  async function save() {
    try {
      await api.saveSettings({ ...form!, allowed_tools: toList(tools), canaries: toList(canaries) });
      setStatus("Settings saved");
    } catch (e) {
      setStatus((e as Error).message);
    }
    setTimeout(() => setStatus(null), 2500);
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p>Defaults applied to every scan. Stored locally; nothing leaves your machine.</p>
        </div>
        <div className="row">
          {status && <span className="small muted" role="status">{status}</span>}
          <button className="btn btn-primary" onClick={save}><Icon name="save" size={16} />Save settings</button>
        </div>
      </div>

      <section className="panel">
        <div className="panel-head"><h2><Icon name="lock" />Scope & safety</h2></div>
        <div className="panel-body form-grid">
          <div className="field">
            <label className="label" htmlFor="tools">Allowed tools (one per line)</label>
            <textarea id="tools" className="textarea" value={tools} onChange={(e) => setTools(e.target.value)} />
            <span className="small dim">Any other tool the target requests counts as a violation. Tools are mocks and never executed.</span>
          </div>
          <div className="field">
            <label className="label" htmlFor="canaries">Synthetic canaries (one per line)</label>
            <textarea id="canaries" className="textarea" value={canaries} onChange={(e) => setCanaries(e.target.value)} />
            <span className="small dim">Fake secrets used to detect leaks. They are redacted from stored evidence.</span>
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head"><h2><Icon name="speed" />Limits & CI policy</h2></div>
        <div className="panel-body form-grid">
          <div className="field">
            <label className="label" htmlFor="max-cases">Max cases per run</label>
            <input id="max-cases" className="input" type="number" min={1} max={200} value={form.max_cases} onChange={(e) => update("max_cases", Number(e.target.value))} />
          </div>
          <div className="field">
            <label className="label" htmlFor="timeout">Timeout (seconds)</label>
            <input id="timeout" className="input" type="number" min={1} max={60} value={form.timeout_seconds} onChange={(e) => update("timeout_seconds", Number(e.target.value))} />
          </div>
          <div className="field">
            <label className="label" htmlFor="repeats">Verification repeats</label>
            <input id="repeats" className="input" type="number" min={0} max={5} value={form.verify_repeats} onChange={(e) => update("verify_repeats", Number(e.target.value))} />
            <span className="small dim">Failed cases re-run this many times. A finding is confirmed only if it fails every time.</span>
          </div>
          <div className="field">
            <label className="label" htmlFor="fail-on">CI gate fails at severity</label>
            <select id="fail-on" className="select" value={form.fail_on} onChange={(e) => update("fail_on", e.target.value as Settings["fail_on"])}>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s} and above</option>)}
            </select>
          </div>
        </div>
      </section>
    </>
  );
}
