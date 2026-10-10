import { useState } from "react";
import { api } from "../api/client";
import type { Run } from "../api/types";
import { Icon } from "./Icon";

const LOOPBACK = ["localhost", "127.0.0.1", "::1"];

interface WebScanLauncherProps {
  onFinished: (run: Run) => void;
}

/** Passive website check: headers, exposed files, and library versions on a site you may test. */
export function WebScanLauncher({ onFinished }: WebScanLauncherProps) {
  const [url, setUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  let host = "";
  try {
    host = new URL(url.trim()).hostname.replace(/^\[|\]$/g, "");
  } catch {
    host = "";
  }
  const loopback = LOOPBACK.includes(host.toLowerCase());
  const canRun = host !== "" && !running && (loopback || authorized);

  async function start() {
    setRunning(true);
    setError(null);
    try {
      const scope = loopback ? undefined : { authorization_confirmed: true, allowed_hosts: [host] };
      onFinished(await api.webScan({ url: url.trim(), scope }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning(false);
    }
  }

  return (
    <section className="panel">
      <div className="panel-head"><h2><Icon name="travel_explore" />Website check</h2></div>
      <div className="panel-body stack">
        <p className="small muted">
          Reads the public page for library versions in a known-vulnerable range (jQuery, jQuery UI, Bootstrap, Lodash,
          Moment, AngularJS) and for missing security headers. Ordinary GET requests only, and only for a site you are allowed to test.
        </p>
        <div className="field">
          <label className="label" htmlFor="webscan-url">Site URL</label>
          <input id="webscan-url" className="input mono" type="url" placeholder="https://your-site.example.com/"
            value={url} onChange={(e) => setUrl(e.target.value)} />
        </div>
        {host !== "" && !loopback && (
          <label className="check">
            <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
            <span>I own this site or I am authorized to test it. Only its host will be contacted.</span>
          </label>
        )}
        {error && <div className="error" role="alert">{error}</div>}
        <div>
          <button className="btn btn-primary" disabled={!canRun} onClick={start}>
            <Icon name="travel_explore" />{running ? "Checking…" : "Check website"}
          </button>
        </div>
      </div>
    </section>
  );
}
