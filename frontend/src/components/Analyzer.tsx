import { useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api, type AnalysisReport } from "../api";

/**
 * Drop a challenge file, get the whole triage chain at once.
 * Flag candidates surface first — that's the answer 60% of the time.
 */
export default function Analyzer() {
  const [mode, setMode] = useState<"file" | "text" | "rsa">("file");
  return (
    <>
      <h2>Analyzer</h2>
      <p className="subtitle">
        Runs the full triage chain for whatever you give it. Nothing is executed —
        every step only reads the artifact.
      </p>

      <div className="filters">
        <button className={`chip ${mode === "file" ? "on" : ""}`} onClick={() => setMode("file")}>
          file
        </button>
        <button className={`chip ${mode === "text" ? "on" : ""}`} onClick={() => setMode("text")}>
          decode text
        </button>
        <button className={`chip ${mode === "rsa" ? "on" : ""}`} onClick={() => setMode("rsa")}>
          RSA
        </button>
      </div>

      {mode === "file" && <FileMode />}
      {mode === "text" && <TextMode />}
      {mode === "rsa" && <RsaMode />}
    </>
  );
}

/* -------------------------------- file -------------------------------- */

function FileMode() {
  const [drag, setDrag] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const run = useMutation({
    mutationFn: (f: File) => api.analyze(f),
  });

  const report = run.data as AnalysisReport | undefined;

  return (
    <>
      <div
        className={`dropzone ${drag ? "over" : ""}`}
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => {
          e.preventDefault(); setDrag(false);
          const f = e.dataTransfer.files?.[0];
          if (f) run.mutate(f);
        }}
        onClick={() => inputRef.current?.click()}
      >
        <input ref={inputRef} type="file" hidden
          onChange={(e) => { const f = e.target.files?.[0]; if (f) run.mutate(f); }} />
        {run.isPending
          ? <span>analysing…</span>
          : <span>drop a challenge file here, or click to choose</span>}
      </div>

      {run.isError && <div className="error">{(run.error as Error).message}</div>}
      {report && <ReportView report={report} />}
    </>
  );
}

function ReportView({ report }: { report: AnalysisReport }) {
  return (
    <>
      {report.flags.length > 0 && (
        <div className="flagbox">
          <h4>Flag candidates</h4>
          {report.flags.map((f) => (
            <code key={f} className="cmd" onClick={() => navigator.clipboard.writeText(f)}
              title="Click to copy">{f}</code>
          ))}
        </div>
      )}

      <div className="stat-grid" style={{ margin: "16px 0" }}>
        <div className="stat">
          <div className="v">{(report.size / 1024).toFixed(0)}<span style={{ fontSize: 12 }}>KB</span></div>
          <div className="k">size</div>
        </div>
        <div className="stat">
          <div className="v" style={{ color: report.entropy > 7.5 ? "var(--amber)" : undefined }}>
            {report.entropy}
          </div>
          <div className="k">entropy /8</div>
        </div>
        <div className="stat">
          <div className="v">{report.category_hint}</div>
          <div className="k">looks like</div>
        </div>
        <div className="stat">
          <div className="v">{report.extracted.length}</div>
          <div className="k">carved files</div>
        </div>
      </div>

      <div className="hint" style={{ marginBottom: 14 }}>▸ {report.filetype}</div>

      {report.summary.length > 0 && (
        <>
          <h4 className="ws-h">What stands out</h4>
          <div className="hints">
            {report.summary.map((s, i) => <div className="hint" key={i}>▸ {s}</div>)}
          </div>
        </>
      )}

      {report.extracted.length > 0 && (
        <>
          <h4 className="ws-h">Files carved out — analyse these next</h4>
          <div className="param-cloud">
            {report.extracted.map((f) => <span key={f} className="tag">{f}</span>)}
          </div>
        </>
      )}

      <h4 className="ws-h">Tool output</h4>
      {report.steps.map((s, i) => (
        <details className="issue" key={i}>
          <summary>
            <span className="sev" style={{ background: s.ok ? "var(--lime)" : "var(--ink-3)" }}>
              {s.ok ? "ok" : "skip"}
            </span>
            <span className="ttl">
              <span className="n">{s.name}</span>
              <span className="h mono">{s.tool}{s.note ? ` · ${s.note}` : ""}</span>
            </span>
          </summary>
          <div className="body">
            <pre>{s.output || s.note || "(no output)"}</pre>
          </div>
        </details>
      ))}
    </>
  );
}

/* -------------------------------- text -------------------------------- */

function TextMode() {
  const [text, setText] = useState("");
  const [caesar, setCaesar] = useState(false);
  const run = useMutation({ mutationFn: () => api.decode(text, caesar) });

  return (
    <>
      <div className="field">
        <label>Encoded text <span className="hint">— peels layers automatically</span></label>
        <textarea value={text} style={{ minHeight: 110 }} spellCheck={false}
          placeholder="paste base64, hex, binary, rot13… nested is fine"
          onChange={(e) => setText(e.target.value)} />
      </div>
      <div className="row">
        <label className="toggle-row">
          <input type="checkbox" checked={caesar} onChange={(e) => setCaesar(e.target.checked)} />
          also show all 25 Caesar shifts
        </label>
        <span style={{ flex: 1 }} />
        <button className="btn sm" disabled={!text.trim() || run.isPending}
          onClick={() => run.mutate()}>
          {run.isPending ? "Decoding…" : "Decode"}
        </button>
      </div>

      {run.data && (
        <>
          {run.data.flags.length > 0 && (
            <div className="flagbox">
              <h4>Flag candidates</h4>
              {run.data.flags.map((f) => <code key={f} className="cmd">{f}</code>)}
            </div>
          )}

          <h4 className="ws-h">Decoded layers ({run.data.chains.length})</h4>
          {run.data.chains.length === 0 && (
            <div className="empty">Nothing decoded to readable text.</div>
          )}
          {run.data.chains.map((c, i) => (
            <div className="param" key={i} style={{ flexDirection: "column", alignItems: "stretch" }}>
              <span className="pname mono">{c.chain}</span>
              <code className="cmd" onClick={() => navigator.clipboard.writeText(c.output)}>
                {c.output}
              </code>
            </div>
          ))}

          {run.data.caesar.length > 0 && (
            <>
              <h4 className="ws-h">Caesar shifts</h4>
              {run.data.caesar.map((c) => (
                <div className="param" key={c.shift}>
                  <span className="pname mono">ROT{c.shift}</span>
                  <span className="pwhy mono">{c.output}</span>
                </div>
              ))}
            </>
          )}
        </>
      )}
    </>
  );
}

/* --------------------------------- RSA -------------------------------- */

function RsaMode() {
  const [n, setN] = useState("");
  const [e, setE] = useState("65537");
  const [c, setC] = useState("");
  const [other, setOther] = useState("");
  const run = useMutation({
    mutationFn: () => api.rsa({
      n, e, c,
      other_n: other.split(/[\s,]+/).filter(Boolean),
    }),
  });

  return (
    <>
      <div className="field">
        <label>n <span className="hint">— modulus, decimal or 0x hex</span></label>
        <textarea value={n} spellCheck={false} style={{ minHeight: 70 }}
          onChange={(ev) => setN(ev.target.value)} />
      </div>
      <div className="row">
        <div className="field" style={{ maxWidth: 160 }}>
          <label>e</label>
          <input value={e} onChange={(ev) => setE(ev.target.value)} />
        </div>
        <div className="field">
          <label>c <span className="hint">— optional ciphertext</span></label>
          <input value={c} onChange={(ev) => setC(ev.target.value)} />
        </div>
      </div>
      <div className="field">
        <label>Other moduli <span className="hint">— to check for a shared factor</span></label>
        <textarea value={other} spellCheck={false}
          onChange={(ev) => setOther(ev.target.value)} />
      </div>
      <button className="btn sm" disabled={!n.trim() || run.isPending}
        onClick={() => run.mutate()}>
        {run.isPending ? "Analysing…" : "Analyse"}
      </button>

      {run.isError && <div className="error">{(run.error as Error).message}</div>}

      {run.data && (
        <>
          <div className="hint" style={{ margin: "16px 0" }}>
            ▸ {run.data.bits}-bit modulus, e = {run.data.e}
          </div>
          {run.data.findings.map((f, i) => (
            <div className="lead" key={i}>
              <div className="top"><span className="area">{f.issue}</span></div>
              <p className="why">{f.why}</p>
              {f.recovered && (
                <code className="cmd">recovered: {f.recovered}</code>
              )}
              {f.p && <code className="cmd">p = {f.p}</code>}
              {f.q && <code className="cmd">q = {f.q}</code>}
              {f.next && <code className="cmd">{f.next}</code>}
            </div>
          ))}
        </>
      )}
    </>
  );
}
