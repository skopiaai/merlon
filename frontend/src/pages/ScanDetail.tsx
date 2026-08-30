import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, scanSocket, SEVERITY_COLOR, type Severity } from "../api";

interface LogLine { level: string; stage: string; message: string; ts: string; }

export default function ScanDetail({ id, onBack }: { id: number; onBack: () => void }) {
  const qc = useQueryClient();
  const [lines, setLines] = useState<LogLine[]>([]);
  const [showDebug, setShowDebug] = useState(false);
  const [report, setReport] = useState<string | null>(null);
  const consoleRef = useRef<HTMLDivElement>(null);

  const scan = useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.getScan(id),
    refetchInterval: (q) => (q.state.data?.state === "running" ? 2000 : false),
  });

  const findings = useQuery({
    queryKey: ["findings", id],
    queryFn: () => api.listFindings({ scan_id: id }),
    refetchInterval: scan.data?.state === "running" ? 4000 : false,
  });

  // seed the console from history, then stream
  useEffect(() => {
    api.scanLogs(id).then(setLines).catch(() => {});
    return scanSocket(id, (e) => {
      if (e.type === "log") {
        setLines((l) => [...l.slice(-800), e]);
      } else if (e.type === "stage" || e.type === "state") {
        qc.invalidateQueries({ queryKey: ["scan", id] });
      } else if (e.type === "finding") {
        qc.invalidateQueries({ queryKey: ["findings", id] });
      }
    });
  }, [id, qc]);

  useEffect(() => {
    const el = consoleRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines]);

  const cancel = useMutation({
    mutationFn: () => api.cancelScan(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scan", id] }),
  });

  const s = scan.data;
  const visible = lines.filter((l) => showDebug || l.level !== "debug");
  const bySeverity = (findings.data ?? []).reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <>
      <button className="btn ghost sm" onClick={onBack} style={{ marginBottom: 14 }}>← Scans</button>
      <h2>Scan #{id}</h2>
      <p className="subtitle">{s?.seeds.join(", ")} · {s?.profile}</p>

      {s?.error && <div className="banner err"><strong>Failed:</strong> {s.error}</div>}

      {!!s?.rejected_hosts?.length && (
        <div className="banner warn">
          <strong>{s.rejected_hosts.length} host(s) filtered as out of scope.</strong>{" "}
          This is the scope guard working — discovered hosts that didn't match your allowlist were
          dropped before any traffic reached them.
          <details style={{ marginTop: 8 }}>
            <summary style={{ cursor: "pointer" }}>Show them</summary>
            <div className="mono" style={{ fontSize: 11, marginTop: 6, maxHeight: 160, overflowY: "auto" }}>
              {s.rejected_hosts.slice(0, 200).map((r, i) => (
                <div key={i}>{r.host} — {r.reason} ({r.stage})</div>
              ))}
            </div>
          </details>
        </div>
      )}

      <div className="card">
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
          <div>
            <span className="pill" style={{
              background:
                s?.state === "running" ? "var(--accent)" :
                s?.state === "completed" ? "var(--ok)" :
                s?.state === "failed" ? "var(--danger)" : "var(--muted)",
            }}>{s?.state}</span>
            <span className="muted" style={{ marginLeft: 10 }}>{s?.stage_current}</span>
          </div>
          <div className="row">
            {s?.state === "running" && (
              <button className="btn danger sm" onClick={() => cancel.mutate()}>Cancel</button>
            )}
            <button className="btn ghost sm" onClick={() => api.scanReport(id).then(setReport)}>
              Generate report
            </button>
          </div>
        </div>
        <div className="progress"><div style={{ width: `${(s?.progress ?? 0) * 100}%` }} /></div>
      </div>

      <div className="card">
        <h3>Results</h3>
        <div className="stat-grid">
          {(["critical", "high", "medium", "low", "info"] as Severity[]).map((sev) => (
            <div className="stat" key={sev}>
              <div className="v" style={{ color: SEVERITY_COLOR[sev] }}>{bySeverity[sev] ?? 0}</div>
              <div className="k">{sev}</div>
            </div>
          ))}
          {Object.entries(s?.stats ?? {})
            .filter(([k]) => k !== "findings_by_severity")
            .map(([k, v]) => (
              <div className="stat" key={k}>
                <div className="v">{String(v)}</div>
                <div className="k">{k.replace(/_/g, " ")}</div>
              </div>
            ))}
        </div>
      </div>

      <div className="card">
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 10 }}>
          <h3 style={{ margin: 0 }}>Live console</h3>
          <label style={{ fontSize: 12, color: "var(--muted)", display: "flex", gap: 6 }}>
            <input type="checkbox" style={{ width: "auto" }}
              checked={showDebug} onChange={(e) => setShowDebug(e.target.checked)} />
            show tool output
          </label>
        </div>
        <div className="console" ref={consoleRef}>
          {visible.length === 0 && <span className="muted">waiting…</span>}
          {visible.map((l, i) => (
            <div key={i} className={`l-${l.level}`}>
              <span style={{ opacity: 0.45 }}>{new Date(l.ts).toLocaleTimeString()} </span>
              {l.stage && <span style={{ opacity: 0.6 }}>[{l.stage}] </span>}
              {l.message}
            </div>
          ))}
        </div>
      </div>

      {report !== null && (
        <>
          <div className="overlay" onClick={() => setReport(null)} />
          <div className="drawer">
            <div className="row" style={{ justifyContent: "space-between", marginBottom: 14 }}>
              <h3 style={{ margin: 0 }}>Summary report</h3>
              <div className="row">
                <button className="btn ghost sm" onClick={() => navigator.clipboard.writeText(report)}>
                  Copy
                </button>
                <button className="btn ghost sm" onClick={() => setReport(null)}>Close</button>
              </div>
            </div>
            <pre style={{ maxHeight: "80vh" }}>{report}</pre>
          </div>
        </>
      )}
    </>
  );
}
