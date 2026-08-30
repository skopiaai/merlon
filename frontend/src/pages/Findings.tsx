import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, SEVERITY_COLOR, type Finding } from "../api";
import FindingDrawer from "../components/FindingDrawer";

const STATUSES = [
  ["", "All statuses"],
  ["new", "New"],
  ["triaging", "Needs review"],
  ["confirmed", "Confirmed"],
  ["false_positive", "False positive"],
  ["reported", "Reported"],
  ["fixed", "Fixed"],
] as const;

export default function Findings() {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<Finding | null>(null);

  const findings = useQuery({
    queryKey: ["findings", "all", severity, status, q],
    queryFn: () => api.listFindings({ severity, status, q }),
  });

  return (
    <>
      <h2>Findings</h2>
      <p className="subtitle">
        Sorted by severity, then triage confidence. Anything the model flagged as needing a human
        sits at the top of its band.
      </p>

      <div className="card">
        <div className="row">
          <div className="field" style={{ maxWidth: 170 }}>
            <label>Severity</label>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="critical,high">Critical + High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>
          <div className="field" style={{ maxWidth: 190 }}>
            <label>Status</label>
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              {STATUSES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </div>
          <div className="field">
            <label>Search</label>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="name or host…" />
          </div>
        </div>
      </div>

      <div className="card">
        {findings.isLoading && <div className="empty">Loading…</div>}
        {findings.data?.length === 0 && <div className="empty">No findings match.</div>}
        {!!findings.data?.length && (
          <table>
            <thead>
              <tr>
                <th style={{ width: 90 }}>Severity</th>
                <th>Finding</th>
                <th>Host</th>
                <th style={{ width: 110 }}>Status</th>
                <th style={{ width: 90 }}>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {findings.data.map((f) => (
                <tr key={f.id} className="clickable" onClick={() => setOpen(f)}>
                  <td>
                    <span className="pill" style={{ background: SEVERITY_COLOR[f.severity] }}>
                      {f.severity}
                    </span>
                  </td>
                  <td>
                    {f.name}
                    <div className="muted mono" style={{ fontSize: 11 }}>
                      {f.engine}{f.rule_id ? ` · ${f.rule_id}` : ""}
                      {f.occurrences > 1 ? ` · ×${f.occurrences}` : ""}
                      {f.cve.length ? ` · ${f.cve.join(", ")}` : ""}
                    </div>
                  </td>
                  <td className="mono" style={{ fontSize: 12, wordBreak: "break-all" }}>
                    {f.url || f.host}
                  </td>
                  <td className="muted">{f.status.replace(/_/g, " ")}</td>
                  <td className="muted">
                    {f.triage_confidence !== null ? `${Math.round(f.triage_confidence * 100)}%` : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {open && <FindingDrawer finding={open} onClose={() => setOpen(null)} />}
    </>
  );
}
