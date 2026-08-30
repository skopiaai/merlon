import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, SEVERITY_COLOR, type Finding, type FindingStatus } from "../api";

const STATUS_OPTIONS: FindingStatus[] = [
  "new", "triaging", "confirmed", "false_positive", "accepted_risk", "reported", "fixed",
];

export default function FindingDrawer({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const qc = useQueryClient();
  const [note, setNote] = useState(finding.analyst_note);
  const [disclosure, setDisclosure] = useState<string | null>(null);

  const invalidate = () => qc.invalidateQueries({ queryKey: ["findings"] });

  const update = useMutation({
    mutationFn: (body: unknown) => api.updateFinding(finding.id, body),
    onSuccess: invalidate,
  });

  const retriage = useMutation({
    mutationFn: () => api.retriage(finding.id),
    onSuccess: invalidate,
  });

  const draft = useMutation({
    mutationFn: () => api.disclosure(finding.id),
    onSuccess: setDisclosure,
  });

  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="drawer">
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 6 }}>
          <span className="pill" style={{ background: SEVERITY_COLOR[finding.severity] }}>
            {finding.severity}
          </span>
          <button className="btn ghost sm" onClick={onClose}>Close</button>
        </div>

        <h2 style={{ fontSize: 17, margin: "8px 0" }}>{finding.name}</h2>
        <p className="mono muted" style={{ fontSize: 12, wordBreak: "break-all", marginTop: 0 }}>
          {finding.url || finding.host}
        </p>

        <div style={{ margin: "10px 0" }}>
          {finding.tags.map((t) => <span key={t} className="tag">{t}</span>)}
          {finding.cve.map((c) => <span key={c} className="tag" style={{ color: "var(--danger)" }}>{c}</span>)}
          {finding.cwe.map((c) => <span key={c} className="tag">{c}</span>)}
        </div>

        {finding.description && (
          <>
            <h3 style={{ fontSize: 13, marginBottom: 6 }}>Description</h3>
            <p style={{ lineHeight: 1.6, marginTop: 0 }}>{finding.description}</p>
          </>
        )}

        {finding.triage_note && (
          <>
            <h3 style={{ fontSize: 13, marginBottom: 6 }}>
              Triage notes{" "}
              <span className="muted" style={{ fontWeight: 400, fontSize: 11 }}>
                — local model, advisory only
              </span>
            </h3>
            <pre style={{ maxHeight: 220 }}>{finding.triage_note}</pre>
          </>
        )}

        {finding.remediation && (
          <>
            <h3 style={{ fontSize: 13, marginBottom: 6 }}>Recommended action</h3>
            <p style={{ lineHeight: 1.6, marginTop: 0 }}>{finding.remediation}</p>
          </>
        )}

        {finding.evidence && (
          <>
            <h3 style={{ fontSize: 13, marginBottom: 6 }}>Evidence</h3>
            <pre>{finding.evidence}</pre>
          </>
        )}

        {!!finding.references.length && (
          <>
            <h3 style={{ fontSize: 13, marginBottom: 6 }}>References</h3>
            <ul style={{ paddingLeft: 18, fontSize: 12, wordBreak: "break-all" }}>
              {finding.references.map((r) => <li key={r} className="mono muted">{r}</li>)}
            </ul>
          </>
        )}

        <hr style={{ border: 0, borderTop: "1px solid var(--border)", margin: "20px 0" }} />

        <div className="field">
          <label>Status</label>
          <select
            value={finding.status}
            onChange={(e) => update.mutate({ status: e.target.value })}
          >
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>{s.replace(/_/g, " ")}</option>
            ))}
          </select>
        </div>

        <div className="field">
          <label>Your notes</label>
          <textarea value={note} onChange={(e) => setNote(e.target.value)}
            onBlur={() => note !== finding.analyst_note && update.mutate({ analyst_note: note })}
            placeholder="What you verified manually, reproduction details, submission reference…" />
        </div>

        <div className="row">
          <button className="btn ghost sm" onClick={() => retriage.mutate()} disabled={retriage.isPending}>
            {retriage.isPending ? "Re-triaging…" : "Re-run triage"}
          </button>
          <button className="btn sm" onClick={() => draft.mutate()} disabled={draft.isPending}>
            {draft.isPending ? "Drafting…" : "Draft disclosure report"}
          </button>
        </div>
        {retriage.isError && (
          <div className="banner err" style={{ marginTop: 10 }}>
            {(retriage.error as Error).message}
          </div>
        )}

        {disclosure && (
          <>
            <div className="row" style={{ justifyContent: "space-between", margin: "18px 0 6px" }}>
              <h3 style={{ fontSize: 13, margin: 0 }}>Draft disclosure</h3>
              <button className="btn ghost sm" onClick={() => navigator.clipboard.writeText(disclosure)}>
                Copy
              </button>
            </div>
            <div className="banner warn" style={{ fontSize: 12 }}>
              Verify every claim in this draft against the actual evidence before you submit it.
              A report with a wrong detail costs you credibility with the program.
            </div>
            <pre style={{ maxHeight: 400 }}>{disclosure}</pre>
          </>
        )}
      </div>
    </>
  );
}
