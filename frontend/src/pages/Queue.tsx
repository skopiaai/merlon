import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type QueueEntry } from "../api";
import { SEV_HEX } from "../plain";

/**
 * The submission queue.
 *
 * Sorted by whether a finding reproduces, not by how severe it claims to be.
 * That ordering is the whole point: a critical that doesn't reproduce is worth
 * less than nothing, because filing it costs acceptance rate — and in 2026,
 * with programs buried under machine-generated reports, acceptance rate is
 * what decides how quickly anything else you send gets read.
 *
 * Nothing here is hidden. A finding that failed verification is still listed,
 * with the reason. The tool's job is to tell you what it can and can't stand
 * behind, not to decide for you.
 */
export default function Queue({ scanId }: { scanId: number }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState<number | null>(null);

  const queue = useQuery({
    queryKey: ["queue", scanId],
    queryFn: () => api.submissionQueue(scanId),
  });

  const recheck = useMutation({
    mutationFn: (id: number) => api.verifyFinding(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["queue", scanId] }),
  });

  if (queue.isLoading) return <div className="empty">Loading queue…</div>;
  const q = queue.data;
  if (!q) return null;

  const pct = (v: number | null) =>
    v === null || v === undefined ? "—" : `${Math.round(v * 100)}%`;

  const Row = ({ f, tone }: { f: QueueEntry; tone: string }) => (
    <>
      <tr className="clickable" onClick={() => setOpen(open === f.id ? null : f.id)}>
        <td>
          <span className="pill" style={{ background: SEV_HEX[f.severity] }}>
            {f.severity}
          </span>
        </td>
        <td>
          {f.is_new === false ? (
            <span className="seen" title={`First seen ${f.first_seen?.slice(0, 10)}`}>
              seen before
            </span>
          ) : (
            <span className="fresh">new</span>
          )}{" "}
          {f.name}
          <div className="muted mono" style={{ fontSize: 10.5 }}>{f.host}</div>
        </td>
        <td className="mono">{f.engine}</td>
        <td>
          <span className={`conf ${tone}`}>{pct(f.confidence)}</span>
        </td>
        <td className="muted" style={{ fontSize: 11 }}>{f.why || "verified"}</td>
        <td>
          <button className="btn sm ghost" disabled={recheck.isPending}
            onClick={(e) => { e.stopPropagation(); recheck.mutate(f.id); }}>
            Re-check
          </button>
        </td>
      </tr>
      {open === f.id && (
        <tr>
          <td colSpan={6} className="reasons">
            <strong>How this was scored</strong>
            <ul>
              {(f.reasons ?? []).map((r, i) => <li key={i}>{r}</li>)}
            </ul>
            <a className="btn sm ghost" target="_blank" rel="noreferrer"
              href={`/api/findings/${f.id}/evidence`}>
              Reproduction block
            </a>{" "}
            <a className="btn sm ghost" target="_blank" rel="noreferrer"
              href={`/api/findings/${f.id}/disclosure`}>
              Full report
            </a>
          </td>
        </tr>
      )}
    </>
  );

  const Section = ({ title, blurb, rows, tone }: {
    title: string; blurb: string; rows: QueueEntry[]; tone: string;
  }) =>
    rows.length === 0 ? null : (
      <div className="card" style={{ padding: 0, marginBottom: 16 }}>
        <div style={{ padding: "14px 16px 4px" }}>
          <h3 style={{ margin: 0 }}>{title} <span className="muted">({rows.length})</span></h3>
          <p className="subtitle" style={{ margin: "6px 0 8px" }}>{blurb}</p>
        </div>
        <table>
          <thead>
            <tr>
              <th style={{ width: 84 }}>Severity</th>
              <th>Finding</th>
              <th style={{ width: 110 }}>Engine</th>
              <th style={{ width: 90 }}>Confidence</th>
              <th style={{ width: 230 }}>Verification</th>
              <th style={{ width: 90 }}></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => <Row key={f.id} f={f} tone={tone} />)}
          </tbody>
        </table>
      </div>
    );

  return (
    <>
      <h2>Submission queue</h2>
      <p className="subtitle">
        Ordered by whether each finding <strong>reproduces</strong>, not by how
        severe it claims to be. Every entry was independently re-tested after the
        scan: fetched again, fetched a second time to rule out a fluke, and
        compared against a control request. A critical that doesn't reproduce
        costs you more to file than it's worth.
        {q.counts.seen_before > 0 && (
          <> Findings marked <span className="seen">seen before</span> appeared in
          an earlier scan of this engagement — you have already read and decided
          about them.</>
        )}
      </p>

      <div className="stat-grid" style={{ marginBottom: 18 }}>
        <div className="stat">
          <div className="v" style={{ color: "var(--lime)" }}>{q.counts.ready}</div>
          <div className="k">ready to submit</div>
        </div>
        <div className="stat">
          <div className="v" style={{ color: "var(--amber)" }}>{q.counts.needs_review}</div>
          <div className="k">needs your eyes</div>
        </div>
        <div className="stat">
          <div className="v" style={{ color: "var(--crit)" }}>{q.counts.did_not_reproduce}</div>
          <div className="k">did not reproduce</div>
        </div>
        <div className="stat">
          <div className="v" style={{ color: "var(--neon)" }}>{q.counts.new}</div>
          <div className="k">new since last scan</div>
        </div>
        <div className="stat">
          <div className="v">{Math.round(q.threshold * 100)}%</div>
          <div className="k">bar to clear</div>
        </div>
      </div>

      <Section
        title="Ready to submit"
        tone="good"
        blurb="Reproduced on retest with evidence a triager can follow. Open one for
               the captured request, response, hash and timestamp."
        rows={q.ready}
      />

      <Section
        title="Needs your eyes"
        tone="warn"
        blurb="Real enough to keep, not proven enough to send unreviewed. Usually
               thin evidence, or a host that answers every request the same way so
               the result isn't specific to what was reported."
        rows={q.needs_review}
      />

      <Section
        title="Did not reproduce"
        tone="bad"
        blurb="Detected during the scan but gone on retest. Sometimes the target
               changed, sometimes it was a transient. Not deleted — but do not
               file these without confirming them yourself first."
        rows={q.did_not_reproduce}
      />

      {q.counts.total === 0 && (
        <div className="empty">No findings in this scan.</div>
      )}
    </>
  );
}
