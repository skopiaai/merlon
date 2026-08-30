import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Lead, type LeadStatus, type SurfaceMap } from "../api";

const STATUS_LABEL: Record<LeadStatus, string> = {
  todo: "to do",
  testing: "testing",
  confirmed: "found",
  clear: "clear",
  skipped: "skipped",
};

const STATUS_ORDER: LeadStatus[] = ["todo", "testing", "confirmed", "clear", "skipped"];

/**
 * The hunting workspace. Two halves:
 *   - LEADS: what to test, tracked with status and notes so progress persists
 *   - SURFACE: the deterministic map — categories, parameters, IDOR candidates
 */
export default function Workspace({ scanId, intel }: { scanId: number; intel?: any }) {
  const [view, setView] = useState<"leads" | "surface">("leads");
  const [hideDone, setHideDone] = useState(true);

  const leads = useQuery({ queryKey: ["leads", scanId], queryFn: () => api.leads(scanId) });
  const surface = useQuery({ queryKey: ["surface", scanId], queryFn: () => api.surface(scanId) });

  const qc = useQueryClient();
  const reanalyze = useMutation({
    mutationFn: () => api.reanalyze(scanId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["leads", scanId] });
      qc.invalidateQueries({ queryKey: ["surface", scanId] });
    },
  });

  const all = leads.data ?? [];
  const open = all.filter((l) => l.status === "todo" || l.status === "testing");
  const shown = hideDone ? open : all;
  const done = all.length - open.length;

  if (!all.length && !surface.data?.total_urls) return null;

  return (
    <div className="intel">
      <div className="ws-head">
        <div>
          <h3>◆ Hunting workspace</h3>
          {intel?.summary && <p className="lede">{intel.summary}</p>}
        </div>
        <div className="ws-tabs">
          <button className={view === "leads" ? "on" : ""} onClick={() => setView("leads")}>
            Leads {open.length ? `(${open.length})` : ""}
          </button>
          <button className={view === "surface" ? "on" : ""} onClick={() => setView("surface")}>
            Surface map
          </button>
        </div>
      </div>

      {view === "leads" ? (
        <>
          {all.length > 0 && (
            <div className="ws-bar">
              <div className="ws-progress">
                <div style={{ width: `${all.length ? (done / all.length) * 100 : 0}%` }} />
              </div>
              <span className="ws-count">{done}/{all.length} checked</span>
              <label className="ws-toggle">
                <input type="checkbox" checked={hideDone}
                  onChange={(e) => setHideDone(e.target.checked)} />
                hide completed
              </label>
            </div>
          )}

          {shown.length === 0 ? (
            <div className="ws-empty">
              {all.length ? "All leads worked through. Nice." : "No leads generated."}
              <div style={{ marginTop: 12 }}>
                <button className="btn ghost sm" onClick={() => reanalyze.mutate()}
                  disabled={reanalyze.isPending}>
                  {reanalyze.isPending ? "Analysing…" : "Re-run analysis"}
                </button>
              </div>
            </div>
          ) : (
            shown.map((l) => <LeadCard key={l.id} lead={l} scanId={scanId} />)
          )}

          {!!intel?.blind_spots?.length && (
            <div className="blind">
              <b>Not covered by this scan:</b> {intel.blind_spots.join(" · ")}
            </div>
          )}
          {!!intel?.notable?.length && (
            <div className="blind"><b>Worth a second look:</b> {intel.notable.join(" · ")}</div>
          )}
        </>
      ) : (
        <SurfacePanel map={surface.data} />
      )}
    </div>
  );
}

/* ------------------------------- lead card ------------------------------- */

function LeadCard({ lead, scanId }: { lead: Lead; scanId: number }) {
  const qc = useQueryClient();
  const [openNotes, setOpenNotes] = useState(false);
  const [notes, setNotes] = useState(lead.notes);
  const [dive, setDive] = useState(lead.deep_dive);

  const invalidate = () => qc.invalidateQueries({ queryKey: ["leads", scanId] });

  const update = useMutation({
    mutationFn: (body: Partial<Lead>) => api.updateLead(lead.id, body as any),
    onSuccess: invalidate,
  });

  const deepDive = useMutation({
    mutationFn: () => api.deepDive(lead.id),
    onSuccess: (r) => setDive(r.deep_dive),
  });

  return (
    <div className={`lead status-${lead.status}`}>
      <div className="top">
        <span className={`prio ${lead.priority}`}>{lead.priority}</span>
        <span className="area mono">{lead.area}</span>
        {lead.vuln_class && <span className="vclass">{lead.vuln_class}</span>}
        {lead.source === "surface" && <span className="src">mapped</span>}
      </div>

      <p className="why">{lead.why}</p>
      <p className="check">{lead.check}</p>

      <div className="lead-actions">
        {STATUS_ORDER.map((s) => (
          <button key={s}
            className={`sbtn ${lead.status === s ? "on" : ""} s-${s}`}
            onClick={() => update.mutate({ status: s })}>
            {STATUS_LABEL[s]}
          </button>
        ))}
        <span style={{ flex: 1 }} />
        <button className="sbtn" onClick={() => setOpenNotes((v) => !v)}>
          notes{lead.notes ? " •" : ""}
        </button>
        {!dive && (
          <button className="sbtn" onClick={() => deepDive.mutate()} disabled={deepDive.isPending}>
            {deepDive.isPending ? "thinking…" : "deep dive"}
          </button>
        )}
      </div>

      {openNotes && (
        <textarea className="lead-notes" value={notes} placeholder="What you tried, what you saw…"
          onChange={(e) => setNotes(e.target.value)}
          onBlur={() => notes !== lead.notes && update.mutate({ notes })} />
      )}

      {deepDive.isError && (
        <div className="lead-err">
          {(deepDive.error as Error).message}
        </div>
      )}

      {dive && (
        <details className="dive" open>
          <summary>test plan</summary>
          <div className="dive-body">
            {dive.split("\n").map((line, i) => {
              if (line.startsWith("## ")) return <h5 key={i}>{line.slice(3)}</h5>;
              if (line.startsWith("- ")) return <div className="li" key={i}>{line.slice(2)}</div>;
              if (!line.trim()) return null;
              return <p key={i}>{line}</p>;
            })}
          </div>
        </details>
      )}
    </div>
  );
}

/* ------------------------------ surface map ------------------------------ */

function SurfacePanel({ map }: { map?: SurfaceMap }) {
  const [openCat, setOpenCat] = useState<string | null>(null);
  if (!map) return <div className="ws-empty">Loading map…</div>;
  if (!map.total_urls) return <div className="ws-empty">No endpoints mapped.</div>;

  return (
    <>
      {!!map.hints?.length && (
        <div className="hints">
          {map.hints.map((h, i) => <div key={i} className="hint">▸ {h}</div>)}
        </div>
      )}

      <h4 className="ws-h">Endpoint categories — {map.total_urls} mapped</h4>
      <div className="catgrid">
        {map.categories.map((c) => (
          <button key={c.category}
            className={`cat ${openCat === c.category ? "on" : ""}`}
            onClick={() => setOpenCat(openCat === c.category ? null : c.category)}>
            <span className="cat-n">{c.count}</span>
            <span className="cat-t">{c.category}</span>
          </button>
        ))}
      </div>

      {openCat && (() => {
        const c = map.categories.find((x) => x.category === openCat)!;
        return (
          <div className="cat-detail">
            <p className="why">{c.why}</p>
            <div style={{ margin: "8px 0" }}>
              {c.vuln_classes.map((v) => <span key={v} className="vclass">{v}</span>)}
            </div>
            <div className="urls">
              {c.urls.map((u) => <div key={u} className="mono">{u}</div>)}
            </div>
          </div>
        );
      })()}

      {!!map.params_interesting.length && (
        <>
          <h4 className="ws-h">Parameters worth testing</h4>
          {map.params_interesting.map((p) => (
            <div className="param" key={p.name}>
              <span className="pname mono">{p.name}</span>
              <span className="vclass">{p.class}</span>
              <span className="pwhy">{p.why}</span>
              <span className="pcount">×{p.count}</span>
            </div>
          ))}
        </>
      )}

      {!!map.idor_candidates.length && (
        <>
          <h4 className="ws-h">Identifiers in paths — {map.idor_candidates.length}</h4>
          {map.idor_candidates.slice(0, 12).map((i) => (
            <div className="param" key={i.url}>
              <span className="pname mono" style={{ flex: 1 }}>{i.url}</span>
              <span className="vclass">{i.kind}</span>
            </div>
          ))}
          <div className="blind">
            {map.idor_candidates[0].why}
          </div>
        </>
      )}

      {!!map.auth_boundaries.length && (
        <>
          <h4 className="ws-h">Permission boundaries — {map.auth_boundaries.length}</h4>
          {map.auth_boundaries.slice(0, 12).map((b) => (
            <div className="param" key={b.url}>
              <span className="pname mono" style={{ flex: 1 }}>{b.url}</span>
              <span className="vclass">HTTP {b.status}</span>
            </div>
          ))}
        </>
      )}

      {!!map.params_other.length && (
        <>
          <h4 className="ws-h">Other parameters observed</h4>
          <div className="param-cloud">
            {map.params_other.map((p) => <span key={p} className="tag">{p}</span>)}
          </div>
        </>
      )}
    </>
  );
}
