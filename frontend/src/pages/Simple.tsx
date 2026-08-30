import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, scanSocket, type Finding, type Scan } from "../api";
import { explain, SEV_HEX, SEV_ORDER, verdict } from "../plain";
import Workspace from "../components/Workspace";

const DEPTHS = [
  { id: "sprint", t: "Sprint", d: "~2 min · critical & high only — for when being first matters" },
  { id: "quick", t: "Quick", d: "~5 min · main site, TLS, high-severity checks" },
  { id: "standard", t: "Standard", d: "~10 min · subdomains, DNS, full header audit" },
  { id: "deep", t: "Deep", d: "25 min+ · ports, services, fuzzing, crawl, everything" },
] as const;

type Depth = (typeof DEPTHS)[number]["id"];

// Fallback only — live labels come from /api/system/engines, so a new
// engine names itself here without a frontend change.
const STEP_LABELS: Record<string, string> = {
  seed: "Validating target scope",
  subfinder: "Enumerating subdomains",
  dnsx: "Resolving DNS records",
  cdncheck: "Fingerprinting CDN / WAF",
  naabu: "Scanning ports",
  httpx: "Probing live services",
  nmap: "Identifying services and versions",
  tlsx: "Auditing TLS certificates",
  ffuf: "Fuzzing for hidden paths",
  katana: "Crawling endpoints",
  nuclei: "Running vulnerability templates",
  correlate: "Correlating attack paths",
  triage: "AI reviewing findings",
  intel: "AI mapping attack surface",
  done: "Complete",
};

export default function Simple() {
  const [scanId, setScanId] = useState<number | null>(null);
  return scanId === null
    ? <Home onStart={setScanId} />
    : <Live id={scanId} onReset={() => setScanId(null)} />;
}

/* --------------------------- content freshness --------------------------- */

/**
 * Detection content age, shown before a scan rather than buried in settings.
 *
 * Templates are the scanner. Running week-old ones means walking past whatever
 * was published since, which in a bug bounty is the difference between finding
 * something and reading about someone else finding it. So this sits directly
 * above the Execute button and says so when it's stale.
 */
function Freshness() {
  const qc = useQueryClient();
  const status = useQuery({
    queryKey: ["update"],
    queryFn: api.updateStatus,
    refetchInterval: (q) => (q.state.data?.running ? 3000 : 60_000),
  });

  const run = useMutation({
    mutationFn: () => api.runUpdate(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["update"] }),
  });

  const s = status.data;
  if (!s) return null;

  const age = s.age_seconds;
  const when =
    age === null || age === undefined ? "never"
      : age < 3600 ? `${Math.round(age / 60)} min ago`
      : age < 86400 ? `${Math.round(age / 3600)} h ago`
      : `${Math.round(age / 86400)} d ago`;

  const templates = s.sources
    .filter((x) => x.kind === "templates")
    .reduce((n, x) => n + x.items, 0);
  const failed = s.sources.filter((x) => !x.ok);

  return (
    <div className={`freshness ${s.stale ? "stale" : ""}`}>
      <div className="fresh-main">
        <span className="dot" />
        <span>
          {s.running ? (
            <>Updating detection content…</>
          ) : s.stale ? (
            <><strong>Templates are stale</strong> — last updated {when}. New checks
              are published daily; the ones you don't have are the ones nobody
              has reported yet.</>
          ) : (
            <>Detection content current — updated {when}
              {templates > 0 && <>, {templates.toLocaleString()} templates loaded</>}.</>
          )}
        </span>
      </div>

      <button type="button" className="btn sm" disabled={s.running || run.isPending}
        onClick={() => run.mutate()}>
        {s.running || run.isPending ? "Updating…" : "Update now"}
      </button>

      {!!failed.length && !s.running && (
        <div className="fresh-detail">
          {failed.length} source{failed.length > 1 ? "s" : ""} unavailable:{" "}
          {failed.map((f) => f.name).join(", ")} — everything else updated.
        </div>
      )}
      {s.auto_daily && !s.running && (
        <div className="fresh-detail muted">
          Runs automatically every 24 hours.
        </div>
      )}
    </div>
  );
}

/* ------------------------------ home ------------------------------ */

function Home({ onStart }: { onStart: (id: number) => void }) {
  const [target, setTarget] = useState("");
  const [depth, setDepth] = useState<Depth>("standard");
  const [subs, setSubs] = useState(true);
  const [ok, setOk] = useState(false);
  const [err, setErr] = useState("");

  const qc = useQueryClient();
  const recent = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.listScans(),
    refetchInterval: 10_000,
  });

  const cancel = useMutation({
    mutationFn: (id: number) => api.cancelScan(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });

  const start = useMutation({
    mutationFn: () =>
      api.quickScan({ target: target.trim(), depth, include_subdomains: subs, authorized: ok }),
    onSuccess: (s) => onStart(s.id),
    onError: (e: Error) => setErr(e.message),
  });

  const ready = target.trim().length > 2 && ok && !start.isPending;

  return (
    <>
      <div className="hero">
        <h1>Target <span className="accent">Acquisition</span></h1>
        <p>
          Enter a host you own or are authorized to test. Recon, vulnerability
          scanning, and AI attack-surface analysis in one pass.
        </p>
      </div>

      <form className="searchbox" onSubmit={(e) => { e.preventDefault(); if (ready) start.mutate(); }}>
        <input
          value={target}
          onChange={(e) => { setTarget(e.target.value); setErr(""); }}
          placeholder="example.com"
          autoFocus
          spellCheck={false}
        />
        <button className="btn" disabled={!ready}>
          {start.isPending ? "Initializing…" : "Execute"}
        </button>
      </form>

      <div className="depths">
        {DEPTHS.map((d) => (
          <button key={d.id} type="button"
            className={`depth ${depth === d.id ? "on" : ""}`}
            onClick={() => setDepth(d.id)}>
            <span className="t">{d.t}</span>
            <span className="d">{d.d}</span>
          </button>
        ))}
      </div>

      {depth !== "quick" && depth !== "sprint" && (
        <div className="toggle-row">
          <input id="subs" type="checkbox" checked={subs} onChange={(e) => setSubs(e.target.checked)} />
          <label htmlFor="subs">Include subdomains of {target.trim() || "the target"}</label>
        </div>
      )}

      <Freshness />

      <div className="consent">
        <input id="ok" type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} />
        <label htmlFor="ok">
          <strong>Authorization confirmed.</strong> I own this target or hold written
          permission to test it. Unauthorized scanning is a criminal offence in most
          jurisdictions, including under India's IT Act. For a college or employer system,
          get it in writing first.
        </label>
      </div>

      {err && <div className="error">{err}</div>}

      {!!recent.data?.length && (
        <div className="history">
          <h2>Previous runs</h2>
          {recent.data.slice(0, 8).map((s) => {
            const active = s.state === "running" || s.state === "queued";
            // A scan still "running" hours later isn't running — the backend
            // restarted under it. Offer a way out rather than leaving it stuck.
            const stale = active && s.started_at
              ? Date.now() - new Date(s.started_at).getTime() > 3 * 60 * 60 * 1000
              : active && !s.started_at;
            return (
              <div key={s.id} className="hrow-wrap">
                <button className="hrow" onClick={() => onStart(s.id)}>
                  <span className="h-target">{s.seeds.join(", ")}</span>
                  <span className="h-count">
                    {s.state === "completed"
                      ? `${Object.values((s.stats?.findings_by_severity as Record<string, number>) ?? {})
                          .reduce((a, b) => a + b, 0)} findings`
                      : s.state}
                    {stale && <span className="stale"> stuck</span>}
                  </span>
                  <span className="h-when">
                    {s.started_at ? new Date(s.started_at).toLocaleDateString() : "—"}
                  </span>
                </button>
                {active && (
                  <button className="sbtn s-kill" title="Stop this scan"
                    onClick={() => cancel.mutate(s.id)} disabled={cancel.isPending}>
                    stop
                  </button>
                )}
              </div>
            );
          })}
          {cancel.isSuccess && (
            <div className="note" style={{ marginTop: 10 }}>{cancel.data.message}</div>
          )}
        </div>
      )}
    </>
  );
}

/* --------------------------- live + results --------------------------- */

function Live({ id, onReset }: { id: number; onReset: () => void }) {
  const qc = useQueryClient();
  const [log, setLog] = useState<string[]>([]);
  const [livePct, setLivePct] = useState<number | null>(null);
  const logRef = useRef<HTMLPreElement>(null);

  const scan = useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.getScan(id),
    refetchInterval: (q) =>
      ["queued", "running"].includes(q.state.data?.state ?? "") ? 3000 : false,
  });

  const findings = useQuery({
    queryKey: ["findings", id],
    queryFn: () => api.listFindings({ scan_id: id }),
    refetchInterval: scan.data?.state === "running" ? 6000 : false,
  });

  useEffect(() => {
    api.scanLogs(id)
      .then((ls) => setLog(ls.filter((l) => l.level !== "debug").map((l) => l.message)))
      .catch(() => {});
    return scanSocket(id, (e) => {
      if (e.type === "log" && e.level !== "debug") setLog((l) => [...l.slice(-400), e.message]);
      else if (e.type === "progress") setLivePct(e.progress);
      else if (e.type === "stage") { setLivePct(e.progress); qc.invalidateQueries({ queryKey: ["scan", id] }); }
      else if (e.type === "state") qc.invalidateQueries({ queryKey: ["scan", id] });
      else if (e.type === "finding") qc.invalidateQueries({ queryKey: ["findings", id] });
    });
  }, [id, qc]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log]);

  const s = scan.data;
  if (!s) return <div className="runcard">Establishing link…</div>;

  const running = s.state === "queued" || s.state === "running";
  return running
    ? <Running scan={s} log={log} logRef={logRef} count={findings.data?.length ?? 0}
               pct={livePct ?? s.progress} />
    : <Results scan={s} findings={findings.data ?? []} onReset={onReset} />;
}

function Running({ scan, log, logRef, count, pct }: {
  scan: Scan; log: string[]; logRef: React.RefObject<HTMLPreElement>;
  count: number; pct: number;
}) {
  const meta = useQuery({ queryKey: ["engines"], queryFn: api.engines, staleTime: 300_000 });
  const labels = { ...STEP_LABELS, ...(meta.data?.labels ?? {}) };
  const order = ["seed", ...scan.stages, "correlate"];
  if (scan.stages.includes("triage")) order.push("intel");
  const idx = order.indexOf(scan.stage_current);
  const shown = Math.min(99, Math.max(0, Math.round(pct * 100)));

  return (
    <div className="runcard">
      <div className="runhead">
        <h2>Scanning {scan.seeds.join(", ")}</h2>
        <p>{scan.profile} profile · safe to leave this page open</p>
      </div>

      <div className="pctwrap">
        <div className="pct">{shown}<span>%</span></div>
        <div className="pct-sub">{labels[scan.stage_current] ?? scan.stage_current}</div>
      </div>

      <div className="bar"><div style={{ width: `${Math.max(2, shown)}%` }} /></div>

      <div className="steps" style={{ marginTop: 22 }}>
        {order.map((st, i) => {
          const state = idx < 0 ? "" : i < idx ? "done" : i === idx ? "active" : "";
          return (
            <div className={`step ${state}`} key={st}>
              <span className="ic">{state === "done" ? "✓" : i + 1}</span>
              <span className="label">{labels[st] ?? st}</span>
              {state === "active" && <span className="meta">running</span>}
            </div>
          );
        })}
      </div>

      <div className="livecount">
        <div><div className="n">{count}</div><div className="k">findings</div></div>
        <div><div className="n">{String((scan.stats as any)?.hosts_in_scope ?? "–")}</div><div className="k">hosts</div></div>
        <div><div className="n">{String((scan.stats as any)?.live_services ?? "–")}</div><div className="k">services</div></div>
        <div><div className="n">{String((scan.stats as any)?.open_ports ?? "–")}</div><div className="k">ports</div></div>
      </div>

      <details className="rawlog">
        <summary>│ raw output</summary>
        <pre ref={logRef}>{log.join("\n") || "initializing…"}</pre>
      </details>
    </div>
  );
}

function Results({ scan, findings, onReset }: {
  scan: Scan; findings: Finding[]; onReset: () => void;
}) {
  const [filter, setFilter] = useState<string>("all");
  const [report, setReport] = useState<string | null>(null);

  const real = findings.filter((f) => f.status !== "false_positive");
  const counts = real.reduce<Record<string, number>>((a, f) => {
    a[f.severity] = (a[f.severity] ?? 0) + 1;
    return a;
  }, {});
  const v = verdict(counts);
  const total = real.length;
  const shown = filter === "all" ? real : real.filter((f) => f.severity === filter);
  const hiddenFP = findings.length - real.length;
  const intel = (scan.stats as any)?.intel;

  if (scan.state === "failed") {
    return (
      <>
        <div className="error" style={{ marginTop: 0 }}>
          <strong>Scan aborted.</strong> {scan.error}
        </div>
        <div className="actions"><button className="btn ghost" onClick={onReset}>← New target</button></div>
      </>
    );
  }

  return (
    <>
      <div className="scoreboard">
        <div className="verdict">
          <span className="big" style={{
            color: v.grade === "✓" ? "var(--lime)" : v.grade === "!" ? "var(--crit)" : "var(--med)",
          }}>{v.grade}</span>
          <div className="txt">
            <h2>{v.title}</h2>
            <p>{scan.seeds.join(", ")} — {v.line}</p>
          </div>
        </div>

        {total > 0 && (
          <>
            <div className="sevbar">
              {SEV_ORDER.map((s) => counts[s] ? (
                <span key={s} style={{ background: SEV_HEX[s], width: `${(counts[s] / total) * 100}%` }} />
              ) : null)}
            </div>
            <div className="sevkey">
              {SEV_ORDER.filter((s) => counts[s]).map((s) => (
                <span key={s}><i style={{ background: SEV_HEX[s] }} />{counts[s]} {s}</span>
              ))}
            </div>
          </>
        )}

        <div className="actions">
          <button className="btn ghost sm" onClick={onReset}>← New target</button>
          <button className="btn ghost sm" onClick={() => api.scanReport(scan.id).then(setReport)}>
            Summary report
          </button>
          <button className="btn ghost sm" onClick={() => api.auditReport(scan.id).then(setReport)}>
            Audit report
          </button>
        </div>
      </div>

      <Workspace scanId={scan.id} intel={intel} />

      {total === 0 ? (
        <div className="clean">
          <div className="tick">✓</div>
          <h3>No known issues detected</h3>
          <p>
            The automated checks found nothing — which means no <em>known</em> vulnerability
            patterns matched. Logic flaws, broken access control and IDORs need a human.
            Start with the attack surface analysis above.
          </p>
        </div>
      ) : (
        <>
          <div className="filters">
            <button className={`chip ${filter === "all" ? "on" : ""}`} onClick={() => setFilter("all")}>
              all {total}
            </button>
            {SEV_ORDER.filter((s) => counts[s]).map((s) => (
              <button key={s} className={`chip ${filter === s ? "on" : ""}`} onClick={() => setFilter(s)}>
                {s} {counts[s]}
              </button>
            ))}
          </div>

          {shown.map((f) => {
            const p = explain(f);
            return (
              <details className="issue" key={f.id}>
                <summary>
                  <span className="sev" style={{ background: SEV_HEX[f.severity] }}>{f.severity}</span>
                  <span className="ttl">
                    <span className="n">{f.name}</span>
                    <span className="w">{p.what}</span>
                    <span className="h mono">{f.url || f.host}</span>
                  </span>
                </summary>
                <div className="body">
                  <h4>Impact</h4>
                  <p>{p.what}</p>

                  <h4>Remediation</h4>
                  <div className="fix">{p.fix}</div>

                  {f.triage_note && (<><h4>AI analysis</h4>
                    <p style={{ whiteSpace: "pre-wrap" }}>{f.triage_note}</p></>)}

                  {f.evidence && (<><h4>Evidence</h4><pre>{f.evidence}</pre></>)}

                  {!!f.references.length && (<><h4>References</h4>
                    <div className="reflist">
                      {f.references.slice(0, 4).map((r) => (
                        <div key={r}><a href={r} target="_blank" rel="noreferrer noopener">{r}</a></div>
                      ))}
                    </div></>)}

                  <div className="actions">
                    <button className="btn ghost sm" onClick={() => api.disclosure(f.id).then(setReport)}>
                      Draft disclosure
                    </button>
                  </div>
                </div>
              </details>
            );
          })}

          {hiddenFP > 0 && (
            <div className="note">
              {hiddenFP} result{hiddenFP === 1 ? "" : "s"} suppressed as likely false positives by
              AI triage. Still visible in the Console tab.
            </div>
          )}
        </>
      )}

      <div className="note">
        Automated scanning covers <em>known</em> patterns — missing headers, outdated software,
        exposed files, published CVEs. It structurally cannot find business logic flaws, broken
        access control, or IDORs, which is where most bounty payouts come from. Use this to clear
        known ground fast, then hunt manually using the leads above.
      </div>

      {report !== null && (
        <>
          <div className="modal-bg" onClick={() => setReport(null)} />
          <div className="modal">
            <div className="actions" style={{ justifyContent: "flex-end", marginTop: 0, marginBottom: 14 }}>
              <button className="btn ghost sm" onClick={() => navigator.clipboard.writeText(report)}>Copy</button>
              <button className="btn ghost sm" onClick={() => setReport(null)}>Close</button>
            </div>
            <pre>{report}</pre>
          </div>
        </>
      )}
    </>
  );
}
