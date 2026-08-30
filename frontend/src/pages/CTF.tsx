import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Challenge, type ChallengeStatus } from "../api";
import Analyzer from "../components/Analyzer";

const STATUSES: ChallengeStatus[] = ["todo", "working", "stuck", "solved", "abandoned"];

/**
 * Competition workspace: challenge board, per-category arsenal, countdown.
 * Built for the Terrier Cyber Quest format — Jeopardy qualifier, then a
 * 36-hour finale graded on methodology as well as findings.
 */
export default function CTF() {
  const [view, setView] = useState<"board" | "analyzer" | "arsenal" | "event">("board");

  return (
    <div className="pro">
      <div className="pro-nav">
        <button className={view === "board" ? "on" : ""} onClick={() => setView("board")}>
          Challenge board
        </button>
        <button className={view === "analyzer" ? "on" : ""} onClick={() => setView("analyzer")}>
          Analyzer
        </button>
        <button className={view === "arsenal" ? "on" : ""} onClick={() => setView("arsenal")}>
          Arsenal
        </button>
        <button className={view === "event" ? "on" : ""} onClick={() => setView("event")}>
          Event
        </button>
      </div>

      {view === "board" && <Board />}
      {view === "analyzer" && <Analyzer />}
      {view === "arsenal" && <Arsenal />}
      {view === "event" && <EventPanel />}
    </div>
  );
}

/* ------------------------------- board ------------------------------- */

function Board() {
  const qc = useQueryClient();
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<Challenge | null>(null);

  const arsenal = useQuery({ queryKey: ["arsenal"], queryFn: api.ctfArsenal });
  const challenges = useQuery({ queryKey: ["challenges"], queryFn: () => api.challenges() });
  const stats = useQuery({ queryKey: ["ctfstats"], queryFn: api.ctfStats });

  const cats = arsenal.data?.categories ?? {};
  const shown = (challenges.data ?? []).filter((c) => !filter || c.category === filter);

  const create = useMutation({
    mutationFn: api.createChallenge,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["challenges"] });
      qc.invalidateQueries({ queryKey: ["ctfstats"] });
    },
  });

  const [form, setForm] = useState({ name: "", category: "web", points: 0, assignee: "" });

  return (
    <>
      <h2>Challenge board</h2>
      <p className="subtitle">
        Track what each of you is on. Notes here feed the writeup generator —
        the finale is graded on methodology, so write as you go.
      </p>

      {stats.data && (
        <div className="stat-grid" style={{ marginBottom: 16 }}>
          <div className="stat">
            <div className="v">{stats.data.solved}/{stats.data.total}</div>
            <div className="k">solved</div>
          </div>
          <div className="stat">
            <div className="v">{stats.data.points}</div>
            <div className="k">points</div>
          </div>
          {Object.entries(stats.data.by_category).map(([cat, s]) => (
            <div className="stat" key={cat}>
              <div className="v" style={{ color: cats[cat]?.colour }}>
                {s.solved}/{s.total}
              </div>
              <div className="k">{cats[cat]?.label ?? cat}</div>
            </div>
          ))}
        </div>
      )}

      <div className="card">
        <h3>Add challenge</h3>
        <div className="row">
          <div className="field" style={{ flex: 2 }}>
            <label>Name</label>
            <input value={form.name} placeholder="e.g. baby-rsa"
              onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </div>
          <div className="field" style={{ maxWidth: 170 }}>
            <label>Category</label>
            <select value={form.category}
              onChange={(e) => setForm({ ...form, category: e.target.value })}>
              {Object.entries(cats).map(([k, c]) => (
                <option key={k} value={k}>{c.label}</option>
              ))}
            </select>
          </div>
          <div className="field" style={{ maxWidth: 110 }}>
            <label>Points</label>
            <input type="number" value={form.points}
              onChange={(e) => setForm({ ...form, points: Number(e.target.value) })} />
          </div>
          <div className="field" style={{ maxWidth: 150 }}>
            <label>Assignee</label>
            <input value={form.assignee} placeholder="who's on it"
              onChange={(e) => setForm({ ...form, assignee: e.target.value })} />
          </div>
          <div className="field" style={{ maxWidth: 110, marginBottom: 14 }}>
            <label>&nbsp;</label>
            <button className="btn sm" disabled={!form.name.trim() || create.isPending}
              onClick={() => { create.mutate({ ...form }); setForm({ ...form, name: "", points: 0 }); }}>
              Add
            </button>
          </div>
        </div>
      </div>

      <div className="filters">
        <button className={`chip ${!filter ? "on" : ""}`} onClick={() => setFilter("")}>
          all
        </button>
        {Object.entries(cats).map(([k, c]) => (
          <button key={k} className={`chip ${filter === k ? "on" : ""}`}
            onClick={() => setFilter(k)}>{c.label}</button>
        ))}
      </div>

      {shown.length === 0 ? (
        <div className="empty">No challenges yet. Add them as they're released.</div>
      ) : (
        <div className="card" style={{ padding: 0 }}>
          <table>
            <thead>
              <tr>
                <th style={{ width: 90 }}>Status</th>
                <th>Challenge</th>
                <th style={{ width: 130 }}>Category</th>
                <th style={{ width: 70 }}>Pts</th>
                <th style={{ width: 110 }}>Who</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((c) => (
                <tr key={c.id} className="clickable" onClick={() => setOpen(c)}>
                  <td>
                    <span className="pill" style={{
                      background: c.status === "solved" ? "var(--lime)"
                        : c.status === "working" ? "var(--neon)"
                        : c.status === "stuck" ? "var(--crit)" : "var(--ink-3)",
                    }}>{c.status}</span>
                  </td>
                  <td>
                    {c.name}
                    {c.flag && <div className="muted mono" style={{ fontSize: 10.5 }}>flag captured</div>}
                  </td>
                  <td style={{ color: cats[c.category]?.colour }}>
                    {cats[c.category]?.label ?? c.category}
                  </td>
                  <td>{c.points || "—"}</td>
                  <td className="muted">{c.assignee || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {open && <ChallengeDrawer challenge={open} onClose={() => setOpen(null)}
                                cats={cats} />}
    </>
  );
}

function ChallengeDrawer({ challenge, onClose, cats }: {
  challenge: Challenge; onClose: () => void; cats: any;
}) {
  const qc = useQueryClient();
  const [notes, setNotes] = useState(challenge.notes);
  const [flag, setFlag] = useState(challenge.flag);
  const [impact, setImpact] = useState(challenge.impact);
  const [writeup, setWriteup] = useState(challenge.writeup);

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["challenges"] });
    qc.invalidateQueries({ queryKey: ["ctfstats"] });
  };
  const update = useMutation({
    mutationFn: (body: any) => api.updateChallenge(challenge.id, body),
    onSuccess: invalidate,
  });
  const draft = useMutation({
    mutationFn: () => api.challengeWriteup(challenge.id),
    onSuccess: setWriteup,
  });
  const remove = useMutation({
    mutationFn: () => api.deleteChallenge(challenge.id),
    onSuccess: () => { invalidate(); onClose(); },
  });

  const cat = cats[challenge.category];

  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="drawer">
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
          <span className="pill" style={{ background: cat?.colour ?? "var(--ink-3)" }}>
            {cat?.label ?? challenge.category}
          </span>
          <button className="btn ghost sm" onClick={onClose}>Close</button>
        </div>

        <h2 style={{ fontSize: 18, margin: "6px 0 14px" }}>{challenge.name}</h2>

        <div className="lead-actions" style={{ marginBottom: 16 }}>
          {STATUSES.map((s) => (
            <button key={s} className={`sbtn ${challenge.status === s ? "on" : ""} s-${s}`}
              onClick={() => update.mutate({ status: s })}>{s}</button>
          ))}
        </div>

        {cat?.triage && (
          <>
            <h4 className="ws-h">Triage order — {cat.label}</h4>
            <div className="dive-body">
              {cat.triage.map((t: string, i: number) => <div className="li" key={i}>{t}</div>)}
            </div>
          </>
        )}

        <div className="field" style={{ marginTop: 18 }}>
          <label>Working notes <span className="hint">— these become the writeup</span></label>
          <textarea value={notes} style={{ minHeight: 160 }}
            placeholder="What you tried, what happened, what worked…"
            onChange={(e) => setNotes(e.target.value)}
            onBlur={() => notes !== challenge.notes && update.mutate({ notes })} />
        </div>

        <div className="row">
          <div className="field">
            <label>Flag</label>
            <input value={flag} onChange={(e) => setFlag(e.target.value)}
              onBlur={() => flag !== challenge.flag && update.mutate({ flag })} />
          </div>
          <div className="field" style={{ maxWidth: 150 }}>
            <label>Severity (finale)</label>
            <select value={challenge.severity}
              onChange={(e) => update.mutate({ severity: e.target.value })}>
              <option value="">—</option>
              {["critical", "high", "medium", "low"].map((s) =>
                <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
        </div>

        <div className="field">
          <label>Impact</label>
          <textarea value={impact} placeholder="What an attacker achieves"
            onChange={(e) => setImpact(e.target.value)}
            onBlur={() => impact !== challenge.impact && update.mutate({ impact })} />
        </div>

        <div className="actions">
          <button className="btn sm" onClick={() => draft.mutate()} disabled={draft.isPending}>
            {draft.isPending ? "Drafting…" : "Generate writeup"}
          </button>
          {writeup && (
            <button className="btn ghost sm"
              onClick={() => navigator.clipboard.writeText(writeup)}>Copy</button>
          )}
          <span style={{ flex: 1 }} />
          <button className="btn ghost sm" onClick={() => remove.mutate()}>Delete</button>
        </div>

        {writeup && <pre style={{ marginTop: 14 }}>{writeup}</pre>}
      </div>
    </>
  );
}

/* ------------------------------ arsenal ------------------------------ */

function Arsenal() {
  const arsenal = useQuery({ queryKey: ["arsenal"], queryFn: api.ctfArsenal });
  const [open, setOpen] = useState<string>("web");
  const [copied, setCopied] = useState("");

  const cats = arsenal.data?.categories ?? {};
  const cat = cats[open];

  const copy = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopied(cmd);
    setTimeout(() => setCopied(""), 1200);
  };

  return (
    <>
      <h2>Arsenal</h2>
      <p className="subtitle">
        Triage order, commands and recurring patterns. Click any command to copy it.
      </p>

      <div className="filters">
        {Object.entries(cats).map(([k, c]) => (
          <button key={k} className={`chip ${open === k ? "on" : ""}`}
            onClick={() => setOpen(k)}>{c.label}</button>
        ))}
      </div>

      {cat && (
        <>
          <div className="hint" style={{ marginBottom: 16 }}>▸ {cat.summary}</div>

          <h4 className="ws-h">Triage order</h4>
          <div className="dive-body">
            {cat.triage.map((t: string, i: number) => (
              <div className="li" key={i}>{t}</div>
            ))}
          </div>

          <h4 className="ws-h">Tools</h4>
          {cat.tools.map((t: any) => (
            <div className="param" key={t.name} style={{ flexDirection: "column", alignItems: "stretch" }}>
              <div style={{ display: "flex", gap: 10, alignItems: "baseline" }}>
                <span className="pname mono">{t.name}</span>
                <span className="pwhy">{t.for}</span>
              </div>
              <code className="cmd" onClick={() => copy(t.cmd)}
                title="Click to copy">
                {copied === t.cmd ? "copied ✓" : t.cmd}
              </code>
            </div>
          ))}

          <h4 className="ws-h">Recurring patterns</h4>
          <div className="dive-body">
            {cat.patterns.map((p: string, i: number) => (
              <div className="li" key={i}>{p}</div>
            ))}
          </div>
        </>
      )}
    </>
  );
}

/* ------------------------------- event ------------------------------- */

function EventPanel() {
  const arsenal = useQuery({ queryKey: ["arsenal"], queryFn: api.ctfArsenal });
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(t);
  }, []);

  const ev = arsenal.data?.event;
  if (!ev) return <div className="empty">Loading…</div>;

  const next = ev.milestones.find((m) => new Date(m.date).getTime() > now);
  const daysTo = (d: string) =>
    Math.ceil((new Date(d).getTime() - now) / 86_400_000);

  return (
    <>
      <h2>{ev.name}</h2>
      <p className="subtitle">{ev.organiser}</p>

      {next && (
        <div className="runcard" style={{ marginBottom: 18 }}>
          <div className="pctwrap">
            <div className="pct">{daysTo(next.date)}<span> days</span></div>
            <div className="pct-sub">until {next.label}</div>
          </div>
        </div>
      )}

      <div className="card">
        <h3>Timeline</h3>
        <table>
          <tbody>
            {ev.milestones.map((m) => {
              const d = daysTo(m.date);
              return (
                <tr key={m.label}>
                  <td style={{ width: 210 }}>
                    <strong>{m.label}</strong>
                    <div className="muted" style={{ fontSize: 11 }}>{m.note}</div>
                  </td>
                  <td className="mono">{m.date}</td>
                  <td className="muted" style={{ width: 100 }}>
                    {d > 0 ? `in ${d}d` : "passed"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h3>Graded on</h3>
        <div className="dive-body">
          {ev.scoring.map((s) => <div className="li" key={s}>{s}</div>)}
        </div>
      </div>

      <div className="card">
        <h3>Before the day</h3>
        <div className="dive-body">
          {ev.prep.map((s) => <div className="li" key={s}>{s}</div>)}
        </div>
      </div>

      <div className="banner warn">
        <strong>Rules you agreed to at registration:</strong>
        <div className="dive-body" style={{ marginTop: 6 }}>
          {ev.rules.map((r) => <div className="li" key={r}>{r}</div>)}
        </div>
      </div>

      <a className="btn ghost sm" href={ev.url} target="_blank" rel="noreferrer noopener">
        Event page ↗
      </a>
    </>
  );
}
