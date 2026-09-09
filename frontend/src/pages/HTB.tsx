import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type HtbAction, type HtbMachine } from "../api";

/**
 * The Hack The Box workspace.
 *
 * The organising idea is that a box has a *current phase*, and at any moment
 * there is a short list of things worth doing. Everything here is subordinate
 * to that: the ranked actions are what you look at, and the rest is reference
 * you open when you need it.
 *
 * The hint ladder is deliberately a series of separate clicks rather than a
 * disclosure triangle. Asking for the answer should be a decision you make
 * four times, not something you reveal by accident and cannot un-see.
 */

const DIFFICULTIES = ["starting point", "easy", "medium", "hard", "insane"];

export default function HTB() {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<number | null>(null);
  const [tab, setTab] = useState<"work" | "privesc" | "flags">("work");

  const machines = useQuery({ queryKey: ["htb"], queryFn: api.htbMachines });
  const xp = useQuery({ queryKey: ["htb-xp"], queryFn: api.htbXp });

  const current = machines.data?.find((m) => m.id === selected) ?? null;

  return (
    <>
      <h2>Hack The Box</h2>
      <p className="subtitle">
        Point this at a box you have spawned on your own account. Every hint is
        worked out from your own scan of your own instance — there is no answer
        key here, because a stored flag would be wrong on respawn, against the
        rules, and worth nothing in the interview where the rank gets spent.
      </p>

      <StreakBar />

      <div className="htb-layout">
        <aside>
          <MachineList
            machines={machines.data ?? []}
            selected={selected}
            onSelect={(id) => { setSelected(id); setTab("work"); }}
          />
          <AddMachine onAdded={(m) => {
            qc.invalidateQueries({ queryKey: ["htb"] });
            setSelected(m.id);
          }} />
          <KnowledgePanel />
        </aside>

        <section>
          {!current ? (
            <div className="empty">
              Add a box to begin. Difficulty matters — it decides whether you
              are shown the everyday checks or the full Active Directory chain,
              and drowning an easy box in forest-level advice is how the obvious
              path gets missed.
            </div>
          ) : (
            <>
              <div className="htb-tabs">
                {(["work", "privesc", "flags"] as const).map((t) => (
                  <button key={t} className={tab === t ? "on" : ""}
                    onClick={() => setTab(t)}>
                    {t === "work" ? "Next steps"
                      : t === "privesc" ? "Privilege escalation"
                      : "Flags"}
                  </button>
                ))}
              </div>
              {tab === "work" && <Workspace machine={current} />}
              {tab === "privesc" && <PrivescPanel />}
              {tab === "flags" && <FlagPanel machine={current} />}
            </>
          )}
        </section>
      </div>
    </>
  );
}

/* ------------------------------------------------------------------ streak */

function StreakBar() {
  const xp = useQuery({ queryKey: ["htb-xp"], queryFn: api.htbXp });
  const s = xp.data?.streak;
  if (!s) return null;

  return (
    <div className={`freshness ${s.urgent ? "stale" : ""}`} style={{ marginBottom: 18 }}>
      <div className="fresh-main">
        <span className="dot" />
        <span>
          {s.safe ? (
            <>Weekly streak is <strong>safe</strong> — {s.xp_this_week} XP banked
              this week from boxes tracked here.</>
          ) : (
            <><strong>{s.xp_needed} XP</strong> needed before the week closes to
              keep your streak, and {Math.round(s.hours_left)} hours left to get
              it. {s.suggestion}</>
          )}
        </span>
      </div>
      <div className="fresh-detail muted">
        {xp.data?.rooted} rooted · {xp.data?.user_only} user-only ·{" "}
        {xp.data?.tracked_xp.toLocaleString()} XP from what you have logged here
        (a lower bound — it only counts boxes you added).
      </div>
    </div>
  );
}

/* ------------------------------------------------------------- machine list */

function MachineList({ machines, selected, onSelect }: {
  machines: HtbMachine[]; selected: number | null; onSelect: (id: number) => void;
}) {
  if (!machines.length) return null;
  return (
    <div className="card" style={{ padding: 0, marginBottom: 14 }}>
      <div style={{ padding: "12px 14px 2px" }}>
        <h3 style={{ margin: 0 }}>Boxes</h3>
      </div>
      <ul className="htb-machines">
        {machines.map((m) => (
          <li key={m.id} className={m.id === selected ? "on" : ""}
            onClick={() => onSelect(m.id)}>
            <div className="row">
              <strong>{m.name || m.host}</strong>
              <span className={`pill tier-${m.difficulty.replace(" ", "-")}`}>
                {m.difficulty}
              </span>
            </div>
            <div className="muted mono" style={{ fontSize: 10.5 }}>
              {m.host} · {m.phase}
              {m.root_flag ? " · rooted" : m.user_flag ? " · user" : ""}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function AddMachine({ onAdded }: { onAdded: (m: HtbMachine) => void }) {
  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [difficulty, setDifficulty] = useState("easy");
  const [os, setOs] = useState("linux");

  const add = useMutation({
    mutationFn: () => api.htbCreate({ name, host, difficulty, os, state: "active" }),
    onSuccess: (m) => { setName(""); setHost(""); onAdded(m); },
  });

  return (
    <div className="card" style={{ marginBottom: 14 }}>
      <h3 style={{ marginTop: 0 }}>Add a box</h3>
      <label>Name
        <input value={name} onChange={(e) => setName(e.target.value)}
          placeholder="Optional" />
      </label>
      <label>Address
        <input value={host} onChange={(e) => setHost(e.target.value)}
          placeholder="10.10.11.55" />
      </label>
      <label>Difficulty
        <select value={difficulty} onChange={(e) => setDifficulty(e.target.value)}>
          {DIFFICULTIES.map((d) => <option key={d} value={d}>{d}</option>)}
        </select>
      </label>
      <label>OS
        <select value={os} onChange={(e) => setOs(e.target.value)}>
          <option value="linux">Linux</option>
          <option value="windows">Windows</option>
        </select>
      </label>
      <button className="btn" disabled={!host || add.isPending}
        onClick={() => add.mutate()}>
        {add.isPending ? "Adding…" : "Add"}
      </button>
      {add.isError && <p className="err">{String(add.error)}</p>}
    </div>
  );
}

/* -------------------------------------------------------------- knowledge */

function KnowledgePanel() {
  const qc = useQueryClient();
  const ref = useQuery({ queryKey: ["htb-ref"], queryFn: api.htbReference });
  const update = useMutation({
    mutationFn: api.htbKnowledgeUpdate,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["htb-ref"] }),
  });

  const k = ref.data?.knowledge ?? {};
  const gtfo = k.gtfobins?.entries ?? 0;
  const lolbas = k.lolbas?.entries ?? 0;

  return (
    <div className="card">
      <h3 style={{ marginTop: 0 }}>Privesc knowledge</h3>
      <p className="subtitle" style={{ marginTop: 0 }}>
        {gtfo || lolbas ? (
          <>{gtfo} GTFOBins and {lolbas} LOLBAS entries loaded. Paste{" "}
            <code>sudo -l</code> output and get the exact escalation instead of
            a link to go and read.</>
        ) : (
          <>Not downloaded yet. Without it the privesc tab can only tell you
            what to look for, not what to run.</>
        )}
      </p>
      <button className="btn sm" disabled={update.isPending}
        onClick={() => update.mutate()}>
        {update.isPending ? "Updating…" : "Update knowledge"}
      </button>
      {update.data && (
        <ul className="muted" style={{ fontSize: 11, marginBottom: 0 }}>
          {update.data.sources.map((s) => (
            <li key={s.name}>{s.name}: {s.detail}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

/* -------------------------------------------------------------- workspace */

function Workspace({ machine }: { machine: HtbMachine }) {
  const qc = useQueryClient();
  const next = useQuery({
    queryKey: ["htb-next", machine.id],
    queryFn: () => api.htbNext(machine.id),
  });

  const recon = useMutation({
    mutationFn: (full: boolean) => api.htbRecon(machine.id, full),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["htb"] });
      qc.invalidateQueries({ queryKey: ["htb-next", machine.id] });
    },
  });

  const mark = useMutation({
    mutationFn: (body: Partial<HtbMachine>) => api.htbUpdate(machine.id, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["htb"] });
      qc.invalidateQueries({ queryKey: ["htb-next", machine.id] });
      qc.invalidateQueries({ queryKey: ["htb-xp"] });
    },
  });

  const phases = next.data?.phases ?? [];
  const here = next.data?.phase ?? machine.phase;

  return (
    <>
      <div className="card">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <div>
            <h3 style={{ margin: 0 }}>{machine.name || machine.host}</h3>
            <span className="muted mono">{machine.host}</span>
          </div>
          <div>
            <button className="btn sm" disabled={recon.isPending}
              onClick={() => recon.mutate(false)}>
              {recon.isPending ? "Scanning…" : "Quick scan"}
            </button>{" "}
            <button className="btn sm ghost" disabled={recon.isPending}
              onClick={() => recon.mutate(true)}
              title="All 65535 ports — the step people skip and lose two hours to">
              Full sweep
            </button>
          </div>
        </div>

        {recon.data?.warning && (
          <p className="warn-box">{recon.data.warning}</p>
        )}
        {recon.data?.hosts_file && (
          <p className="subtitle">
            Add this to <code>/etc/hosts</code> — the web app is served by name,
            not by address, and scanning the IP shows you a different site:
            <br />
            <code>{recon.data.hosts_file}</code>
          </p>
        )}

        <div className="phase-strip">
          {phases.map((p) => (
            <span key={p.key}
              className={`phase ${p.key === here ? "on" : ""}`}
              title={`Done when: ${p.done_when}\nCommon trap: ${p.trap}`}>
              {p.label}
            </span>
          ))}
        </div>

        {!!machine.ports.length && (
          <table style={{ marginTop: 12 }}>
            <thead>
              <tr><th style={{ width: 70 }}>Port</th><th>Service</th><th>Version</th></tr>
            </thead>
            <tbody>
              {machine.ports.map((p) => (
                <tr key={p.port}>
                  <td className="mono">{p.port}</td>
                  <td>{p.service}</td>
                  <td className="muted">{[p.product, p.version].filter(Boolean).join(" ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="row" style={{ gap: 8, marginTop: 12, flexWrap: "wrap" }}>
          <button className="btn sm ghost"
            onClick={() => mark.mutate({ has_shell: !machine.has_shell })}>
            {machine.has_shell ? "✓ shell" : "Mark shell obtained"}
          </button>
          <button className="btn sm ghost"
            onClick={() => mark.mutate({ is_root: !machine.is_root })}>
            {machine.is_root ? "✓ root" : "Mark root obtained"}
          </button>
        </div>
      </div>

      <h3 style={{ marginTop: 22 }}>What to do next</h3>
      <p className="subtitle">
        Ordered by phase first and value second. There is no point suggesting a
        privilege-escalation check to someone who has not got a shell, however
        promising the service looks.
      </p>
      {(next.data?.actions ?? []).map((a) => (
        <ActionCard key={a.key} action={a} machineId={machine.id} />
      ))}
    </>
  );
}

function ActionCard({ action, machineId }: { action: HtbAction; machineId: number }) {
  const [level, setLevel] = useState(0);
  const [note, setNote] = useState("");
  const hint = useMutation({
    mutationFn: (n: number) => api.htbHint(machineId, n, action.key),
    onSuccess: (h) => {
      setLevel(h.level);
      // The backend answers a different question when this action's
      // prerequisites are not met. Say so rather than showing another
      // action's advice under this heading.
      setNote(h.substituted ? (h.note ?? "") : "");
    },
  });

  return (
    <div className={`card action ${action.current_phase ? "now" : ""}`}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h4 style={{ margin: 0 }}>{action.title}</h4>
        <span className="muted mono" style={{ fontSize: 10.5 }}>
          {action.phase}{action.tier !== "starting point" && ` · ${action.tier}+`}
        </span>
      </div>
      <p className="subtitle">{action.why}</p>

      <pre className="cmd">{action.commands.join("\n")}</pre>

      {!!action.look_for.length && (
        <p className="muted" style={{ fontSize: 11.5 }}>
          Look for: {action.look_for.join(" · ")}
        </p>
      )}

      <div className="ladder">
        {note && <p className="warn-box">{note}</p>}
        {level > 0 && !note && (
          <blockquote>
            {action.hints.slice(0, level).map((h, i) => (
              <p key={i}>
                <span className="rung">{["nudge", "direction", "technique", "exact command"][i]}</span>
                {h}
              </p>
            ))}
          </blockquote>
        )}
        {level < 4 && (
          <button className="btn sm ghost" disabled={hint.isPending}
            onClick={() => hint.mutate(level + 1)}>
            {level === 0 ? "Stuck? Give me a nudge"
              : level === 3 ? "Just tell me the command"
              : "More help"}
          </button>
        )}
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- privesc */

function PrivescPanel() {
  const [text, setText] = useState("");
  const sudo = useMutation({ mutationFn: () => api.htbSudo(text) });
  const triage = useMutation({ mutationFn: () => api.htbTriage(text) });

  return (
    <div className="card">
      <h3 style={{ marginTop: 0 }}>Paste what the box told you</h3>
      <p className="subtitle">
        <code>sudo -l</code>, <code>whoami /all</code>, a linpeas dump — anything.
        The sudo lookup joins each entry against GTFOBins so you get the command,
        not a reading list.
      </p>
      <textarea rows={8} value={text} onChange={(e) => setText(e.target.value)}
        placeholder="(root) NOPASSWD: /usr/bin/find" />
      <div className="row" style={{ gap: 8 }}>
        <button className="btn sm" disabled={!text || sudo.isPending}
          onClick={() => sudo.mutate()}>Look up sudo entries</button>
        <button className="btn sm ghost" disabled={!text || triage.isPending}
          onClick={() => triage.mutate()}>Triage everything</button>
      </div>

      {sudo.data?.entries.map((e) => (
        <div key={e.path} className={`card ${e.exploitable ? "" : "muted"}`}
          style={{ marginTop: 12 }}>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <strong className="mono">{e.path}</strong>
            <span className={`conf ${e.exploitable ? "good" : "warn"}`}>
              {e.exploitable ? "known escalation" : "not in GTFOBins"}
            </span>
          </div>
          {e.command ? <pre className="cmd">{e.command}</pre>
            : <p className="subtitle">{e.note}</p>}
        </div>
      ))}

      {triage.data?.hits.map((h, i) => (
        <div key={i} className="card" style={{ marginTop: 12 }}>
          <strong>{h.title}</strong>
          <p className="subtitle">{h.why}</p>
          <pre className="cmd">{h.command}</pre>
        </div>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ flags */

function FlagPanel({ machine }: { machine: HtbMachine }) {
  const qc = useQueryClient();
  const [text, setText] = useState("");
  const [source, setSource] = useState("cat /root/root.txt");
  const check = useMutation({ mutationFn: () => api.htbFlags(text, source) });
  const save = useMutation({
    mutationFn: (body: Partial<HtbMachine>) => api.htbUpdate(machine.id, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["htb"] });
      qc.invalidateQueries({ queryKey: ["htb-xp"] });
    },
  });

  return (
    <div className="card">
      <h3 style={{ marginTop: 0 }}>Flags</h3>
      <p className="subtitle">
        Thirty-two hex characters is the shape of a machine flag and also of
        every MD5 digest ever printed, so tell it where the text came from —
        that is what separates a captured flag from a checksum.
      </p>
      <label>Where did this come from?
        <input value={source} onChange={(e) => setSource(e.target.value)} />
      </label>
      <textarea rows={4} value={text} onChange={(e) => setText(e.target.value)}
        placeholder="Paste the output" />
      <button className="btn sm" disabled={!text || check.isPending}
        onClick={() => check.mutate()}>Check</button>

      {check.data?.flags.map((f) => (
        <div key={f.value} className="card" style={{ marginTop: 12 }}>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <code>{f.value}</code>
            <span className={`conf ${f.confidence > 0.9 ? "good" : "warn"}`}>
              {f.kind} · {Math.round(f.confidence * 100)}%
            </span>
          </div>
          <p className="subtitle">{f.why}</p>
          <button className="btn sm ghost"
            onClick={() => save.mutate(
              f.kind === "root" ? { root_flag: f.value } : { user_flag: f.value })}>
            Save as {f.kind === "root" ? "root" : "user"} flag
          </button>
        </div>
      ))}

      <div style={{ marginTop: 16 }}>
        <p className="muted" style={{ fontSize: 11.5 }}>
          user: <code>{machine.user_flag || "—"}</code><br />
          root: <code>{machine.root_flag || "—"}</code>
        </p>
      </div>
    </div>
  );
}
