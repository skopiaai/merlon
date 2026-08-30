import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api";

const STAGES = [
  { id: "subfinder", label: "Subdomain enum", note: "passive — no traffic to target" },
  { id: "naabu", label: "Port discovery", note: "TCP connect scan" },
  { id: "httpx", label: "HTTP probe", note: "required" },
  { id: "katana", label: "Crawl endpoints", note: "slower, better nuclei coverage" },
  { id: "nuclei", label: "Nuclei templates", note: "the detection pass" },
  { id: "triage", label: "LLM triage", note: "needs Ollama running" },
];

export default function Scans({ onOpen }: { onOpen: (id: number) => void }) {
  const qc = useQueryClient();
  const [engagementId, setEngagementId] = useState<number | "">("");
  const [seeds, setSeeds] = useState("");
  const [profile, setProfile] = useState("standard");
  const [stages, setStages] = useState<string[]>(["subfinder", "naabu", "httpx", "nuclei", "triage"]);
  const [err, setErr] = useState("");
  const [preview, setPreview] = useState<{ input: string; allowed: boolean; reason: string }[] | null>(null);

  const engagements = useQuery({ queryKey: ["engagements"], queryFn: api.listEngagements });
  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.listScans(),
    refetchInterval: 4000,
  });

  const seedList = () => seeds.split(/[\n,\s]+/).map((s) => s.trim()).filter(Boolean);

  const dryRun = useMutation({
    mutationFn: () => api.checkScope(Number(engagementId), seedList()),
    onSuccess: (r) => { setPreview(r.results); setErr(""); },
    onError: (e: Error) => setErr(e.message),
  });

  const launch = useMutation({
    mutationFn: () =>
      api.createScan({
        engagement_id: Number(engagementId),
        seeds: seedList(),
        profile,
        stages,
      }),
    onSuccess: (s) => {
      setErr("");
      setPreview(null);
      qc.invalidateQueries({ queryKey: ["scans"] });
      onOpen(s.id);
    },
    onError: (e: Error) => setErr(e.message),
  });

  const toggleStage = (id: string) =>
    setStages((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));

  const ready = engagementId !== "" && seedList().length > 0;

  return (
    <>
      <h2>Scans</h2>
      <p className="subtitle">Launch a run, then watch it live.</p>

      <div className="card">
        <h3>New scan</h3>
        {err && <div className="banner err">{err}</div>}

        <div className="row">
          <div className="field">
            <label>Engagement</label>
            <select value={engagementId} onChange={(e) => setEngagementId(Number(e.target.value) || "")}>
              <option value="">Select…</option>
              {engagements.data?.map((e) => (
                <option key={e.id} value={e.id}>{e.name}</option>
              ))}
            </select>
          </div>
          <div className="field" style={{ maxWidth: 200 }}>
            <label>Profile</label>
            <select value={profile} onChange={(e) => setProfile(e.target.value)}>
              <option value="passive">Passive — no active probing</option>
              <option value="standard">Standard — top 100 ports</option>
              <option value="thorough">Thorough — top 1000, all severities</option>
            </select>
          </div>
        </div>

        <div className="field">
          <label>
            Seed targets
            <span className="hint"> — domains or IPs, one per line. Must match the engagement scope.</span>
          </label>
          <textarea value={seeds} onChange={(e) => setSeeds(e.target.value)}
            placeholder={"example.com\napi.example.com"} />
        </div>

        <div className="field">
          <label>Stages</label>
          <div className="row" style={{ gap: 16 }}>
            {STAGES.map((s) => (
              <label key={s.id} style={{ display: "flex", gap: 7, alignItems: "flex-start",
                                          fontSize: 13, textTransform: "none", letterSpacing: 0,
                                          color: "var(--text)", cursor: "pointer", minWidth: 0 }}>
                <input type="checkbox" style={{ width: "auto", marginTop: 2 }}
                  checked={stages.includes(s.id)} onChange={() => toggleStage(s.id)} />
                <span>
                  {s.label}
                  <div className="muted" style={{ fontSize: 11 }}>{s.note}</div>
                </span>
              </label>
            ))}
          </div>
        </div>

        {preview && (
          <div className={preview.every((p) => p.allowed) ? "banner ok" : "banner warn"}>
            {preview.map((p) => (
              <div key={p.input} className="mono" style={{ fontSize: 12 }}>
                {p.allowed ? "✓" : "✗"} {p.input} — {p.reason}
              </div>
            ))}
          </div>
        )}

        <div className="row">
          <button className="btn ghost" disabled={!ready || dryRun.isPending}
            onClick={() => dryRun.mutate()}>
            Check scope first
          </button>
          <button className="btn" disabled={!ready || launch.isPending}
            onClick={() => launch.mutate()}>
            {launch.isPending ? "Starting…" : "Launch scan"}
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Recent scans</h3>
        {!scans.data?.length && <div className="empty">Nothing yet.</div>}
        {!!scans.data?.length && (
          <table>
            <thead>
              <tr><th>#</th><th>Targets</th><th>Profile</th><th>State</th><th>Progress</th><th>Started</th></tr>
            </thead>
            <tbody>
              {scans.data.map((s) => (
                <tr key={s.id} className="clickable" onClick={() => onOpen(s.id)}>
                  <td className="mono">{s.id}</td>
                  <td>{s.seeds.join(", ")}</td>
                  <td className="muted">{s.profile}</td>
                  <td>
                    <span className="pill" style={{
                      background:
                        s.state === "running" ? "var(--accent)" :
                        s.state === "completed" ? "var(--ok)" :
                        s.state === "failed" ? "var(--danger)" : "var(--muted)",
                    }}>{s.state}</span>
                  </td>
                  <td style={{ minWidth: 120 }}>
                    <div className="progress"><div style={{ width: `${s.progress * 100}%` }} /></div>
                    <div className="muted" style={{ fontSize: 11, marginTop: 3 }}>{s.stage_current || "—"}</div>
                  </td>
                  <td className="muted">
                    {s.started_at ? new Date(s.started_at).toLocaleString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
