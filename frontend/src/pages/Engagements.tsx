import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api";

const BLANK = {
  name: "",
  kind: "bug_bounty",
  authorized_by: "",
  authorization_ref: "",
  expires_at: "",
  allow_rules: "",
  deny_rules: "",
  notes: "",
};

export default function Engagements() {
  const qc = useQueryClient();
  const [form, setForm] = useState(BLANK);
  const [err, setErr] = useState("");

  const list = useQuery({ queryKey: ["engagements"], queryFn: api.listEngagements });

  const create = useMutation({
    mutationFn: api.createEngagement,
    onSuccess: () => {
      setForm(BLANK);
      setErr("");
      qc.invalidateQueries({ queryKey: ["engagements"] });
    },
    onError: (e: Error) => setErr(e.message),
  });

  const del = useMutation({
    mutationFn: api.deleteEngagement,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["engagements"] }),
  });

  const set = (k: keyof typeof BLANK) => (e: React.ChangeEvent<any>) =>
    setForm({ ...form, [k]: e.target.value });

  const splitRules = (s: string) =>
    s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    create.mutate({
      name: form.name,
      kind: form.kind,
      authorized_by: form.authorized_by,
      authorization_ref: form.authorization_ref,
      expires_at: form.expires_at ? new Date(form.expires_at).toISOString() : null,
      allow_rules: splitRules(form.allow_rules),
      deny_rules: splitRules(form.deny_rules),
      notes: form.notes,
    });
  };

  return (
    <>
      <h2>Engagements</h2>
      <p className="subtitle">
        Every scan belongs to an engagement. No engagement, no scan — that's the point.
      </p>

      <div className="banner warn">
        <strong>Before you create one:</strong> confirm you have permission in writing. For a bounty
        program, the program page is your authorization. For a college or employer system, that's an
        email from whoever owns it. Record the reference below so the paper trail lives with the data.
      </div>

      <div className="card">
        <h3>New engagement</h3>
        {err && <div className="banner err">{err}</div>}
        <form onSubmit={submit}>
          <div className="row">
            <div className="field">
              <label>Name</label>
              <input value={form.name} onChange={set("name")} placeholder="Acme public bounty" required />
            </div>
            <div className="field" style={{ maxWidth: 180 }}>
              <label>Type</label>
              <select value={form.kind} onChange={set("kind")}>
                <option value="bug_bounty">Bug bounty</option>
                <option value="internal">Internal / employer</option>
                <option value="ctf">CTF</option>
                <option value="lab">Own lab</option>
              </select>
            </div>
          </div>

          <div className="row">
            <div className="field">
              <label>Authorized by</label>
              <input
                value={form.authorized_by}
                onChange={set("authorized_by")}
                placeholder="HackerOne program / Dr. Rao, IT Services"
                required
              />
            </div>
            <div className="field">
              <label>
                Authorization reference
                <span className="hint"> — link, email subject, or ticket ID</span>
              </label>
              <input
                value={form.authorization_ref}
                onChange={set("authorization_ref")}
                placeholder="https://hackerone.com/acme  ·  RE: Permission to test, 2026-08-02"
                required
              />
            </div>
            <div className="field" style={{ maxWidth: 180 }}>
              <label>Expires</label>
              <input type="date" value={form.expires_at} onChange={set("expires_at")} />
            </div>
          </div>

          <div className="row">
            <div className="field">
              <label>
                In-scope rules
                <span className="hint"> — one per line: example.com, *.example.com, 10.0.0.0/24</span>
              </label>
              <textarea value={form.allow_rules} onChange={set("allow_rules")} required
                placeholder={"*.example.com\napi.example.org"} />
            </div>
            <div className="field">
              <label>
                Excluded
                <span className="hint"> — always wins over in-scope</span>
              </label>
              <textarea value={form.deny_rules} onChange={set("deny_rules")}
                placeholder={"payments.example.com\nlegacy.example.com"} />
            </div>
          </div>

          <div className="field">
            <label>Notes</label>
            <textarea value={form.notes} onChange={set("notes")}
              placeholder="Rate limits the program asks for, out-of-scope vuln classes, contact for questions…" />
          </div>

          <button className="btn" disabled={create.isPending}>
            {create.isPending ? "Creating…" : "Create engagement"}
          </button>
        </form>
      </div>

      <div className="card">
        <h3>Existing</h3>
        {list.isLoading && <div className="empty">Loading…</div>}
        {list.data?.length === 0 && <div className="empty">No engagements yet.</div>}
        {!!list.data?.length && (
          <table>
            <thead>
              <tr>
                <th>Name</th><th>Authorized by</th><th>Scope</th><th>Expires</th><th />
              </tr>
            </thead>
            <tbody>
              {list.data.map((e) => {
                const expired = e.expires_at && new Date(e.expires_at) < new Date();
                return (
                  <tr key={e.id}>
                    <td>
                      <strong>{e.name}</strong>
                      <div className="muted" style={{ fontSize: 11 }}>{e.kind}</div>
                    </td>
                    <td>
                      {e.authorized_by}
                      <div className="muted mono" style={{ fontSize: 11, wordBreak: "break-all" }}>
                        {e.authorization_ref}
                      </div>
                    </td>
                    <td>
                      {e.allow_rules.map((r) => <span key={r} className="tag">{r}</span>)}
                      {e.deny_rules.map((r) => (
                        <span key={r} className="tag" style={{ color: "var(--danger)" }}>−{r}</span>
                      ))}
                    </td>
                    <td className={expired ? "" : "muted"} style={expired ? { color: "var(--danger)" } : {}}>
                      {e.expires_at ? new Date(e.expires_at).toLocaleDateString() : "—"}
                      {expired && <div style={{ fontSize: 11 }}>expired</div>}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <button className="btn ghost sm" onClick={() => del.mutate(e.id)}>Delete</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
