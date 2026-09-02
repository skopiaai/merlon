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

          <ScopePaste
            onParsed={(allow, deny) =>
              setForm((f) => ({
                ...f,
                allow_rules: [...splitRules(f.allow_rules), ...allow]
                  .filter((v, i, a) => a.indexOf(v) === i).join("\n"),
                deny_rules: [...splitRules(f.deny_rules), ...deny]
                  .filter((v, i, a) => a.indexOf(v) === i).join("\n"),
              }))}
          />

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

/**
 * Paste a bug bounty program's scope table and turn it into rules.
 *
 * Pasted rather than fetched from a program URL. Scope is the one piece of
 * configuration in this tool where being wrong is a legal problem rather than
 * a bug, and deriving it from a regex over someone else's markup would make an
 * authorization decision automatically. The parse fills the fields below; you
 * still read them against the program page and press Create. That step is the
 * point, not friction to remove.
 */
function ScopePaste({ onParsed }: {
  onParsed: (allow: string[], deny: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");

  const parse = useMutation({
    mutationFn: () => api.parseScope(text),
    onSuccess: (r) => onParsed(r.allow, r.deny),
  });

  const result = parse.data;

  if (!open) {
    return (
      <button type="button" className="btn ghost sm" style={{ marginBottom: 14 }}
        onClick={() => setOpen(true)}>
        Paste a program scope table
      </button>
    );
  }

  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <h3 style={{ marginTop: 0 }}>Import scope</h3>
      <p className="subtitle" style={{ marginTop: 0 }}>
        Copy both the in-scope and out-of-scope tables from the program page and
        paste them here. Exclusions win over wildcards, and asset types this tool
        can't test (mobile apps, source repos) are named rather than dropped.
      </p>

      <div className="field">
        <textarea rows={8} value={text} spellCheck={false}
          onChange={(e) => setText(e.target.value)}
          placeholder={"In scope\n*.example.com\napi.example.com\n\nOut of scope\nlegacy.example.com"} />
      </div>

      <div className="row" style={{ gap: 10 }}>
        <button type="button" className="btn sm"
          disabled={!text.trim() || parse.isPending}
          onClick={() => parse.mutate()}>
          {parse.isPending ? "Parsing…" : "Parse"}
        </button>
        <button type="button" className="btn ghost sm" onClick={() => setOpen(false)}>
          Close
        </button>
      </div>

      {result && (
        <div className="note" style={{ marginTop: 14, whiteSpace: "pre-wrap" }}>
          {result.summary}
        </div>
      )}
    </div>
  );
}
