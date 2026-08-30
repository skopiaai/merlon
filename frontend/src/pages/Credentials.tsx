import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Identity } from "../api";

/**
 * Credentials for authenticated scanning.
 *
 * This screen exists because the coverage difference is enormous and the setup
 * cost is thirty seconds. Logged out, a scan sees the marketing site. Logged
 * in, it sees the application — the account pages, the API, the admin
 * functions, the places data actually lives.
 *
 * A second account unlocks the class of bug no single-session scanner can find:
 * one user reading another user's data. That comparison needs two logged-in
 * sessions, which is why it's here rather than in an engine's configuration.
 *
 * Values are never read back from the server — the panel shows which headers
 * are set, not what they contain.
 */

const COOKIE_HELP =
  "DevTools → Network → click any request to the site → Request Headers → " +
  "copy the whole Cookie line.";

export default function Credentials() {
  const qc = useQueryClient();
  const [eid, setEid] = useState<number | null>(null);

  const engagements = useQuery({ queryKey: ["engagements"], queryFn: api.listEngagements });

  useEffect(() => {
    if (eid === null && engagements.data?.length) setEid(engagements.data[0].id);
  }, [engagements.data, eid]);

  const current = useQuery({
    queryKey: ["auth", eid],
    queryFn: () => api.getAuth(eid!),
    enabled: eid !== null,
  });

  const [headerText, setHeaderText] = useState("");
  const [checkUrl, setCheckUrl] = useState("");
  const [checkString, setCheckString] = useState("");
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!current.data) return;
    setCheckUrl(current.data.check_url);
    setCheckString(current.data.check_string);
    setIdentities(
      current.data.identities.map((i) => ({
        name: i.name, role: i.role, headers: {}, check_url: i.check_url, check_string: "",
      }))
    );
  }, [current.data]);

  const save = useMutation({
    mutationFn: () =>
      api.setAuth(eid!, {
        headers: parseHeaders(headerText),
        check_url: checkUrl,
        check_string: checkString,
        identities: identities.filter((i) => i.name.trim()),
      }),
    onSuccess: () => {
      setErr("");
      qc.invalidateQueries({ queryKey: ["auth", eid] });
      verify.mutate();
    },
    onError: (e: Error) => setErr(e.message),
  });

  const verify = useMutation({ mutationFn: () => api.verifyAuth(eid!) });

  if (!engagements.data?.length) {
    return (
      <>
        <h2>Credentials</h2>
        <div className="empty">
          Create an engagement first — credentials are stored against one, so the
          authorization record and the session travel together.
        </div>
      </>
    );
  }

  const result = verify.data;

  return (
    <>
      <h2>Credentials</h2>
      <p className="subtitle">
        The single largest coverage gain available. Logged out, a scan sees the
        marketing site; logged in, it sees the application. Add a second account
        and it can also test whether one user can read another's data — which no
        single-session scanner can detect.
      </p>

      <div className="card">
        <div className="field" style={{ maxWidth: 420 }}>
          <label>Engagement</label>
          <select value={eid ?? ""} onChange={(e) => setEid(Number(e.target.value))}>
            {engagements.data.map((e) => (
              <option key={e.id} value={e.id}>{e.name}</option>
            ))}
          </select>
        </div>

        {current.data?.configured && (
          <div className="note">
            Currently {current.data.describes}. Header values are never sent back
            from the server — leave the box blank to keep what's stored.
          </div>
        )}
      </div>

      <div className="card">
        <h3>Primary session</h3>
        <div className="field">
          <label>Request headers</label>
          <textarea
            rows={4}
            spellCheck={false}
            value={headerText}
            onChange={(e) => setHeaderText(e.target.value)}
            placeholder={"Cookie: session=abc123; csrf=def456\nAuthorization: Bearer eyJhbGci…"}
          />
          <div className="hint">One per line, as they appear in the request. {COOKIE_HELP}</div>
        </div>

        <div className="row">
          <div className="field" style={{ flex: 2 }}>
            <label>Verification URL</label>
            <input value={checkUrl} spellCheck={false}
              onChange={(e) => setCheckUrl(e.target.value)}
              placeholder="https://target/account" />
            <div className="hint">A page only a logged-in user can see.</div>
          </div>
          <div className="field" style={{ flex: 1 }}>
            <label>Text proving it worked</label>
            <input value={checkString} spellCheck={false}
              onChange={(e) => setCheckString(e.target.value)}
              placeholder="Sign out" />
            <div className="hint">Checked before every scan.</div>
          </div>
        </div>
      </div>

      <div className="card">
        <h3>Additional accounts</h3>
        <p className="subtitle" style={{ marginTop: 0 }}>
          A second account turns on access-control testing. The scanner fetches a
          record as the primary account, then asks for the identical URL as this
          one — if the same data comes back, that's an IDOR. Use two genuinely
          unrelated accounts, or every result will be a false positive.
        </p>

        {identities.map((identity, i) => (
          <div className="row" key={i}>
            <div className="field" style={{ maxWidth: 150 }}>
              <label>Name</label>
              <input value={identity.name} placeholder="user-b"
                onChange={(e) => update(setIdentities, i, { name: e.target.value })} />
            </div>
            <div className="field" style={{ maxWidth: 150 }}>
              <label>Role</label>
              <input value={identity.role} placeholder="standard"
                onChange={(e) => update(setIdentities, i, { role: e.target.value })} />
            </div>
            <div className="field" style={{ flex: 2 }}>
              <label>Headers</label>
              <input spellCheck={false}
                placeholder="Cookie: session=…"
                onChange={(e) =>
                  update(setIdentities, i, { headers: parseHeaders(e.target.value) })} />
            </div>
            <div className="field" style={{ flex: 1 }}>
              <label>Verification URL</label>
              <input value={identity.check_url} spellCheck={false}
                placeholder="https://target/account"
                onChange={(e) => update(setIdentities, i, { check_url: e.target.value })} />
            </div>
            <div className="field" style={{ maxWidth: 40, marginBottom: 14 }}>
              <label>&nbsp;</label>
              <button className="btn sm ghost"
                onClick={() => setIdentities(identities.filter((_x, j) => j !== i))}>×</button>
            </div>
          </div>
        ))}

        <button className="btn sm ghost"
          onClick={() =>
            setIdentities([...identities,
              { name: "", role: "", headers: {}, check_url: "", check_string: "" }])}>
          Add account
        </button>
      </div>

      <div className="row" style={{ alignItems: "center", gap: 12 }}>
        <button className="btn" disabled={eid === null || save.isPending}
          onClick={() => save.mutate()}>
          {save.isPending ? "Saving…" : "Save and verify"}
        </button>
        <button className="btn ghost" disabled={eid === null || verify.isPending}
          onClick={() => verify.mutate()}>
          {verify.isPending ? "Checking…" : "Verify now"}
        </button>
      </div>

      {err && <div className="error">{err}</div>}

      {result && (
        <div className={`card ${result.ok ? "" : "warn"}`} style={{ marginTop: 14 }}>
          <h3>Session status</h3>
          <div className={result.ok ? "ok-line" : "warn-line"}>
            <strong>Primary:</strong> {result.reason}
          </div>
          {result.identities.map((i) => (
            <div key={i.name} className={i.ok ? "ok-line" : "warn-line"}>
              <strong>{i.name}:</strong> {i.reason}
            </div>
          ))}
          <div className="hint" style={{ marginTop: 8 }}>
            {result.access_control_testing
              ? "Access-control testing is active — scans will compare what each account can reach."
              : "Access-control testing is off. It needs the primary session plus at least one working additional account."}
          </div>
        </div>
      )}

      <div className="note" style={{ marginTop: 16 }}>
        <strong>Where these go.</strong> Credentials are sent only to hosts inside
        the engagement's scope, re-checked on every single request — enumeration
        routinely turns up hosts that aren't yours, and a session cookie sent to
        one of them is an incident. They're stored in the local database in
        plaintext, which is fine for a single-user offline tool and would not be
        for anything shared.
      </div>
    </>
  );
}

function update<T>(set: (fn: (prev: T[]) => T[]) => void, index: number, patch: Partial<T>) {
  set((prev) => prev.map((item, i) => (i === index ? { ...item, ...patch } : item)));
}

/** `Name: value` per line — the format you get from copying request headers. */
export function parseHeaders(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of (text || "").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const at = trimmed.indexOf(":");
    if (at < 1) continue;
    const name = trimmed.slice(0, at).trim();
    const value = trimmed.slice(at + 1).trim();
    if (name && value) out[name] = value;
  }
  return out;
}
