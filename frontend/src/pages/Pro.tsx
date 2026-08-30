import { useState } from "react";
import Engagements from "./Engagements";
import Scans from "./Scans";
import ScanDetail from "./ScanDetail";
import Findings from "./Findings";
import Credentials from "./Credentials";

type View =
  | { name: "engagements" | "scans" | "findings" | "credentials" }
  | { name: "scan"; id: number };

/**
 * The full operator console — engagements, scope rules, stage selection,
 * raw findings triage. Everything the simple flow hides.
 */
export default function Pro({ initialScanId }: { initialScanId?: number | null }) {
  const [view, setView] = useState<View>(
    initialScanId ? { name: "scan", id: initialScanId } : { name: "scans" }
  );

  const is = (n: string) => view.name === n || (n === "scans" && view.name === "scan");

  return (
    <div className="pro">
      <div className="pro-nav">
        {(["scans", "findings", "engagements", "credentials"] as const).map((n) => (
          <button key={n} className={is(n) ? "on" : ""} onClick={() => setView({ name: n })}>
            {n === "engagements" ? "Scope & authorization" : n}
          </button>
        ))}
      </div>

      {view.name === "credentials" && <Credentials />}
      {view.name === "engagements" && <Engagements />}
      {view.name === "scans" && <Scans onOpen={(id) => setView({ name: "scan", id })} />}
      {view.name === "scan" && (
        <ScanDetail id={view.id} onBack={() => setView({ name: "scans" })} />
      )}
      {view.name === "findings" && <Findings />}
    </div>
  );
}
