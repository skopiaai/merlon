import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import Simple from "./pages/Simple";
import Pro from "./pages/Pro";
import CTF from "./pages/CTF";

type Tab = "scan" | "console" | "ctf";

/** Shown instead of the app when the API is unreachable. */
function BackendDown() {
  return (
    <div className="clean" style={{ textAlign: "left", padding: 30 }}>
      <h3 style={{ marginTop: 0 }}>The backend isn't responding</h3>
      <p style={{ margin: "0 0 18px" }}>
        The interface loaded, but it can't reach the API. That almost always means the backend
        container failed to build or crashed on startup, while the frontend container came up fine.
      </p>
      <h4 style={{ fontSize: 12.5, textTransform: "uppercase", letterSpacing: "0.06em",
                   color: "var(--ink-3)", margin: "0 0 8px" }}>
        Run these in the project folder
      </h4>
      <pre style={{ background: "#1c1a17", color: "#d6d3d1", padding: 14, borderRadius: 10,
                    fontSize: 12.5, overflow: "auto", margin: 0 }}>
{`docker compose ps                 # is "backend" running?
docker compose logs backend       # what went wrong
docker compose up --build backend # rebuild just the backend`}
      </pre>
      <p style={{ marginTop: 16, fontSize: 13.5 }}>
        Or run <code>./diagnose.sh</code> in the project folder — it collects the container
        status, restart count, and logs in one go.
      </p>
      <p style={{ marginTop: 10, fontSize: 13.5 }}>
        This page rechecks every 8 seconds and will come back on its own once the backend is up.
      </p>
    </div>
  );
}

export default function App() {
  const [tab, setTab] = useState<Tab>("scan");
  const [theme, setTheme] = useState<"dark" | "light">(
    () => (localStorage.getItem("theme") as "dark" | "light") ?? "dark"
  );

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("theme", theme);
  }, [theme]);

  const health = useQuery({
    queryKey: ["health"],
    queryFn: api.health,
    refetchInterval: 8_000,
    retry: 0,
    // Don't keep showing the last good status after the backend disappears —
    // a stale "AI on" while nothing works is worse than no indicator at all.
    gcTime: 0,
  });

  // isError alone lags by one interval; treat "no data" as down too.
  const backendDown = health.isError || (!health.isLoading && !health.data);
  const ollamaOn = !backendDown && health.data?.ollama.reachable;

  return (
    <div className={tab === "scan" ? "" : "wide"}>
      <div className="shell">
        <header className="topbar">
          <button className="brand" onClick={() => setTab("scan")}>
            <span className="dot" />
            Bug Bounty Webapp
          </button>

          <div className="status">
            <nav className="tabs">
              <button className={tab === "scan" ? "on" : ""} onClick={() => setTab("scan")}>
                Scan
              </button>
              <button className={tab === "console" ? "on" : ""} onClick={() => setTab("console")}>
                Console
              </button>
              <button className={tab === "ctf" ? "on" : ""} onClick={() => setTab("ctf")}>
                CTF
              </button>
            </nav>
            <span title={ollamaOn ? health.data?.ollama.models.join(", ") : "Start Ollama for AI triage"}>
              <i className={`led ${ollamaOn ? "on" : "off"}`} />
              <b>AI {ollamaOn ? "on" : "off"}</b>
            </span>

            <button
              className="themebtn"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
            >
              {theme === "dark" ? "☀" : "☾"}
            </button>
          </div>
        </header>

        {backendDown ? <BackendDown />
          : tab === "scan" ? <Simple />
          : tab === "ctf" ? <CTF />
          : <Pro />}
      </div>
    </div>
  );
}
