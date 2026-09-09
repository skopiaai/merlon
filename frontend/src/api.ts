export const API = import.meta.env.VITE_API_BASE ?? "http://127.0.0.1:8000";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type ScanState = "queued" | "running" | "completed" | "failed" | "cancelled";
export type FindingStatus =
  | "new" | "triaging" | "confirmed" | "false_positive"
  | "accepted_risk" | "reported" | "fixed";

/** A finding as it appears in the submission queue. */
export interface QueueEntry {
  id: number;
  name: string;
  severity: Severity;
  host: string;
  url: string;
  engine: string;
  rule_id: string;
  status: string;
  confidence: number | null;
  reproduced: boolean;
  verified_at: string | null;
  reasons: string[];
  why?: string;
  /** False when this finding appeared in an earlier scan of the same engagement. */
  is_new: boolean;
  first_seen?: string;
  previously?: string;
}

/** One account the scanner can act as. Two of these enable IDOR detection. */
export interface Identity {
  name: string;
  role: string;
  headers: Record<string, string>;
  check_url: string;
  check_string: string;
}

export interface Engagement {
  id: number;
  name: string;
  kind: string;
  authorized_by: string;
  authorization_ref: string;
  authorized_at: string;
  expires_at: string | null;
  allow_rules: string[];
  deny_rules: string[];
  notes: string;
}

export interface Scan {
  id: number;
  engagement_id: number;
  seeds: string[];
  profile: string;
  stages: string[];
  state: ScanState;
  stage_current: string;
  progress: number;
  error: string;
  stats: Record<string, unknown>;
  rejected_hosts: { host: string; reason: string; stage: string }[];
  started_at: string | null;
  finished_at: string | null;
}

export interface Finding {
  id: number;
  scan_id: number;
  engine: string;
  rule_id: string;
  name: string;
  severity: Severity;
  host: string;
  url: string;
  description: string;
  evidence: string;
  remediation: string;
  references: string[];
  tags: string[];
  cve: string[];
  cwe: string[];
  occurrences: number;
  status: FindingStatus;
  /** The local LLM's opinion. Commentary — deliberately not the gate. */
  triage_confidence: number | null;
  triage_note: string;
  analyst_note: string;
  /** Computed from whether the finding actually reproduces. This is the gate. */
  verify_confidence: number | null;
  reproduced: boolean;
  verified_at: string | null;
}

/** Thrown when the backend can't be reached at all (vs. returning an error). */
export class BackendDownError extends Error {
  constructor() {
    super(
      `Can't reach the backend at ${API}. It's probably not running — ` +
      `check "docker compose ps" and "docker compose logs backend".`
    );
    this.name = "BackendDownError";
  }
}

export type LeadStatus = "todo" | "testing" | "confirmed" | "clear" | "skipped";

export interface Lead {
  id: number;
  scan_id: number;
  area: string;
  why: string;
  check: string;
  vuln_class: string;
  priority: "high" | "medium" | "low";
  source: "ai" | "surface";
  category: string;
  deep_dive: string;
  status: LeadStatus;
  notes: string;
}

export interface SurfaceMap {
  total_urls: number;
  categories: {
    category: string; why: string; vuln_classes: string[];
    count: number; urls: string[];
  }[];
  params_interesting: { name: string; class: string; why: string; count: number; seen_on: string[] }[];
  params_other: string[];
  idor_candidates: { url: string; kind: string; why: string }[];
  auth_boundaries: { url: string; status: number | null }[];
  hints?: string[];
}

export type ChallengeStatus = "todo" | "working" | "stuck" | "solved" | "abandoned";

export interface Challenge {
  id: number;
  name: string;
  category: string;
  points: number;
  status: ChallengeStatus;
  assignee: string;
  description: string;
  notes: string;
  flag: string;
  writeup: string;
  artifacts: string[];
  severity: string;
  impact: string;
}

export interface AnalysisReport {
  filename: string;
  size: number;
  filetype: string;
  category_hint: string;
  entropy: number;
  flags: string[];
  extracted: string[];
  summary: string[];
  steps: { name: string; tool: string; ok: boolean; output: string; note: string }[];
}

export interface ArsenalCategory {
  label: string; colour: string; summary: string;
  triage: string[];
  tools: { name: string; for: string; cmd: string }[];
  patterns: string[];
}

export interface ArsenalData {
  categories: Record<string, ArsenalCategory>;
  event: {
    name: string; organiser: string; url: string;
    milestones: { label: string; date: string; note: string }[];
    scoring: string[]; rules: string[]; prep: string[];
  };
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    });
  } catch {
    // fetch only rejects on network-level failure: server down, DNS, CORS block
    throw new BackendDownError();
  }
  if (!res.ok) {
    let detail: unknown = await res.text();
    try { detail = JSON.parse(detail as string).detail ?? detail; } catch { /* plain text */ }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  const ct = res.headers.get("content-type") ?? "";
  return (ct.includes("json") ? res.json() : res.text()) as Promise<T>;
}

export const api = {
  engines: () => req<{
    engines: { name: string; label: string; description: string; phase: string;
               takes: string; produces: string; skip_cdn: boolean;
               weight: number; default_in: string[] }[];
    core_stages: string[];
    labels: Record<string, string>;
  }>("/api/system/engines"),

  health: () => req<{ status: string; ollama: { reachable: boolean; models: string[] } }>("/api/health"),
  updateTemplates: () => req<{ output: string }>("/api/system/update-templates", { method: "POST" }),

  // --- submission queue -------------------------------------------------
  // Split by whether a finding reproduces, not by severity.
  submissionQueue: (scanId: number) => req<{
    threshold: number;
    ready: QueueEntry[];
    needs_review: QueueEntry[];
    did_not_reproduce: QueueEntry[];
    counts: { ready: number; needs_review: number;
              did_not_reproduce: number; total: number;
              new: number; seen_before: number };
  }>(`/api/scans/${scanId}/queue`),

  // Assembled from captured evidence — no model in this path.
  submissionReport: (id: number, platform: string) => req<{
    platform: string; title: string; body: string;
    ready: boolean; warning: string;
  }>(`/api/findings/${id}/submission?platform=${platform}`),

  verifyFinding: (id: number) => req<{
    confidence: number; reproduced: boolean; submittable: boolean;
    reasons: string[]; evidence: unknown[];
  }>(`/api/findings/${id}/verify`, { method: "POST" }),

  // --- continuous monitoring --------------------------------------------
  engagementDiff: (eid: number) => req<{
    available: boolean;
    detail?: string;
    baseline_scan?: number;
    current_scan?: number;
    new_hosts: string[];
    gone_hosts: string[];
    new_urls: string[];
    changed: { host: string; before: string; after: string; why: string }[];
    interesting: boolean;
    counts: { new_hosts: number; gone_hosts: number;
              new_urls: number; changed: number };
  }>(`/api/engagements/${eid}/diff`),

  // Parses only — creating the engagement stays a separate, deliberate step.
  parseScope: (text: string) => req<{
    allow: string[];
    deny: string[];
    unscannable: { asset: string; kind: string }[];
    ignored: string[];
    counts: { allow: number; deny: number; unscannable: number };
    summary: string;
  }>("/api/scope/parse", { method: "POST", body: JSON.stringify({ text }) }),

  rescan: (eid: number) =>
    req<Scan>(`/api/engagements/${eid}/rescan`, { method: "POST" }),

  updateStatus: () => req<{
    last_run: number | null;
    age_seconds: number | null;
    stale: boolean;
    running: boolean;
    auto_daily: boolean;
    template_dirs: string[];
    kev: { entries: number; age_seconds: number | null; ransomware_entries: number };
    sources: { name: string; kind: string; ok: boolean; skipped?: boolean;
               detail: string; items: number; seconds: number; at: number }[];
  }>("/api/system/update"),

  runUpdate: () => req<{ started: boolean; detail: string }>(
    "/api/system/update", { method: "POST" }),

  listEngagements: () => req<Engagement[]>("/api/engagements"),
  createEngagement: (body: unknown) =>
    req<Engagement>("/api/engagements", { method: "POST", body: JSON.stringify(body) }),
  deleteEngagement: (id: number) =>
    req<void>(`/api/engagements/${id}`, { method: "DELETE" }),

  checkScope: (engagement_id: number, hosts: string[]) =>
    req<{ expired: boolean; results: { input: string; host: string; allowed: boolean; reason: string }[] }>(
      "/api/scope/check", { method: "POST", body: JSON.stringify({ engagement_id, hosts }) }),

  quickScan: (body: {
    target: string;
    depth: "sprint" | "quick" | "standard" | "deep";
    include_subdomains: boolean;
    authorized: boolean;
  }) => req<Scan>("/api/quickscan", { method: "POST", body: JSON.stringify(body) }),

  listScans: (engagementId?: number) =>
    req<Scan[]>(`/api/scans${engagementId ? `?engagement_id=${engagementId}` : ""}`),
  getScan: (id: number) => req<Scan>(`/api/scans/${id}`),
  createScan: (body: unknown) =>
    req<Scan>("/api/scans", { method: "POST", body: JSON.stringify(body) }),
  cancelScan: (id: number) =>
    req<{ result: "cancelled" | "forced" | "already-finished"; message: string }>(
      `/api/scans/${id}/cancel`, { method: "POST" }),
  scanLogs: (id: number) =>
    req<{ id: number; level: string; stage: string; message: string; ts: string }[]>(`/api/scans/${id}/logs`),
  scanReport: (id: number) => req<string>(`/api/scans/${id}/report`),
  auditReport: (id: number) => req<string>(`/api/scans/${id}/audit-report`),
  setAuth: (engagementId: number, body: {
    headers: Record<string, string>; check_url: string; check_string: string;
    identities?: Identity[];
  }) =>
    req<unknown>(`/api/engagements/${engagementId}/auth`, { method: "PUT", body: JSON.stringify(body) }),

  // Describes what's configured; header *values* are deliberately never
  // returned by the server.
  getAuth: (engagementId: number) => req<{
    configured: boolean;
    describes: string;
    check_url: string;
    check_string: string;
    header_names: string[];
    identities: { name: string; role: string; check_url: string; header_names: string[] }[];
  }>(`/api/engagements/${engagementId}/auth`),
  verifyAuth: (engagementId: number) =>
    req<{
      ok: boolean; reason: string; configured: string;
      identities: { name: string; role: string; ok: boolean; reason: string }[];
      access_control_testing: boolean;
    }>(`/api/engagements/${engagementId}/auth/verify`, { method: "POST" }),

  listFindings: (params: Record<string, string | number | undefined>) => {
    const qs = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v !== undefined && v !== "") as [string, string][]
    );
    return req<Finding[]>(`/api/findings?${qs}`);
  },
  // --- CTF workspace ---
  analyze: async (file: File) => {
    const body = new FormData();
    body.append("file", file);
    const res = await fetch(`${API}/api/ctf/analyze`, { method: "POST", body });
    if (!res.ok) throw new Error(await res.text());
    return res.json() as Promise<AnalysisReport>;
  },
  decode: (text: string, include_caesar = false) =>
    req<{ chains: { chain: string; output: string; depth: number }[];
          caesar: { shift: number; output: string }[]; flags: string[] }>(
      "/api/ctf/decode", { method: "POST", body: JSON.stringify({ text, include_caesar }) }),
  rsa: (body: { n: string; e: string; c?: string; other_n?: string[] }) =>
    req<{ bits: number; e: number; findings: Record<string, string>[] }>(
      "/api/ctf/rsa", { method: "POST", body: JSON.stringify(body) }),

  ctfArsenal: () => req<ArsenalData>("/api/ctf/arsenal"),
  ctfStats: () => req<{
    total: number; solved: number; points: number;
    by_category: Record<string, { total: number; solved: number; points: number }>;
  }>("/api/ctf/stats"),
  challenges: (category?: string) =>
    req<Challenge[]>(`/api/ctf/challenges${category ? `?category=${category}` : ""}`),
  createChallenge: (body: { name: string; category: string; points: number; assignee: string }) =>
    req<Challenge>("/api/ctf/challenges", { method: "POST", body: JSON.stringify(body) }),
  updateChallenge: (id: number, body: Partial<Challenge>) =>
    req<Challenge>(`/api/ctf/challenges/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteChallenge: (id: number) =>
    req<void>(`/api/ctf/challenges/${id}`, { method: "DELETE" }),
  challengeWriteup: (id: number) =>
    req<string>(`/api/ctf/challenges/${id}/writeup`, { method: "POST" }),

  // ---- Hack The Box ----
  htbReference: () => req<HtbReference>("/api/htb/reference"),
  htbMachines: () => req<HtbMachine[]>("/api/htb/machines"),
  htbCreate: (body: { name: string; host: string; difficulty: string; os: string; state: string }) =>
    req<HtbMachine>("/api/htb/machines", { method: "POST", body: JSON.stringify(body) }),
  htbUpdate: (id: number, body: Partial<HtbMachine>) =>
    req<HtbMachine>(`/api/htb/machines/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  htbDelete: (id: number) => req<void>(`/api/htb/machines/${id}`, { method: "DELETE" }),
  htbRecon: (id: number, full = true) =>
    req<HtbRecon>(`/api/htb/machines/${id}/recon?full=${full}`, { method: "POST" }),
  htbNext: (id: number) =>
    req<{ phase: string; actions: HtbAction[]; phases: HtbPhase[] }>(`/api/htb/machines/${id}/next`),
  htbHint: (id: number, level: number, key = "") =>
    req<HtbHint>(`/api/htb/machines/${id}/hint?level=${level}&key=${encodeURIComponent(key)}`,
      { method: "POST" }),
  htbFlags: (text: string, source = "") =>
    req<{ flags: HtbFlag[] }>("/api/htb/flags",
      { method: "POST", body: JSON.stringify({ text, source }) }),
  htbSudo: (text: string) =>
    req<{ entries: SudoEntry[] }>("/api/htb/privesc/sudo",
      { method: "POST", body: JSON.stringify({ text }) }),
  htbTriage: (text: string) =>
    req<{ hits: { title: string; platform: string; why: string; command: string }[] }>(
      "/api/htb/privesc/scan", { method: "POST", body: JSON.stringify({ text }) }),
  htbKnowledgeUpdate: () =>
    req<{ sources: { name: string; ok: boolean; detail: string; items: number }[] }>(
      "/api/htb/knowledge/update", { method: "POST" }),
  htbXp: () => req<HtbXp>("/api/htb/xp"),

  leads: (scanId: number) => req<Lead[]>(`/api/scans/${scanId}/leads`),
  surface: (scanId: number) => req<SurfaceMap>(`/api/scans/${scanId}/surface`),
  updateLead: (id: number, body: Partial<Pick<Lead, "status" | "notes" | "priority">>) =>
    req<Lead>(`/api/leads/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deepDive: (id: number) =>
    req<{ deep_dive: string }>(`/api/leads/${id}/deep-dive`, { method: "POST" }),
  reanalyze: (scanId: number) =>
    req<{ leads_added: number }>(`/api/scans/${scanId}/reanalyze`, { method: "POST" }),

  updateFinding: (id: number, body: unknown) =>
    req<Finding>(`/api/findings/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  retriage: (id: number) => req<unknown>(`/api/findings/${id}/retriage`, { method: "POST" }),
  disclosure: (id: number) => req<string>(`/api/findings/${id}/disclosure`),
};

export function scanSocket(scanId: number, onEvent: (e: any) => void): () => void {
  const url = API.replace(/^http/, "ws") + `/ws/scans/${scanId}`;
  const ws = new WebSocket(url);
  ws.onmessage = (m) => {
    const data = JSON.parse(m.data);
    if (data.type !== "ping") onEvent(data);
  };
  return () => ws.close();
}

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--crit)",
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
  info: "var(--info)",
};

// ---- Hack The Box ----
export type HtbMachine = {
  id: number; name: string; host: string; difficulty: string; os: string;
  state: string; kind: string; phase: string; has_shell: boolean;
  shell_user: string; is_root: boolean; user_flag: string; root_flag: string;
  ports: { port: number; service: string; product: string; version: string }[];
  hostnames: string[]; creds: { user: string; secret: string }[];
  os_guess: string; notes: string; hints_used: number; max_hint_level: number;
  created_at: string; user_owned_at: string | null; root_owned_at: string | null;
};

export type HtbAction = {
  key: string; phase: string; tier: string; title: string; why: string;
  commands: string[]; look_for: string[]; hints: string[]; current_phase: boolean;
};

export type HtbPhase = { key: string; label: string; done_when: string; trap: string };

export type HtbRecon = {
  host: string; warning: string; phase: string;
  ports: HtbMachine["ports"]; hostnames: string[]; os_guess: string;
  actions: HtbAction[]; quick_detail: string; full_detail: string;
  seconds: number; hosts_file: string;
};

export type HtbHint = {
  key: string; title: string; level: number; level_label: string; of: number;
  hint: string; next_level_available: boolean; hints_used: number;
  requested_key: string; substituted: boolean; note?: string;
  writeup_policy: { allowed: boolean; note: string };
};

export type HtbFlag = { value: string; kind: string; confidence: number; why: string };

export type SudoEntry = {
  path: string; runas: string; binary: string; exploitable: boolean;
  command?: string; note?: string; source?: string;
};

export type HtbXp = {
  tracked_xp: number; machines: number; rooted: number; user_only: number;
  streak: {
    week_start: string; week_end: string; xp_this_week: number;
    xp_needed: number; safe: boolean; hours_left: number; urgent: boolean;
    suggestion: string;
  };
};

export type HtbReference = {
  phases: HtbPhase[];
  privesc: Record<string, { label: string; first: string[]; then: string[];
                            checks: [string, string][] }>;
  xp: Record<string, unknown>;
  rules: { key: string; phase: string; title: string; why: string;
           ports: number[]; look_for: string[] }[];
  knowledge: Record<string, { entries: number; age_seconds: number | null; present: boolean }>;
};
