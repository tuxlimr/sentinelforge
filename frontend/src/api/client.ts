import type {
  Benchmark, FuzzResult, Health, Mutation, PackInfo, Regression, ReplayResult, Run, RunRequest, SaveRegression,
  Settings, TargetSpec, TestCaseInfo,
} from "./types";

/** Thin wrapper over fetch that throws readable errors from the API's `detail` field. */
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, { headers: { "Content-Type": "application/json" }, ...init });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(typeof body?.detail === "string" ? body.detail : `Request failed (${response.status})`);
  }
  if (response.status === 204) return undefined as T;
  const isText = response.headers.get("content-type")?.startsWith("text/");
  return (isText ? response.text() : response.json()) as Promise<T>;
}

const post = <T>(path: string, body: unknown) => request<T>(path, { method: "POST", body: JSON.stringify(body) });

export const api = {
  health: () => request<Health>("/health"),
  listPacks: () => request<PackInfo[]>("/packs"),

  listRuns: () => request<Run[]>("/runs"),
  getRun: (id: string) => request<Run>(`/runs/${id}`),
  createRun: (body: RunRequest) => post<Run>("/runs", body),
  deleteRun: (id: string) => request<void>(`/runs/${id}`, { method: "DELETE" }),
  getSarif: (id: string) => request<unknown>(`/runs/${id}/sarif`),

  listRegressions: () => request<Regression[]>("/regressions"),
  saveRegression: (body: SaveRegression) => post<Regression>("/regressions", body),
  removeRegression: (id: string) => request<void>(`/regressions/${encodeURIComponent(id)}`, { method: "DELETE" }),
  exportRegressions: () => request<string>("/regressions/export"),
  replayRegressions: (target: TargetSpec) => post<ReplayResult[]>("/regressions/replay", { target }),

  listPayloads: () => request<TestCaseInfo[]>("/lab/payloads"),
  listMutations: () => request<Mutation[]>("/lab/mutations"),
  fuzz: (caseId: string, mutations: string[], target: TargetSpec) =>
    post<FuzzResult[]>("/lab/fuzz", { case_id: caseId, mutations, target }),

  runBenchmark: (repeats: number) => post<Benchmark>("/benchmark", { repeats }),

  getSettings: () => request<Settings>("/settings"),
  saveSettings: (settings: Settings) => request<Settings>("/settings", { method: "PUT", body: JSON.stringify(settings) }),
};
