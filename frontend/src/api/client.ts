import type {
  BulkTransitionBody,
  Finding,
  FindingPage,
  Filters,
  MetricsSummary,
  TransitionResult,
  TriageAction,
  User,
} from "../types";

const BASE = "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    ...init,
  });
  if (!response.ok) {
    let detail = `Request failed with ${response.status}`;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      // response had no JSON body
    }
    throw new Error(detail);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export function filtersToParams(filters: Filters, limit = 100): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.state) params.append("state", filters.state);
  if (filters.severity) params.append("severity", filters.severity);
  if (filters.rule_id) params.set("rule_id", filters.rule_id);
  if (filters.repo) params.set("repo", filters.repo);
  if (filters.search) params.set("search", filters.search);
  params.set("limit", String(limit));
  return params;
}

export async function listFindings(filters: Filters): Promise<FindingPage> {
  return request<FindingPage>(`/api/findings?${filtersToParams(filters).toString()}`);
}

export async function getFinding(id: string): Promise<Finding> {
  return request<Finding>(`/api/findings/${id}`);
}

export async function bulkTransition(body: BulkTransitionBody): Promise<TransitionResult> {
  return request<TransitionResult>("/api/findings/bulk-transition", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function transitionFinding(
  id: string,
  action: TriageAction,
  assigneeUserId?: string,
): Promise<Finding> {
  return request<Finding>(`/api/findings/${id}/transition`, {
    method: "POST",
    body: JSON.stringify({
      action,
      assignee_user_id: assigneeUserId ?? null,
    }),
  });
}

export async function listUsers(): Promise<User[]> {
  return request<User[]>("/api/users");
}

export async function getMetrics(): Promise<MetricsSummary> {
  return request<MetricsSummary>("/api/metrics/summary");
}
