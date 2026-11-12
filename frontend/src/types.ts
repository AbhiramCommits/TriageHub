export type Severity = "low" | "medium" | "high" | "critical";
export type FindingState = "open" | "accepted" | "muted" | "fixed";
export type Variant = "A" | "B";
export type Surface = "slack" | "github" | "console" | "system";

export interface Finding {
  id: string;
  workspace_id: string;
  rule_id: string;
  severity: Severity;
  message: string;
  repo: string;
  file_path: string;
  start_line: number;
  end_line: number;
  line_fingerprint: string;
  code_snippet: string | null;
  rule_rationale: string | null;
  state: FindingState;
  assignee_user_id: string | null;
  first_seen_at: string;
  triaged_at: string | null;
  notification_variant: Variant | null;
}

export interface FindingPage {
  items: Finding[];
  next_cursor: string | null;
}

export interface Filters {
  state: string;
  severity: string;
  rule_id: string;
  repo: string;
  search: string;
}

export interface User {
  id: string;
  workspace_id: string;
  email: string;
  role: "admin" | "reviewer";
  created_at: string;
}

export type TriageAction = "accept" | "mute" | "assign" | "reopen" | "resolve";

export interface BulkTransitionBody {
  finding_ids: string[];
  action: TriageAction;
  assignee_user_id?: string;
}

export interface TransitionResult {
  updated: Finding[];
  skipped: { finding_id: string; reason: string }[];
}

export interface TimeBucket {
  n: number;
  median_seconds: number;
  p90_seconds: number;
}

export interface RuleFpRate {
  rule_id: string;
  muted: number;
  accepted: number;
  fp_rate: number;
}

export interface VariantStats {
  variant: string;
  n: number;
  triaged: number;
  triage_rate: number;
  median_seconds: number | null;
}

export interface MetricsSummary {
  time_to_triage: {
    overall: TimeBucket;
    by_severity: Record<string, TimeBucket>;
  };
  false_positive_rate_by_rule: RuleFpRate[];
  variant_comparison: {
    variant_a: VariantStats;
    variant_b: VariantStats;
    absolute_delta: number | null;
    z: number | null;
    p_value: number | null;
    significant: boolean;
    verdict: string;
  };
}
