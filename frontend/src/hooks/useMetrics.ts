import { useQuery } from "@tanstack/react-query";

import { getMetrics } from "../api/client";
import type { MetricsSummary } from "../types";

export function useMetrics() {
  return useQuery<MetricsSummary>({
    queryKey: ["metrics"],
    queryFn: getMetrics,
  });
}
