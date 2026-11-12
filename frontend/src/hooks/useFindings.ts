import { useQuery } from "@tanstack/react-query";

import { listFindings, listUsers } from "../api/client";
import type { FindingPage, Filters, User } from "../types";

export function findingsQueryKey(filters: Filters) {
  return ["findings", filters] as const;
}

export function useFindings(filters: Filters) {
  return useQuery<FindingPage>({
    queryKey: findingsQueryKey(filters),
    queryFn: () => listFindings(filters),
  });
}

export function useUsers() {
  return useQuery<User[]>({
    queryKey: ["users"],
    queryFn: listUsers,
  });
}
