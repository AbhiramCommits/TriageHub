import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { QueryKey } from "@tanstack/react-query";
import { useRef } from "react";

import { bulkTransition } from "../api/client";
import type { FindingPage, FindingState, TriageAction } from "../types";

export interface ToastInput {
  message: string;
  retry?: () => void;
}

export interface TransitionVariables {
  ids: string[];
  action: TriageAction;
  assigneeUserId?: string;
}

interface MutationContext {
  previous: [QueryKey, FindingPage | undefined][];
}

const OPTIMISTIC_STATE: Partial<Record<TriageAction, FindingState>> = {
  accept: "accepted",
  mute: "muted",
  reopen: "open",
};

function optimisticUpdates(
  queryClient: ReturnType<typeof useQueryClient>,
  variables: TransitionVariables,
) {
  const nextState = OPTIMISTIC_STATE[variables.action];
  const ids = new Set(variables.ids);
  queryClient.setQueriesData<FindingPage>({ queryKey: ["findings"] }, (page) => {
    if (!page) return page;
    return {
      ...page,
      items: page.items.map((finding) => {
        if (!ids.has(finding.id)) return finding;
        const updated = { ...finding };
        if (nextState) {
          updated.state = nextState;
          updated.triaged_at =
            nextState === "open" ? null : (finding.triaged_at ?? new Date().toISOString());
        }
        if (variables.action === "assign" && variables.assigneeUserId) {
          updated.assignee_user_id = variables.assigneeUserId;
        }
        return updated;
      }),
    };
  });
}

export function useTransition(onToast: (toast: ToastInput) => void) {
  const queryClient = useQueryClient();
  const retryRef = useRef<(variables: TransitionVariables) => void>(() => undefined);

  const mutation = useMutation({
    mutationFn: (variables: TransitionVariables) =>
      bulkTransition({
        finding_ids: variables.ids,
        action: variables.action,
        assignee_user_id: variables.assigneeUserId,
      }),
    onMutate: async (variables): Promise<MutationContext> => {
      await queryClient.cancelQueries({ queryKey: ["findings"] });
      const previous = queryClient.getQueriesData<FindingPage>({ queryKey: ["findings"] });
      optimisticUpdates(queryClient, variables);
      return { previous };
    },
    onError: (error: Error, variables, context) => {
      context?.previous.forEach(([key, data]) => queryClient.setQueryData<FindingPage | undefined>(key, data));
      onToast({
        message: `${variables.action} failed: ${error.message}`,
        retry: () => retryRef.current(variables),
      });
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["findings"] }),
  });

  retryRef.current = mutation.mutate;
  return mutation;
}
