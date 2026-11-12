import { useEffect, useState } from "react";

import { BulkActionBar } from "./components/BulkActionBar";
import { DetailPanel } from "./components/DetailPanel";
import { EmptyState } from "./components/EmptyState";
import { ErrorState } from "./components/ErrorState";
import { FilterBar } from "./components/FilterBar";
import { FindingList } from "./components/FindingList";
import { Skeleton } from "./components/Skeleton";
import { useFindings, useUsers } from "./hooks/useFindings";
import { useKeyboardNav } from "./hooks/useKeyboardNav";
import { useTransition } from "./hooks/useTransition";
import type { ToastInput } from "./hooks/useTransition";
import type { Filters, TriageAction } from "./types";
import styles from "./App.module.css";

const EMPTY_FILTERS: Filters = {
  state: "",
  severity: "",
  rule_id: "",
  repo: "",
  search: "",
};

export function filtersFromSearch(search: string): Filters {
  const params = new URLSearchParams(search);
  return {
    state: params.get("state") ?? "",
    severity: params.get("severity") ?? "",
    rule_id: params.get("rule_id") ?? "",
    repo: params.get("repo") ?? "",
    search: params.get("search") ?? "",
  };
}

export function searchFromFilters(filters: Filters): string {
  const params = new URLSearchParams();
  if (filters.state) params.set("state", filters.state);
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.rule_id) params.set("rule_id", filters.rule_id);
  if (filters.repo) params.set("repo", filters.repo);
  if (filters.search) params.set("search", filters.search);
  const query = params.toString();
  return query ? `?${query}` : "";
}

export default function App() {
  const [filters, setFilters] = useState<Filters>(() => filtersFromSearch(window.location.search));
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [anchorIndex, setAnchorIndex] = useState<number | null>(null);
  const [detailId, setDetailId] = useState<string | null>(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const [toast, setToast] = useState<(ToastInput & { key: number }) | null>(null);

  const findingsQuery = useFindings(filters);
  const usersQuery = useUsers();
  const findings = findingsQuery.data?.items ?? [];
  const hasFilters = Object.values(filters).some(Boolean);

  const mutation = useTransition((input) => setToast({ ...input, key: Date.now() }));

  useEffect(() => {
    const next = searchFromFilters(filters);
    window.history.replaceState(null, "", `${window.location.pathname}${next}`);
  }, [filters]);

  useEffect(() => {
    setSelectedIds(new Set());
    setAnchorIndex(null);
    setDetailId(null);
  }, [filters]);

  const updateFilter = (patch: Partial<Filters>) => {
    setFilters((current) => ({ ...current, ...patch }));
  };

  const clearFilters = () => setFilters({ ...EMPTY_FILTERS });

  const toggleSelection = (index: number, shiftKey: boolean) => {
    const finding = findings[index];
    if (!finding) return;
    if (shiftKey && anchorIndex !== null) {
      const start = Math.min(anchorIndex, index);
      const end = Math.max(anchorIndex, index);
      setSelectedIds((current) => {
        const next = new Set(current);
        for (let i = start; i <= end; i += 1) {
          const item = findings[i];
          if (item) next.add(item.id);
        }
        return next;
      });
      return;
    }
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(finding.id)) next.delete(finding.id);
      else next.add(finding.id);
      return next;
    });
    setAnchorIndex(index);
  };

  const toggleAll = () => {
    const allSelected = findings.length > 0 && findings.every((finding) => selectedIds.has(finding.id));
    setSelectedIds(allSelected ? new Set() : new Set(findings.map((finding) => finding.id)));
  };

  const idsForIndex = (index: number): string[] => {
    if (selectedIds.size > 0) return [...selectedIds];
    const finding = findings[index];
    return finding ? [finding.id] : [];
  };

  const runAction = (action: TriageAction, index: number, assigneeUserId?: string) => {
    const ids = idsForIndex(index);
    if (ids.length === 0) return;
    mutation.mutate({ ids, action, assigneeUserId });
  };

  const bulkAction = (action: TriageAction, assigneeUserId?: string) => {
    const ids = [...selectedIds];
    if (ids.length === 0) return;
    mutation.mutate({ ids, action, assigneeUserId });
    if (action !== "assign") setSelectedIds(new Set());
  };

  const openDetail = (index: number) => {
    const finding = findings[index];
    if (finding) setDetailId(finding.id);
  };

  const { focusedIndex } = useKeyboardNav({
    count: findings.length,
    onToggle: (index) => toggleSelection(index, false),
    onAccept: (index) => runAction("accept", index),
    onMute: (index) => runAction("mute", index),
    onOpen: (index) => openDetail(index),
    onClose: () => {
      if (helpOpen) setHelpOpen(false);
      else setDetailId(null);
    },
    onHelp: () => setHelpOpen(true),
  });

  const detail = findings.find((finding) => finding.id === detailId) ?? null;

  return (
    <div className={styles.app}>
      <header className={styles.header}>
        <div>
          <h1>TriageHub</h1>
          <p className={styles.muted}>Triage static-analysis findings where you already work.</p>
        </div>
        <button
          type="button"
          className={styles.secondaryButton}
          onClick={() => setHelpOpen(true)}
          aria-label="Show keyboard shortcuts"
        >
          Shortcuts (?) 
        </button>
      </header>

      <FilterBar filters={filters} onChange={updateFilter} onClear={clearFilters} />

      <main className={styles.main}>
        {findingsQuery.isLoading ? <Skeleton /> : null}
        {findingsQuery.isError ? (
          <ErrorState
            message={(findingsQuery.error as Error).message}
            onRetry={() => void findingsQuery.refetch()}
          />
        ) : null}
        {!findingsQuery.isLoading && !findingsQuery.isError && findings.length === 0 ? (
          <EmptyState
            kind={hasFilters ? "filtered" : "none"}
            onClear={clearFilters}
          />
        ) : null}
        {findings.length > 0 ? (
          <>
            <div className={styles.resultCount} role="status">
              {findings.length} finding{findings.length === 1 ? "" : "s"}
            </div>
            <FindingList
              findings={findings}
              selectedIds={selectedIds}
              focusedIndex={focusedIndex}
              onToggle={toggleSelection}
              onToggleAll={toggleAll}
              onOpen={openDetail}
            />
          </>
        ) : null}
      </main>

      <BulkActionBar
        count={selectedIds.size}
        users={usersQuery.data ?? []}
        disabled={mutation.isPending}
        onAction={bulkAction}
        onClear={() => setSelectedIds(new Set())}
      />
      <DetailPanel finding={detail} onClose={() => setDetailId(null)} />

      {toast ? (
        <div className={styles.toast} role="status" data-testid="toast">
          <span>{toast.message}</span>
          {toast.retry ? (
            <button
              type="button"
              className={styles.secondaryButton}
              onClick={() => {
                toast.retry?.();
                setToast(null);
              }}
            >
              Retry
            </button>
          ) : null}
          <button
            type="button"
            className={styles.linkButton}
            onClick={() => setToast(null)}
            aria-label="Dismiss notification"
          >
            Dismiss
          </button>
        </div>
      ) : null}

      {helpOpen ? (
        <div className={styles.overlay} role="dialog" aria-label="Keyboard shortcuts">
          <div className={styles.helpCard}>
            <h2>Keyboard shortcuts</h2>
            <ul>
              <li><kbd>j</kbd> / <kbd>k</kbd> next / previous finding</li>
              <li><kbd>x</kbd> toggle selection</li>
              <li><kbd>a</kbd> accept</li>
              <li><kbd>m</kbd> mute</li>
              <li><kbd>Enter</kbd> open detail</li>
              <li><kbd>Esc</kbd> close detail or this help</li>
              <li><kbd>?</kbd> this help</li>
            </ul>
            <button type="button" className={styles.secondaryButton} onClick={() => setHelpOpen(false)}>
              Close
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
