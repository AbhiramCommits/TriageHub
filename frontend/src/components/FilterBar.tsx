import type { Filters } from "../types";
import styles from "./components.module.css";

interface FilterBarProps {
  filters: Filters;
  onChange: (patch: Partial<Filters>) => void;
  onClear: () => void;
}

export function FilterBar({ filters, onChange, onClear }: FilterBarProps) {
  const hasFilters = Object.values(filters).some(Boolean);
  return (
    <section className={styles.filters} aria-label="Findings filters">
      <label className={styles.field}>
        <span>State</span>
        <select
          value={filters.state}
          onChange={(event) => onChange({ state: event.target.value })}
        >
          <option value="">All states</option>
          <option value="open">Open</option>
          <option value="accepted">Accepted</option>
          <option value="muted">Muted</option>
          <option value="fixed">Fixed</option>
        </select>
      </label>
      <label className={styles.field}>
        <span>Severity</span>
        <select
          value={filters.severity}
          onChange={(event) => onChange({ severity: event.target.value })}
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </label>
      <label className={styles.field}>
        <span>Rule</span>
        <input
          value={filters.rule_id}
          placeholder="python.lang..."
          onChange={(event) => onChange({ rule_id: event.target.value })}
        />
      </label>
      <label className={styles.field}>
        <span>Repo</span>
        <input
          value={filters.repo}
          placeholder="acme/payments-api"
          onChange={(event) => onChange({ repo: event.target.value })}
        />
      </label>
      <label className={`${styles.field} ${styles.searchField}`}>
        <span>Search</span>
        <input
          type="search"
          value={filters.search}
          placeholder="message, file or rule"
          onChange={(event) => onChange({ search: event.target.value })}
        />
      </label>
      {hasFilters ? (
        <button type="button" className={styles.secondaryButton} onClick={onClear}>
          Clear filters
        </button>
      ) : null}
    </section>
  );
}
