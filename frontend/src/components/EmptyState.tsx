import styles from "./components.module.css";

interface EmptyStateProps {
  kind: "none" | "filtered";
  onClear: () => void;
}

export function EmptyState({ kind, onClear }: EmptyStateProps) {
  if (kind === "none") {
    return (
      <div className={styles.empty} role="status">
        <h2>No findings yet</h2>
        <p>Your scanners have not sent any findings to this workspace.</p>
      </div>
    );
  }
  return (
    <div className={styles.empty} role="status">
      <h2>No findings match these filters</h2>
      <p>Try widening the severity, rule or repository filters.</p>
      <button type="button" className={styles.secondaryButton} onClick={onClear}>
        Clear filters
      </button>
    </div>
  );
}
