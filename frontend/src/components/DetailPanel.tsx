import type { Finding } from "../types";
import styles from "./components.module.css";

interface DetailPanelProps {
  finding: Finding | null;
  onClose: () => void;
}

export function DetailPanel({ finding, onClose }: DetailPanelProps) {
  if (!finding) return null;
  return (
    <aside className={styles.detail} aria-label="Finding detail">
      <div className={styles.detailHeader}>
        <h2>{finding.rule_id}</h2>
        <button type="button" className={styles.secondaryButton} onClick={onClose} aria-label="Close detail">
          Close
        </button>
      </div>
      <p>{finding.message}</p>
      <dl className={styles.meta}>
        <dt>Severity</dt>
        <dd>{finding.severity}</dd>
        <dt>State</dt>
        <dd>{finding.state}</dd>
        <dt>Location</dt>
        <dd>
          {finding.repo}/{finding.file_path}:{finding.start_line}
        </dd>
        <dt>First seen</dt>
        <dd>{new Date(finding.first_seen_at).toLocaleString()}</dd>
        <dt>Triaged</dt>
        <dd>{finding.triaged_at ? new Date(finding.triaged_at).toLocaleString() : "not yet"}</dd>
        <dt>Line fingerprint</dt>
        <dd className={styles.mono}>{finding.line_fingerprint.slice(0, 16)}…</dd>
        <dt>Variant</dt>
        <dd>{finding.notification_variant ?? "unassigned"}</dd>
      </dl>
      {finding.code_snippet ? <pre className={styles.code}>{finding.code_snippet}</pre> : null}
      {finding.rule_rationale ? <p className={styles.muted}>{finding.rule_rationale}</p> : null}
    </aside>
  );
}
