import type { Finding } from "../types";
import styles from "./components.module.css";

interface FindingRowProps {
  finding: Finding;
  index: number;
  selected: boolean;
  focused: boolean;
  onToggle: (index: number, shiftKey: boolean) => void;
  onOpen: (index: number) => void;
}

const severityClass: Record<Finding["severity"], string> = {
  critical: styles.severityCritical ?? "",
  high: styles.severityHigh ?? "",
  medium: styles.severityMedium ?? "",
  low: styles.severityLow ?? "",
};

export function FindingRow({ finding, index, selected, focused, onToggle, onOpen }: FindingRowProps) {
  return (
    <tr
      className={`${styles.row} ${focused ? styles.focusedRow : ""}`}
      data-testid="finding-row"
      aria-current={focused ? "true" : undefined}
      onClick={() => onOpen(index)}
    >
      <td className={styles.checkCell} onClick={(event) => event.stopPropagation()}>
        <input
          type="checkbox"
          checked={selected}
          aria-label={`Select ${finding.rule_id} in ${finding.file_path}`}
          onChange={() => onToggle(index, false)}
          onClick={(event) => {
            event.stopPropagation();
            if (event.shiftKey) {
              event.preventDefault();
              onToggle(index, true);
            }
          }}
        />
      </td>
      <td>
        <span className={`${styles.badge} ${severityClass[finding.severity]}`}>
          {finding.severity}
        </span>
      </td>
      <td className={styles.findingCell}>
        <button
          type="button"
          className={styles.linkButton}
          onClick={(event) => {
            event.stopPropagation();
            onOpen(index);
          }}
          aria-label={`Open ${finding.rule_id} in ${finding.file_path}`}
        >
          {finding.message}
        </button>
        <div className={styles.muted}>{finding.rule_id}</div>
      </td>
      <td className={styles.mono}>
        {finding.repo}
        <br />
        {finding.file_path}:{finding.start_line}
      </td>
      <td>
        <span className={styles.state}>{finding.state}</span>
        {finding.notification_variant ? (
          <span className={styles.variant}>variant {finding.notification_variant}</span>
        ) : null}
      </td>
    </tr>
  );
}
