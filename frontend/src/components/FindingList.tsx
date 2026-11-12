import type { Finding } from "../types";
import { FindingRow } from "./FindingRow";
import styles from "./components.module.css";

interface FindingListProps {
  findings: Finding[];
  selectedIds: Set<string>;
  focusedIndex: number;
  onToggle: (index: number, shiftKey: boolean) => void;
  onToggleAll: () => void;
  onOpen: (index: number) => void;
}

export function FindingList({
  findings,
  selectedIds,
  focusedIndex,
  onToggle,
  onToggleAll,
  onOpen,
}: FindingListProps) {
  const allSelected = findings.length > 0 && findings.every((finding) => selectedIds.has(finding.id));
  return (
    <div className={styles.tableWrap}>
      <table className={styles.table} aria-label="Security findings">
        <thead>
          <tr>
            <th className={styles.checkCell}>
              <input
                type="checkbox"
                checked={allSelected}
                aria-label="Select all visible findings"
                onChange={onToggleAll}
              />
            </th>
            <th>Severity</th>
            <th>Finding</th>
            <th>Location</th>
            <th>State</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding, index) => (
            <FindingRow
              key={finding.id}
              finding={finding}
              index={index}
              selected={selectedIds.has(finding.id)}
              focused={focusedIndex === index}
              onToggle={onToggle}
              onOpen={onOpen}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}
