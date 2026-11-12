import { useState } from "react";

import type { TriageAction, User } from "../types";
import styles from "./components.module.css";

interface BulkActionBarProps {
  count: number;
  users: User[];
  disabled: boolean;
  onAction: (action: TriageAction, assigneeUserId?: string) => void;
  onClear: () => void;
}

export function BulkActionBar({ count, users, disabled, onAction, onClear }: BulkActionBarProps) {
  const [assignee, setAssignee] = useState("");

  if (count === 0) return null;

  return (
    <div className={styles.bulkBar} role="region" aria-label="Bulk actions">
      <strong>{count} selected</strong>
      <button
        type="button"
        className={styles.primaryButton}
        disabled={disabled}
        onClick={() => onAction("accept")}
      >
        Accept
      </button>
      <button
        type="button"
        className={styles.secondaryButton}
        disabled={disabled}
        onClick={() => onAction("mute")}
      >
        Mute
      </button>
      <label className={styles.field}>
        <span>Assignee</span>
        <select value={assignee} onChange={(event) => setAssignee(event.target.value)}>
          <option value="">Choose user</option>
          {users.map((user) => (
            <option key={user.id} value={user.id}>
              {user.email}
            </option>
          ))}
        </select>
      </label>
      <button
        type="button"
        className={styles.secondaryButton}
        disabled={disabled || !assignee}
        onClick={() => onAction("assign", assignee)}
      >
        Assign
      </button>
      <button type="button" className={styles.linkButton} onClick={onClear}>
        Clear selection
      </button>
    </div>
  );
}
