import styles from "./components.module.css";

interface ErrorStateProps {
  message: string;
  onRetry: () => void;
}

export function ErrorState({ message, onRetry }: ErrorStateProps) {
  return (
    <div className={styles.empty} role="alert">
      <h2>Could not load findings</h2>
      <p>{message}</p>
      <button type="button" className={styles.primaryButton} onClick={onRetry}>
        Retry
      </button>
    </div>
  );
}
