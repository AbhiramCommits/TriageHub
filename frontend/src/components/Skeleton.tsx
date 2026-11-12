import styles from "./components.module.css";

export function Skeleton() {
  return (
    <div className={styles.skeleton} data-testid="skeleton" aria-busy="true" aria-label="Loading findings">
      {Array.from({ length: 6 }).map((_, index) => (
        <div key={index} className={styles.skeletonRow} />
      ))}
    </div>
  );
}
