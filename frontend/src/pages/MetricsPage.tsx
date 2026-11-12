import { useMetrics } from "../hooks/useMetrics";
import styles from "./MetricsPage.module.css";

function humanSeconds(seconds: number | null): string {
  if (seconds === null) return "—";
  const total = Math.round(seconds);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (hours > 0) return `${hours}h ${String(minutes).padStart(2, "0")}m`;
  if (minutes > 0) return `${minutes}m`;
  return `${total}s`;
}

export default function MetricsPage() {
  const { data, isLoading, isError, error, refetch } = useMetrics();

  if (isLoading) {
    return (
      <div className={styles.page} role="status" aria-busy="true">
        Loading metrics…
      </div>
    );
  }
  if (isError || !data) {
    return (
      <div className={styles.page} role="alert">
        <h1>Could not load metrics</h1>
        <p>{error instanceof Error ? error.message : "Unknown error"}</p>
        <button type="button" onClick={() => void refetch()}>
          Retry
        </button>
      </div>
    );
  }

  const buckets = Object.entries(data.time_to_triage.by_severity);
  const maxMedian = Math.max(
    data.time_to_triage.overall.median_seconds,
    ...buckets.map(([, bucket]) => bucket.median_seconds),
    1,
  );
  const comparison = data.variant_comparison;
  const maxRuleRate = Math.max(
    ...data.false_positive_rate_by_rule.map((row) => row.fp_rate),
    0.01,
  );

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <div>
          <h1>Triage metrics</h1>
          <p className={styles.muted}>
            How fast findings get triaged, which rules are noisy, and whether notification
            variants differ.
          </p>
        </div>
        <a href="/">Back to findings</a>
      </header>

      <section className={styles.card} aria-label="Time to triage">
        <h2>Time to triage</h2>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Scope</th>
              <th>n</th>
              <th>Median</th>
              <th>p90</th>
              <th>Median bar</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Overall</td>
              <td>{data.time_to_triage.overall.n}</td>
              <td>{humanSeconds(data.time_to_triage.overall.median_seconds)}</td>
              <td>{humanSeconds(data.time_to_triage.overall.p90_seconds)}</td>
              <td>
                <div className={styles.barTrack}>
                  <div
                    className={styles.barFill}
                    style={{
                      width: `${(data.time_to_triage.overall.median_seconds / maxMedian) * 100}%`,
                    }}
                  />
                </div>
              </td>
            </tr>
            {buckets.map(([severity, bucket]) => (
              <tr key={severity}>
                <td>{severity}</td>
                <td>{bucket.n}</td>
                <td>{humanSeconds(bucket.median_seconds)}</td>
                <td>{humanSeconds(bucket.p90_seconds)}</td>
                <td>
                  <div className={styles.barTrack}>
                    <div
                      className={styles.barFill}
                      style={{ width: `${(bucket.median_seconds / maxMedian) * 100}%` }}
                    />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className={styles.card} aria-label="Noisiest rules">
        <h2>Noisiest rules by false-positive rate</h2>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Rule</th>
              <th>Muted</th>
              <th>Accepted</th>
              <th>n</th>
              <th>FP rate</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {data.false_positive_rate_by_rule.map((row) => (
              <tr key={row.rule_id}>
                <td>
                  <code>{row.rule_id}</code>
                </td>
                <td>{row.muted}</td>
                <td>{row.accepted}</td>
                <td>{row.muted + row.accepted}</td>
                <td>{(row.fp_rate * 100).toFixed(1)}%</td>
                <td>
                  <div className={styles.barTrack}>
                    <div
                      className={styles.barFill}
                      style={{ width: `${(row.fp_rate / maxRuleRate) * 100}%` }}
                    />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className={styles.card} aria-label="A/B variant comparison">
        <h2>Notification variants A/B</h2>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Variant</th>
              <th>n</th>
              <th>Triaged</th>
              <th>Triage rate</th>
              <th>Median time</th>
            </tr>
          </thead>
          <tbody>
            {[comparison.variant_a, comparison.variant_b].map((variant) => (
              <tr key={variant.variant}>
                <td>{variant.variant}</td>
                <td>{variant.n}</td>
                <td>{variant.triaged}</td>
                <td>{(variant.triage_rate * 100).toFixed(1)}%</td>
                <td>{humanSeconds(variant.median_seconds)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p>
          Absolute difference in triage rate: {(comparison.absolute_delta ?? 0) * 100} points ·
          z = {comparison.z ?? "—"} · p = {comparison.p_value ?? "—"}
        </p>
        <p className={styles.verdict}>{comparison.verdict}</p>
      </section>
    </div>
  );
}
