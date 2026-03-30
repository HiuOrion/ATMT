from __future__ import annotations

import argparse
from pathlib import Path
import sys

import pandas as pd

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.config import DEFAULT_SETTINGS, output_path
from analysis.loaders import load_benign_alerts, load_ransomware_alerts
from analysis.metrics import compute_detection_metrics, compute_time_to_detect, metrics_to_frame
from analysis.plots import plot_detection_results, plot_top_alerts


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate prerecorded Wazuh alerts for the ATMT demo.")
    parser.add_argument("--benign", type=Path, required=True, help="Directory containing benign CSV exports.")
    parser.add_argument(
        "--ransomware",
        type=Path,
        required=True,
        help="Directory containing ransomware sample folders with alerts.csv and metadata.json.",
    )
    parser.add_argument("--out", type=Path, required=True, help="Directory where outputs should be written.")
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_SETTINGS.detection_threshold,
        help="Rule level threshold used to count a detection.",
    )
    return parser


def format_percent(value: float) -> str:
    return f"{value:.2%}"


def excel_safe_frame(frame: pd.DataFrame) -> pd.DataFrame:
    safe = frame.copy()
    for column in safe.columns:
        series = safe[column]
        if isinstance(series.dtype, pd.DatetimeTZDtype):
            safe[column] = series.dt.tz_convert("UTC").dt.tz_localize(None)
    return safe


def build_run_summary(
    metrics_summary: pd.DataFrame,
    time_to_detect: pd.DataFrame,
    *,
    threshold: int,
) -> str:
    metrics = {row["metric"]: row["value"] for _, row in metrics_summary.iterrows()}
    avg_ttd = metrics.get("avg_time_to_detect_seconds")
    avg_ttd_text = "n/a" if pd.isna(avg_ttd) else f"{avg_ttd:.2f} seconds"

    lines = [
        "# Run Summary",
        "",
        f"- Detection threshold: level >= {threshold}",
        f"- True positives: {int(metrics['true_positives'])}",
        f"- False positives: {int(metrics['false_positives'])}",
        f"- False negatives: {int(metrics['false_negatives'])}",
        f"- Precision: {format_percent(float(metrics['precision']))}",
        f"- Recall: {format_percent(float(metrics['recall']))}",
        f"- F1-score: {format_percent(float(metrics['f1_score']))}",
        f"- False positive rate: {format_percent(float(metrics['false_positive_rate']))}",
        f"- Average time to detect: {avg_ttd_text}",
        "",
        "## Sample-Level Time to Detect",
        "",
    ]

    if time_to_detect.empty:
        lines.append("No sample detections were available.")
    else:
        lines.append("| Sample | Family | First Detection | TTD (seconds) |")
        lines.append("|---|---|---|---:|")
        for row in time_to_detect.itertuples(index=False):
            first_detection = row.first_detection_time.isoformat() if pd.notna(row.first_detection_time) else "n/a"
            ttd = "n/a" if pd.isna(row.time_to_detect_seconds) else f"{row.time_to_detect_seconds:.2f}"
            lines.append(f"| {row.sample_name} | {row.family} | {first_detection} | {ttd} |")

    return "\n".join(lines) + "\n"


def run(benign_root: Path, ransomware_root: Path, out_root: Path, *, threshold: int) -> dict[str, pd.DataFrame]:
    out_root.mkdir(parents=True, exist_ok=True)

    benign_alerts = load_benign_alerts(benign_root)
    ransomware_alerts, metadata = load_ransomware_alerts(ransomware_root)

    detection_metrics = compute_detection_metrics(benign_alerts, ransomware_alerts, threshold=threshold)
    time_to_detect = compute_time_to_detect(ransomware_alerts, metadata, threshold=threshold)
    metrics_summary = metrics_to_frame(detection_metrics, time_to_detect)

    avg_ttd = None
    if not time_to_detect.empty and time_to_detect["time_to_detect_seconds"].notna().any():
        avg_ttd = float(time_to_detect["time_to_detect_seconds"].dropna().mean())
        metrics_summary.loc[
            metrics_summary["metric"] == "avg_time_to_detect_seconds", "value"
        ] = avg_ttd

    metrics_summary.to_csv(output_path(out_root, DEFAULT_SETTINGS.summary_csv_name), index=False)

    with pd.ExcelWriter(output_path(out_root, DEFAULT_SETTINGS.metrics_xlsx_name), engine="openpyxl") as writer:
        excel_safe_frame(metrics_summary).to_excel(writer, sheet_name="summary", index=False)
        excel_safe_frame(time_to_detect).to_excel(writer, sheet_name="time_to_detect", index=False)
        excel_safe_frame(benign_alerts).to_excel(writer, sheet_name="benign_alerts", index=False)
        excel_safe_frame(ransomware_alerts).to_excel(writer, sheet_name="ransomware_alerts", index=False)

    plot_detection_results(metrics_summary, output_path(out_root, DEFAULT_SETTINGS.detection_plot_name))
    plot_top_alerts(ransomware_alerts, output_path(out_root, DEFAULT_SETTINGS.top_alerts_plot_name))

    summary_text = build_run_summary(metrics_summary, time_to_detect, threshold=threshold)
    output_path(out_root, DEFAULT_SETTINGS.summary_markdown_name).write_text(summary_text, encoding="utf-8")

    return {
        "benign_alerts": benign_alerts,
        "ransomware_alerts": ransomware_alerts,
        "metadata": metadata,
        "time_to_detect": time_to_detect,
        "metrics_summary": metrics_summary,
    }


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    run(args.benign, args.ransomware, args.out, threshold=args.threshold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
