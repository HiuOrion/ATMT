from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True)
class DetectionMetrics:
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    avg_time_to_detect_seconds: float | None


def safe_divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def compute_detection_metrics(
    benign_alerts: pd.DataFrame,
    ransomware_alerts: pd.DataFrame,
    *,
    threshold: int,
) -> DetectionMetrics:
    tp = int((ransomware_alerts["rule_level"] >= threshold).sum())
    fp = int((benign_alerts["rule_level"] >= threshold).sum())
    fn = int((ransomware_alerts["rule_level"] < threshold).sum())

    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    f1_score = safe_divide(2 * precision * recall, precision + recall)
    false_positive_rate = safe_divide(fp, len(benign_alerts))

    return DetectionMetrics(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        false_positive_rate=false_positive_rate,
        avg_time_to_detect_seconds=None,
    )


def compute_time_to_detect(
    ransomware_alerts: pd.DataFrame,
    metadata: pd.DataFrame,
    *,
    threshold: int,
) -> pd.DataFrame:
    high_alerts = ransomware_alerts[ransomware_alerts["rule_level"] >= threshold].copy()
    if high_alerts.empty:
        return pd.DataFrame(
            columns=[
                "sample_name",
                "family",
                "attack_start_time",
                "first_detection_time",
                "time_to_detect_seconds",
            ]
        )

    first_detection = (
        high_alerts.sort_values("timestamp")
        .groupby("sample_name", as_index=False)["timestamp"]
        .first()
        .rename(columns={"timestamp": "first_detection_time"})
    )

    merged = metadata.merge(first_detection, on="sample_name", how="left")
    merged["time_to_detect_seconds"] = (
        merged["first_detection_time"] - merged["attack_start_time"]
    ).dt.total_seconds()
    return merged[
        [
            "sample_name",
            "family",
            "attack_start_time",
            "first_detection_time",
            "time_to_detect_seconds",
        ]
    ]


def metrics_to_frame(metrics: DetectionMetrics, time_to_detect: pd.DataFrame) -> pd.DataFrame:
    avg_ttd = None
    if not time_to_detect.empty and time_to_detect["time_to_detect_seconds"].notna().any():
        avg_ttd = float(time_to_detect["time_to_detect_seconds"].dropna().mean())

    return pd.DataFrame(
        [
            {"metric": "true_positives", "value": metrics.true_positives},
            {"metric": "false_positives", "value": metrics.false_positives},
            {"metric": "false_negatives", "value": metrics.false_negatives},
            {"metric": "precision", "value": metrics.precision},
            {"metric": "recall", "value": metrics.recall},
            {"metric": "f1_score", "value": metrics.f1_score},
            {"metric": "false_positive_rate", "value": metrics.false_positive_rate},
            {"metric": "avg_time_to_detect_seconds", "value": avg_ttd},
        ]
    )
