import pandas as pd

from analysis.metrics import compute_detection_metrics, compute_time_to_detect


def test_compute_detection_metrics_handles_zero_division() -> None:
    benign = pd.DataFrame(columns=["rule_level"])
    ransomware = pd.DataFrame(columns=["rule_level"])

    metrics = compute_detection_metrics(benign, ransomware, threshold=10)

    assert metrics.true_positives == 0
    assert metrics.false_positives == 0
    assert metrics.false_negatives == 0
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1_score == 0.0
    assert metrics.false_positive_rate == 0.0


def test_compute_time_to_detect_uses_metadata_start_time() -> None:
    alerts = pd.DataFrame(
        [
            {
                "sample_name": "sample_a",
                "rule_level": 12,
                "timestamp": pd.Timestamp("2026-03-25T09:15:20Z"),
            },
            {
                "sample_name": "sample_a",
                "rule_level": 8,
                "timestamp": pd.Timestamp("2026-03-25T09:15:05Z"),
            },
        ]
    )
    metadata = pd.DataFrame(
        [
            {
                "sample_name": "sample_a",
                "family": "Replay",
                "attack_start_time": pd.Timestamp("2026-03-25T09:15:00Z"),
            }
        ]
    )

    time_to_detect = compute_time_to_detect(alerts, metadata, threshold=10)

    assert len(time_to_detect) == 1
    assert time_to_detect.loc[0, "time_to_detect_seconds"] == 20.0
