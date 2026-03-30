from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


def plot_detection_results(metrics_summary: pd.DataFrame, output_path: Path) -> None:
    values = {
        row["metric"]: row["value"]
        for _, row in metrics_summary.iterrows()
        if row["metric"] in {"true_positives", "false_positives", "false_negatives"}
    }

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(
        ["TP", "FP", "FN"],
        [
            values.get("true_positives", 0),
            values.get("false_positives", 0),
            values.get("false_negatives", 0),
        ],
        color=["#2d6a4f", "#bc4749", "#6c757d"],
    )
    ax.set_title("Detection Results")
    ax.set_ylabel("Alert Count")
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)


def plot_top_alerts(ransomware_alerts: pd.DataFrame, output_path: Path, *, top_n: int = 5) -> None:
    top_counts = (
        ransomware_alerts["rule_id"]
        .astype(str)
        .value_counts()
        .head(top_n)
        .sort_values()
    )

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.barh(top_counts.index.tolist(), top_counts.values.tolist(), color="#3a86ff")
    ax.set_title("Top Alert Rules in Ransomware Samples")
    ax.set_xlabel("Count")
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
