from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    detection_threshold: int = 10
    summary_csv_name: str = "metrics_summary.csv"
    metrics_xlsx_name: str = "metrics_table.xlsx"
    detection_plot_name: str = "detection_results.png"
    top_alerts_plot_name: str = "top_alerts.png"
    summary_markdown_name: str = "run_summary.md"


DEFAULT_SETTINGS = Settings()

NORMALIZED_COLUMNS = [
    "timestamp",
    "sample_name",
    "source_type",
    "rule_id",
    "rule_level",
    "agent_name",
    "description",
    "command_line",
    "image",
    "technique_id",
]


COLUMN_ALIASES = {
    "timestamp": {
        "timestamp",
        "@timestamp",
        "time",
    },
    "rule_id": {
        "rule_id",
        "rule.id",
        "ruleid",
    },
    "rule_level": {
        "rule_level",
        "rule.level",
        "level",
    },
    "agent_name": {
        "agent_name",
        "agent.name",
        "agent",
    },
    "description": {
        "description",
        "rule.description",
        "message",
    },
    "command_line": {
        "command_line",
        "data.win.eventdata.commandline",
        "win.eventdata.commandline",
    },
    "image": {
        "image",
        "data.win.eventdata.image",
        "win.eventdata.image",
    },
    "technique_id": {
        "technique_id",
        "mitre.id",
        "mitreid",
    },
}


def output_path(root: Path, name: str) -> Path:
    return root / name
