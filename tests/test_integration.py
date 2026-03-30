import json
from pathlib import Path
import shutil
import uuid

import pandas as pd

from analysis.evaluate import run


ROOT = Path(__file__).resolve().parents[1]
TEST_WORK_ROOT = ROOT / ".test-work"


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    pd.DataFrame(rows).to_csv(path, index=False)


def test_end_to_end_run_generates_outputs() -> None:
    case_root = TEST_WORK_ROOT / f"integration-{uuid.uuid4().hex}"
    case_root.mkdir(parents=True, exist_ok=False)
    try:
        benign_dir = case_root / "benign"
        benign_dir.mkdir()
        write_csv(
            benign_dir / "alerts.csv",
            [
                {"@timestamp": "2026-03-25T08:00:00Z", "rule.id": 60106, "rule.level": 3},
                {"@timestamp": "2026-03-25T08:10:00Z", "rule.id": 61613, "rule.level": 4},
            ],
        )

        ransomware_root = case_root / "ransomware"
        sample_dir = ransomware_root / "sample_one"
        sample_dir.mkdir(parents=True)
        write_csv(
            sample_dir / "alerts.csv",
            [
                {"@timestamp": "2026-03-25T09:00:15Z", "rule.id": 100501, "rule.level": 12},
                {"@timestamp": "2026-03-25T09:00:30Z", "rule.id": 100502, "rule.level": 12},
            ],
        )
        (sample_dir / "metadata.json").write_text(
            json.dumps(
                {
                    "family": "Replay",
                    "source": "fixture",
                    "attack_start_time": "2026-03-25T09:00:00Z",
                    "notes": "fixture",
                }
            ),
            encoding="utf-8",
        )

        out_dir = case_root / "results"
        run(benign_dir, ransomware_root, out_dir, threshold=10)

        expected_outputs = [
            "metrics_summary.csv",
            "metrics_table.xlsx",
            "detection_results.png",
            "top_alerts.png",
            "run_summary.md",
        ]
        for name in expected_outputs:
            assert (out_dir / name).exists(), f"Missing expected output {name}"
    finally:
        if case_root.exists():
            shutil.rmtree(case_root, ignore_errors=True)
