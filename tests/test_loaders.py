from pathlib import Path

import pandas as pd

from analysis.loaders import normalize_alert_frame


def test_normalize_alert_frame_maps_wazuh_columns() -> None:
    frame = pd.DataFrame(
        [
            {
                "@timestamp": "2026-03-25T09:15:14Z",
                "rule.id": 100501,
                "rule.level": 12,
                "agent.name": "agent-1",
                "rule.description": "Rapid write burst",
                "data.win.eventdata.commandLine": "demo command",
                "data.win.eventdata.image": r"C:\Demo\simulator.exe",
                "mitre.id": "T1486",
            }
        ]
    )

    normalized = normalize_alert_frame(
        frame,
        source_type="ransomware",
        sample_name="sample_demo",
        source_path=Path("sample.csv"),
    )

    assert normalized.loc[0, "timestamp"].isoformat() == "2026-03-25T09:15:14+00:00"
    assert normalized.loc[0, "rule_id"] == "100501"
    assert normalized.loc[0, "rule_level"] == 12
    assert normalized.loc[0, "sample_name"] == "sample_demo"
    assert normalized.loc[0, "source_type"] == "ransomware"
    assert normalized.loc[0, "technique_id"] == "T1486"


def test_normalize_alert_frame_rejects_missing_required_columns() -> None:
    frame = pd.DataFrame([{"rule.level": 10}])

    try:
        normalize_alert_frame(
            frame,
            source_type="benign",
            sample_name="benign",
            source_path=Path("broken.csv"),
        )
    except ValueError as exc:
        assert "missing required columns" in str(exc)
    else:
        raise AssertionError("Expected ValueError for missing columns")
