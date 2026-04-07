import json

from demo_web.parsers import parse_source_event_line, parse_wazuh_alert_line


def test_parse_source_event_line_for_public_lockbit() -> None:
    event = {
        "dataset": "public_lockbit",
        "signal_type": "cipher_artifact",
        "description": "Cipher observed",
        "demo_session": "abc123",
        "sequence": 4,
        "target_filename": "demo.txt",
        "image": "C:\\demo.exe",
        "timestamp": "2026-04-07T10:00:00Z",
    }
    parsed = parse_source_event_line(f"SOURCE_EVENT {json.dumps(event)}")
    assert parsed is not None
    assert parsed["mode"] == "lockbit_public"
    assert parsed["story_phase"] == "cipher_artifact"
    assert parsed["demo_session"] == "abc123"


def test_parse_wazuh_alert_line_matches_demo_session_from_full_log() -> None:
    alert = {
        "timestamp": "2026-04-07T10:00:01Z",
        "rule": {
            "id": 100501,
            "level": 12,
            "description": "Demo ransomware behavior: rapid file write burst",
            "mitre": {"id": ["T1486"]},
        },
        "location": "demo-sim",
        "full_log": "demo_ransomware_sim event=mass_write count=18 target=demo session=session42",
    }
    parsed = parse_wazuh_alert_line(json.dumps(alert), "session42")
    assert parsed is not None
    assert parsed["rule_id"] == 100501
    assert parsed["demo_session"] == "session42"
    assert parsed["story_phase"] == "detection_triggered"


def test_parse_wazuh_alert_line_rejects_other_session() -> None:
    alert = {
        "timestamp": "2026-04-07T10:00:01Z",
        "rule": {"id": 100610, "level": 14, "description": "Lockbit replay"},
        "data": {"demo_session": "another"},
        "full_log": '{"demo_session": "another"}',
    }
    assert parse_wazuh_alert_line(json.dumps(alert), "session42") is None
