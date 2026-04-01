from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
import xml.etree.ElementTree as ET

import pandas as pd


EVENT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
SUSPICIOUS_KEYWORDS = ("lockbit", "ransom", "cipher", "decipher", "shadow")


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build analysis and replay artifacts from Splunk's public Lockbit Sysmon dataset."
    )
    parser.add_argument("--source-log", type=Path, required=True, help="Path to the public sysmon.log file.")
    parser.add_argument("--source-meta", type=Path, required=True, help="Path to the public dataset metadata yml.")
    parser.add_argument("--data-root", type=Path, default=Path("data"), help="Root data directory.")
    return parser


def parse_event(line: str) -> dict[str, str]:
    root = ET.fromstring(line)
    payload: dict[str, str] = {}
    payload["event_id"] = root.findtext("e:System/e:EventID", namespaces=EVENT_NS) or ""
    payload["timestamp"] = root.find("e:System/e:TimeCreated", EVENT_NS).attrib.get("SystemTime", "")
    payload["computer"] = root.findtext("e:System/e:Computer", namespaces=EVENT_NS) or ""
    for node in root.findall("e:EventData/e:Data", EVENT_NS):
        payload[node.attrib.get("Name", "")] = node.text or ""
    return payload


def contains_keyword(*values: str) -> bool:
    haystack = " ".join(value.lower() for value in values if value)
    return any(keyword in haystack for keyword in SUSPICIOUS_KEYWORDS)


def classify_signal(event: dict[str, str]) -> tuple[str, int, str, str] | None:
    target = event.get("TargetFilename", "") or event.get("TargetObject", "")
    image = event.get("Image", "") or event.get("SourceImage", "")
    event_id = event.get("event_id", "")
    target_lower = target.lower()

    if "shadow" in target_lower and event_id in {"12", "13"}:
        return (
            "shadow_delete",
            100610,
            14,
            "Public Lockbit replay: shadow-related deletion or registry modification observed",
        )
    if "ransom" in target_lower:
        return (
            "ransom_note",
            100611,
            13,
            "Public Lockbit replay: ransom note artifact observed",
        )
    if "cipher" in target_lower or "decipher" in target_lower:
        return (
            "cipher_artifact",
            100612,
            12,
            "Public Lockbit replay: cipher-related artifact observed",
        )
    if "lockbit" in target_lower:
        return (
            "lockbit_archive",
            100613,
            11,
            "Public Lockbit replay: Lockbit-named artifact observed",
        )
    if event_id == "10" and contains_keyword(target, image):
        return (
            "process_access",
            100614,
            10,
            "Public Lockbit replay: suspicious process access observed",
        )
    return None


def build_alert_row(
    event: dict[str, str],
    *,
    sample_name: str,
    source_type: str,
    rule_id: int,
    rule_level: int,
    description: str,
) -> dict[str, str | int]:
    command_line = " | ".join(
        value
        for value in (
            event.get("CommandLine", ""),
            event.get("TargetFilename", ""),
            event.get("TargetObject", ""),
            event.get("Details", ""),
        )
        if value
    )
    return {
        "@timestamp": event["timestamp"],
        "rule.id": rule_id,
        "rule.level": rule_level,
        "agent.name": event.get("computer", "lockbit-public"),
        "rule.description": description,
        "data.win.eventdata.commandLine": command_line,
        "data.win.eventdata.image": event.get("Image", "") or event.get("SourceImage", ""),
        "mitre.id": "T1490" if rule_id == 100610 else "T1486",
        "sample_name": sample_name,
        "source_type": source_type,
    }


def build_replay_row(event: dict[str, str], signal_type: str, rule_id: int, rule_level: int, description: str) -> dict[str, str | int]:
    return {
        "dataset": "public_lockbit",
        "source": "splunk_attack_data",
        "timestamp": event["timestamp"],
        "signal_type": signal_type,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "description": description,
        "image": event.get("Image", "") or event.get("SourceImage", ""),
        "target_filename": event.get("TargetFilename", ""),
        "target_object": event.get("TargetObject", ""),
        "details": event.get("Details", ""),
    }


def build_public_dataset(source_log: Path, source_meta: Path, data_root: Path) -> dict[str, int]:
    public_source_dir = data_root / "public_sources" / "lockbit_ransomware"
    public_source_dir.mkdir(parents=True, exist_ok=True)
    (public_source_dir / source_log.name).write_bytes(source_log.read_bytes())
    (public_source_dir / source_meta.name).write_bytes(source_meta.read_bytes())

    benign_rows: list[dict[str, str | int]] = []
    ransomware_rows: list[dict[str, str | int]] = []
    replay_rows: list[dict[str, str | int]] = []
    suspicious_counter: Counter[str] = Counter()

    with source_log.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            event = parse_event(line)
            classification = classify_signal(event)
            if classification:
                signal_type, rule_id, rule_level, description = classification
                suspicious_counter[signal_type] += 1
                ransomware_rows.append(
                    build_alert_row(
                        event,
                        sample_name="lockbit_public",
                        source_type="ransomware",
                        rule_id=rule_id,
                        rule_level=rule_level,
                        description=description,
                    )
                )
                replay_rows.append(build_replay_row(event, signal_type, rule_id, rule_level, description))
                continue

            if len(benign_rows) < 250:
                benign_rows.append(
                    build_alert_row(
                        event,
                        sample_name="public_background",
                        source_type="benign",
                        rule_id=600000 + len(benign_rows),
                        rule_level=4,
                        description="Public Lockbit background Sysmon event",
                    )
                )

    ransomware_frame = pd.DataFrame(ransomware_rows).sort_values("@timestamp").reset_index(drop=True)
    benign_frame = pd.DataFrame(benign_rows).sort_values("@timestamp").reset_index(drop=True)

    benign_root = data_root / "benign_logs"
    benign_root.mkdir(parents=True, exist_ok=True)
    benign_frame.to_csv(benign_root / "alerts.csv", index=False)

    ransomware_root = data_root / "ransomware_logs" / "lockbit_public"
    ransomware_root.mkdir(parents=True, exist_ok=True)
    ransomware_frame.to_csv(ransomware_root / "alerts.csv", index=False)
    metadata = {
        "family": "Lockbit public replay",
        "source": "https://github.com/splunk/attack_data/tree/master/datasets/malware/lockbit_ransomware",
        "attack_start_time": ransomware_frame.iloc[0]["@timestamp"],
        "notes": "Derived from Splunk's public attack_data Lockbit Sysmon dataset. Converted into normalized alert rows and replay JSON for safe demonstration.",
    }
    (ransomware_root / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    replay_root = data_root / "public_replay"
    replay_root.mkdir(parents=True, exist_ok=True)
    replay_path = replay_root / "lockbit_public.jsonl"
    with replay_path.open("w", encoding="utf-8") as handle:
        for row in replay_rows:
            handle.write(json.dumps(row) + "\n")

    summary = {
        "benign_rows": len(benign_rows),
        "ransomware_rows": len(ransomware_rows),
        "replay_rows": len(replay_rows),
        **{f"signal_{key}": value for key, value in suspicious_counter.items()},
    }
    (public_source_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    summary = build_public_dataset(args.source_log, args.source_meta, args.data_root)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
