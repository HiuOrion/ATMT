from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd

from analysis.config import COLUMN_ALIASES, NORMALIZED_COLUMNS


REQUIRED_COLUMNS = ("timestamp", "rule_id", "rule_level")


def canonicalize_column_name(name: str) -> str:
    return "".join(char.lower() for char in name if char.isalnum() or char in {".", "_", "@"})


def build_column_mapping(columns: list[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    canonical_to_original = {canonicalize_column_name(column): column for column in columns}
    for normalized_name, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            alias_key = canonicalize_column_name(alias)
            if alias_key in canonical_to_original:
                mapping[canonical_to_original[alias_key]] = normalized_name
                break
    return mapping


def normalize_alert_frame(
    frame: pd.DataFrame,
    *,
    source_type: str,
    sample_name: str,
    source_path: Path,
) -> pd.DataFrame:
    renamed = frame.rename(columns=build_column_mapping(frame.columns.tolist())).copy()

    missing = [column for column in REQUIRED_COLUMNS if column not in renamed.columns]
    if missing:
        raise ValueError(f"{source_path} is missing required columns: {', '.join(missing)}")

    renamed["timestamp"] = pd.to_datetime(renamed["timestamp"], utc=True, errors="coerce")
    if renamed["timestamp"].isna().any():
        invalid_rows = renamed.index[renamed["timestamp"].isna()].tolist()
        raise ValueError(f"{source_path} contains invalid timestamps at rows: {invalid_rows}")

    renamed["rule_id"] = renamed["rule_id"].astype(str)
    renamed["rule_level"] = pd.to_numeric(renamed["rule_level"], errors="coerce")
    if renamed["rule_level"].isna().any():
        invalid_rows = renamed.index[renamed["rule_level"].isna()].tolist()
        raise ValueError(f"{source_path} contains invalid rule_level values at rows: {invalid_rows}")

    renamed["sample_name"] = sample_name
    renamed["source_type"] = source_type

    for column in NORMALIZED_COLUMNS:
        if column not in renamed.columns:
            renamed[column] = pd.NA

    renamed = renamed[NORMALIZED_COLUMNS].copy()
    renamed["rule_level"] = renamed["rule_level"].astype(int)
    return renamed.sort_values("timestamp").reset_index(drop=True)


def load_benign_alerts(benign_root: Path) -> pd.DataFrame:
    csv_paths = sorted(path for path in benign_root.rglob("*.csv") if path.is_file())
    if not csv_paths:
        raise FileNotFoundError(f"No CSV files found under {benign_root}")

    frames = [
        normalize_alert_frame(
            pd.read_csv(csv_path),
            source_type="benign",
            sample_name="benign",
            source_path=csv_path,
        )
        for csv_path in csv_paths
    ]
    return pd.concat(frames, ignore_index=True)


def load_metadata(metadata_path: Path) -> dict[str, Any]:
    with metadata_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if "attack_start_time" not in payload:
        raise ValueError(f"{metadata_path} is missing attack_start_time")
    payload["attack_start_time"] = pd.to_datetime(payload["attack_start_time"], utc=True, errors="coerce")
    if pd.isna(payload["attack_start_time"]):
        raise ValueError(f"{metadata_path} has an invalid attack_start_time")
    return payload


def load_ransomware_alerts(ransomware_root: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    frames: list[pd.DataFrame] = []
    metadata_rows: list[dict[str, Any]] = []

    sample_directories = sorted(path for path in ransomware_root.iterdir() if path.is_dir())
    if not sample_directories:
        raise FileNotFoundError(f"No sample directories found under {ransomware_root}")

    for sample_directory in sample_directories:
        alerts_path = sample_directory / "alerts.csv"
        metadata_path = sample_directory / "metadata.json"
        if not alerts_path.exists():
            raise FileNotFoundError(f"Missing alerts.csv in {sample_directory}")
        if not metadata_path.exists():
            raise FileNotFoundError(f"Missing metadata.json in {sample_directory}")

        metadata = load_metadata(metadata_path)
        metadata_rows.append({"sample_name": sample_directory.name, **metadata})

        frame = normalize_alert_frame(
            pd.read_csv(alerts_path),
            source_type="ransomware",
            sample_name=sample_directory.name,
            source_path=alerts_path,
        )
        frames.append(frame)

    metadata_frame = pd.DataFrame(metadata_rows).sort_values("sample_name").reset_index(drop=True)
    alerts_frame = pd.concat(frames, ignore_index=True)
    return alerts_frame, metadata_frame
