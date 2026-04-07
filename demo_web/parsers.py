from __future__ import annotations

import json
import re
from typing import Any

from demo_web.story import RULE_TO_STORY, SAFE_EVENT_TO_STORY, SIGNAL_TO_STORY

SOURCE_PREFIX = "SOURCE_EVENT "
SESSION_RE = re.compile(r"session=([A-Za-z0-9_-]+)")


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _nested_lookup(payload: dict[str, Any], *paths: tuple[str, ...]) -> Any:
    for path in paths:
        current: Any = payload
        found = True
        for part in path:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                found = False
                break
        if found:
            return current
    return None


def parse_source_event_line(line: str) -> dict[str, Any] | None:
    text = line.strip()
    if not text.startswith(SOURCE_PREFIX):
        return None
    payload = json.loads(text[len(SOURCE_PREFIX) :])
    mode = str(payload.get("mode") or ("lockbit_public" if payload.get("dataset") == "public_lockbit" else "safe_file_activity"))
    if mode == "lockbit_public":
        phase, title = SIGNAL_TO_STORY.get(
            str(payload.get("signal_type", "")),
            (str(payload.get("story_phase", "activity")), str(payload.get("story_title", "Observed activity"))),
        )
    else:
        phase, title = SAFE_EVENT_TO_STORY.get(
            str(payload.get("event", "")),
            (str(payload.get("story_phase", "activity")), str(payload.get("story_title", "Observed activity"))),
        )
    target = payload.get("target_object") or payload.get("target_filename") or payload.get("target") or ""
    return {
        "mode": mode,
        "demo_session": payload.get("demo_session", ""),
        "sequence": _coerce_int(payload.get("sequence")) or 0,
        "story_phase": phase,
        "story_title": title,
        "signal_type": payload.get("signal_type") or payload.get("event") or "",
        "rule_id": _coerce_int(payload.get("rule_id")),
        "rule_level": _coerce_int(payload.get("rule_level")),
        "description": payload.get("description") or title,
        "target": target,
        "image": payload.get("image", ""),
        "details": payload.get("details", ""),
        "timestamp": payload.get("timestamp", ""),
        "raw": payload,
    }


def parse_wazuh_alert_line(line: str, session_id: str) -> dict[str, Any] | None:
    text = line.strip()
    if not text:
        return None
    payload = json.loads(text)
    rule = payload.get("rule", {})
    rule_id = _coerce_int(rule.get("id"))
    if rule_id is None:
        return None

    full_log = str(payload.get("full_log", ""))
    data = payload.get("data", {}) if isinstance(payload.get("data"), dict) else {}
    predecoder = payload.get("predecoder", {}) if isinstance(payload.get("predecoder"), dict) else {}

    embedded_session = (
        _nested_lookup(data, ("demo_session",), ("demo", "session"))
        or payload.get("demo_session")
        or _nested_lookup(predecoder, ("demo_session",))
    )
    if not embedded_session and full_log:
        match = SESSION_RE.search(full_log)
        if match:
            embedded_session = match.group(1)

    if session_id and embedded_session != session_id:
        return None

    phase, title = RULE_TO_STORY.get(rule_id, ("detection_triggered", "Detection triggered"))
    mitre_ids = rule.get("mitre", {}).get("id", [])
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]

    return {
        "rule_id": rule_id,
        "level": _coerce_int(rule.get("level")) or 0,
        "description": rule.get("description", ""),
        "timestamp": payload.get("timestamp", ""),
        "mitre_ids": mitre_ids,
        "groups": rule.get("groups", []),
        "location": payload.get("location", ""),
        "decoder": payload.get("decoder", {}).get("name", ""),
        "story_phase": phase,
        "story_title": title,
        "demo_session": embedded_session or "",
        "full_log": full_log,
        "raw": payload,
    }
