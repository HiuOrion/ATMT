from __future__ import annotations

LOCKBIT_STEPS = [
    {"id": "shadow_tampering", "label": "Shadow copy tampering"},
    {"id": "process_access", "label": "Process access"},
    {"id": "cipher_artifact", "label": "Cipher artifact"},
    {"id": "ransom_artifact", "label": "Ransom note / Lockbit artifact"},
    {"id": "detection_triggered", "label": "Detection triggered"},
]

SAFE_SIM_STEPS = [
    {"id": "staging_complete", "label": "Staging complete"},
    {"id": "mass_write", "label": "Mass write"},
    {"id": "mass_rename", "label": "Mass rename"},
    {"id": "detection_triggered", "label": "Detection triggered"},
]

TIMELINES = {
    "lockbit_public": LOCKBIT_STEPS,
    "safe_file_activity": SAFE_SIM_STEPS,
}

SIGNAL_TO_STORY = {
    "shadow_delete": ("shadow_tampering", "Shadow copy tampering"),
    "process_access": ("process_access", "Process access"),
    "cipher_artifact": ("cipher_artifact", "Cipher artifact"),
    "ransom_note": ("ransom_artifact", "Ransom note / Lockbit artifact"),
    "lockbit_archive": ("ransom_artifact", "Ransom note / Lockbit artifact"),
}

SAFE_EVENT_TO_STORY = {
    "staging_complete": ("staging_complete", "Staging complete"),
    "mass_write": ("mass_write", "Mass write"),
    "mass_rename": ("mass_rename", "Mass rename"),
}

RULE_TO_STORY = {
    100610: ("detection_triggered", "Detection triggered"),
    100611: ("detection_triggered", "Detection triggered"),
    100612: ("detection_triggered", "Detection triggered"),
    100613: ("detection_triggered", "Detection triggered"),
    100614: ("detection_triggered", "Detection triggered"),
    100501: ("detection_triggered", "Detection triggered"),
    100502: ("detection_triggered", "Detection triggered"),
    100503: ("detection_triggered", "Detection triggered"),
}


def timeline_for_mode(mode: str | None) -> list[dict[str, str]]:
    return list(TIMELINES.get(mode or "lockbit_public", LOCKBIT_STEPS))
