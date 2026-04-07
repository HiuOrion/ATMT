from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import time


PHASE_BY_SIGNAL_TYPE = {
    "shadow_delete": ("shadow_tampering", "Shadow copy tampering"),
    "process_access": ("process_access", "Process access"),
    "cipher_artifact": ("cipher_artifact", "Cipher artifact"),
    "ransom_note": ("ransom_artifact", "Ransom note / Lockbit artifact"),
    "lockbit_archive": ("ransom_artifact", "Ransom note / Lockbit artifact"),
}


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Replay public Lockbit-derived events into a live Wazuh-monitored JSONL file.")
    parser.add_argument("--source", type=Path, default=Path("data/public_replay/lockbit_public.jsonl"))
    parser.add_argument("--dest", type=Path, default=Path("runtime/replay/live_demo.jsonl"))
    parser.add_argument("--limit", type=int, default=12, help="Maximum number of events to replay.")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay in seconds between replayed events.")
    parser.add_argument("--start-delay", type=float, default=1.0, help="Delay before the first event is written.")
    parser.add_argument("--truncate", action="store_true", help="Clear the destination file before replaying.")
    parser.add_argument("--demo-session", default="", help="Attach a demo session identifier to each replayed event.")
    parser.add_argument("--emit-stdout", action="store_true", help="Print structured source-event lines for a live UI.")
    return parser


def append_line(dest: Path, event: dict[str, str | int]) -> None:
    with dest.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(event) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def enrich_event(event: dict[str, str | int], *, sequence: int, demo_session: str) -> dict[str, str | int]:
    signal_type = str(event.get("signal_type", ""))
    story_phase, story_title = PHASE_BY_SIGNAL_TYPE.get(signal_type, ("activity", "Observed activity"))
    enriched = dict(event)
    enriched["sequence"] = sequence
    enriched["story_phase"] = story_phase
    enriched["story_title"] = story_title
    if demo_session:
        enriched["demo_session"] = demo_session
    return enriched


def replay(
    source: Path,
    dest: Path,
    *,
    limit: int,
    delay: float,
    start_delay: float,
    truncate: bool,
    demo_session: str,
    emit_stdout: bool,
) -> int:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if truncate:
        dest.write_text("", encoding="utf-8")

    if start_delay > 0:
        time.sleep(start_delay)

    count = 0
    with source.open("r", encoding="utf-8") as src:
        for line in src:
            if not line.strip():
                continue
            raw_event = json.loads(line)
            event = enrich_event(raw_event, sequence=count + 1, demo_session=demo_session)
            append_line(dest, event)
            if emit_stdout:
                print(f"SOURCE_EVENT {json.dumps(event, ensure_ascii=False)}", flush=True)
            count += 1
            if count >= limit:
                break
            time.sleep(delay)
    return count


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    replay(
        args.source,
        args.dest,
        limit=args.limit,
        delay=args.delay,
        start_delay=args.start_delay,
        truncate=args.truncate,
        demo_session=args.demo_session,
        emit_stdout=args.emit_stdout,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
