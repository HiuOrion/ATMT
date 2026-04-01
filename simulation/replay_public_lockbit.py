from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import time


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Replay public Lockbit-derived events into a live Wazuh-monitored JSONL file.")
    parser.add_argument("--source", type=Path, default=Path("data/public_replay/lockbit_public.jsonl"))
    parser.add_argument("--dest", type=Path, default=Path("runtime/replay/live_demo.jsonl"))
    parser.add_argument("--limit", type=int, default=12, help="Maximum number of events to replay.")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay in seconds between replayed events.")
    parser.add_argument("--start-delay", type=float, default=1.0, help="Delay before the first event is written.")
    parser.add_argument("--truncate", action="store_true", help="Clear the destination file before replaying.")
    return parser


def append_line(dest: Path, event: dict[str, str | int]) -> None:
    with dest.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(event) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def replay(
    source: Path,
    dest: Path,
    *,
    limit: int,
    delay: float,
    start_delay: float,
    truncate: bool,
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
            event = json.loads(line)
            append_line(dest, event)
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
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
