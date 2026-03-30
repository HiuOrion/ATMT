from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path
import shutil
import time
import uuid


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate harmless ransomware-like file activity for a Wazuh demo.")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory where the demo files should be created.")
    parser.add_argument("--log-file", type=Path, required=True, help="Path to the simulator event log file.")
    parser.add_argument("--count", type=int, default=18, help="Number of demo files to create and rename.")
    parser.add_argument("--extension", default=".locked-demo", help="Extension used for renamed files.")
    parser.add_argument("--clean", action="store_true", help="Delete the output directory before running.")
    return parser


def write_log(log_file: Path, event: str, count: int, target: Path, session_id: str) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    line = f"demo_ransomware_sim event={event} count={count} target={target.name} session={session_id}\n"
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(line)


def run_simulation(output_dir: Path, log_file: Path, *, count: int, extension: str, clean: bool) -> None:
    session_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8]

    if clean and output_dir.exists():
        shutil.rmtree(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    created_files: list[Path] = []
    for index in range(count):
        file_path = output_dir / f"demo_document_{index:02d}.txt"
        file_path.write_text(
            "This is a harmless ransomware demo file.\n"
            f"session={session_id}\n"
            f"index={index}\n",
            encoding="utf-8",
        )
        created_files.append(file_path)

    write_log(log_file, "staging_complete", count, output_dir, session_id)
    time.sleep(0.2)

    for file_path in created_files:
        with file_path.open("a", encoding="utf-8") as handle:
            handle.write("updated_by_demo_simulation=true\n")
    write_log(log_file, "mass_write", count, output_dir, session_id)
    time.sleep(0.2)

    for file_path in created_files:
        file_path.rename(file_path.with_suffix(extension))
    write_log(log_file, "mass_rename", count, output_dir, session_id)


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    run_simulation(
        args.output_dir,
        args.log_file,
        count=args.count,
        extension=args.extension,
        clean=args.clean,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
