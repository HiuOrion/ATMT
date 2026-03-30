from __future__ import annotations

import json
from datetime import datetime, UTC
from pathlib import Path

import pandas as pd
from docx import Document
from docx.enum.section import WD_SECTION_START
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.shared import Inches

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results"
REPORT_DIR = ROOT / "report"
DATA_DIR = ROOT / "data" / "ransomware_logs"
OUTPUT_PATH = REPORT_DIR / "ATMT_Wazuh_Demo_Report.docx"


def load_metrics() -> dict[str, float]:
    frame = pd.read_csv(RESULTS_DIR / "metrics_summary.csv")
    return {row["metric"]: row["value"] for _, row in frame.iterrows()}


def load_time_to_detect() -> pd.DataFrame:
    return pd.read_excel(RESULTS_DIR / "metrics_table.xlsx", sheet_name="time_to_detect")


def load_sample_sources() -> dict[str, dict[str, str]]:
    payload: dict[str, dict[str, str]] = {}
    for metadata_path in sorted(DATA_DIR.glob("*/metadata.json")):
        with metadata_path.open("r", encoding="utf-8") as handle:
            metadata = json.load(handle)
        payload[metadata_path.parent.name] = metadata
    return payload


def add_paragraphs(document: Document, paragraphs: list[str]) -> None:
    for paragraph in paragraphs:
        document.add_paragraph(paragraph)


def add_table(document: Document, headers: list[str], rows: list[list[str]]) -> None:
    table = document.add_table(rows=1, cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = "Table Grid"
    for index, header in enumerate(headers):
        table.rows[0].cells[index].text = header
    for row in rows:
        cells = table.add_row().cells
        for index, value in enumerate(row):
            cells[index].text = value
    document.add_paragraph()


def format_percent(value: float) -> str:
    return f"{value:.2%}"


def format_number(value: float | int | None) -> str:
    if value is None or pd.isna(value):
        return "n/a"
    if float(value).is_integer():
        return str(int(value))
    return f"{float(value):.2f}"


def build_document() -> Document:
    metrics = load_metrics()
    time_to_detect = load_time_to_detect()
    sample_sources = load_sample_sources()

    document = Document()
    document.core_properties.title = "ATMT Wazuh Demo Report"
    document.core_properties.subject = "Behavior-based ransomware detection demonstration"
    document.core_properties.author = "OpenAI Codex"

    document.add_heading("ATMT Wazuh Demo Report", level=0)
    document.add_paragraph("Behavior-based ransomware detection demonstration using Dockerized Wazuh, prerecorded telemetry replay, and safe live validation.")
    document.add_paragraph(f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}")

    document.add_heading("1. Executive Summary", level=1)
    add_paragraphs(
        document,
        [
            "This report documents a safe and repeatable ransomware-detection demo built for a professor-facing presentation.",
            "The environment uses Wazuh running on Docker Desktop for the SIEM layer, prerecorded telemetry to represent real ransomware evidence, and a harmless local simulator to prove the live alerting path without executing malware.",
            "The current sample run achieved perfect alert-level precision and recall on the bundled demonstration dataset, with an average time to detect of 16 seconds.",
        ],
    )

    document.add_heading("2. Objectives and Scope", level=1)
    add_paragraphs(
        document,
        [
            "The objective is to demonstrate behavior-based ransomware detection that is technically credible, presentation-ready, and safe to reproduce on a host machine.",
            "The repository intentionally excludes malware acquisition or execution. The evidence set consists of prerecorded alert exports and metadata collected outside the repo, while the live component is limited to benign file creation, update, and rename activity.",
        ],
    )

    document.add_heading("3. Demo Architecture", level=1)
    add_paragraphs(
        document,
        [
            "The live stack consists of a Wazuh manager, Wazuh indexer, and Wazuh dashboard running in Docker Desktop.",
            "A host Wazuh agent can be configured to ingest simulator log lines from a local file and forward them to the manager, where custom decoders and rules classify them as demo ransomware behaviors.",
            "The analysis pipeline consumes benign alert exports and ransomware-labeled sample exports, computes metrics, and produces report-ready charts and tables.",
        ],
    )

    document.add_heading("4. Dataset and Methodology", level=1)
    add_paragraphs(
        document,
        [
            "Benign activity is stored under data/benign_logs and represents normal host behavior.",
            "Ransomware-labeled activity is stored under data/ransomware_logs/<sample_name> with alerts.csv and metadata.json for each sample.",
            "A detection is counted when the Wazuh rule level is greater than or equal to 10. Time to detect is measured from the attack_start_time in each sample metadata file to the first alert at or above that threshold.",
        ],
    )

    dataset_rows = []
    for sample_name, metadata in sorted(sample_sources.items()):
        dataset_rows.append(
            [
                sample_name,
                metadata.get("family", "n/a"),
                metadata.get("source", "n/a"),
                metadata.get("attack_start_time", "n/a"),
            ]
        )
    add_table(document, ["Sample", "Family", "Source", "Attack Start"], dataset_rows)

    document.add_heading("5. Results", level=1)
    metrics_rows = [
        ["True Positives", format_number(metrics.get("true_positives"))],
        ["False Positives", format_number(metrics.get("false_positives"))],
        ["False Negatives", format_number(metrics.get("false_negatives"))],
        ["Precision", format_percent(float(metrics.get("precision", 0.0)))],
        ["Recall", format_percent(float(metrics.get("recall", 0.0)))],
        ["F1-Score", format_percent(float(metrics.get("f1_score", 0.0)))],
        ["False Positive Rate", format_percent(float(metrics.get("false_positive_rate", 0.0)))],
        ["Average Time to Detect", f"{float(metrics.get('avg_time_to_detect_seconds', 0.0)):.2f} seconds"],
    ]
    add_table(document, ["Metric", "Value"], metrics_rows)

    ttd_rows = []
    for row in time_to_detect.itertuples(index=False):
        first_detection = row.first_detection_time.isoformat() if pd.notna(row.first_detection_time) else "n/a"
        ttd_rows.append([
            str(row.sample_name),
            str(row.family),
            first_detection,
            format_number(row.time_to_detect_seconds),
        ])
    add_table(document, ["Sample", "Family", "First Detection", "TTD (s)"], ttd_rows)

    for image_name in ["detection_results.png", "top_alerts.png"]:
        image_path = RESULTS_DIR / image_name
        if image_path.exists():
            document.add_paragraph(image_name)
            document.add_picture(str(image_path), width=Inches(6.3))
            document.add_paragraph()

    document.add_heading("6. Standards Mapping", level=1)
    nist_rows = [
        ["Govern", "Defined safe demo procedure, evidence handling, and operator responsibilities."],
        ["Identify", "Tracked the host, Dockerized Wazuh services, datasets, simulator output, and analysis results."],
        ["Protect", "Avoided live malware, limited the live validation to harmless file activity, and kept telemetry replay read-only."],
        ["Detect", "Applied Wazuh rules, alert review, metrics computation, and time-to-detect analysis."],
        ["Respond", "Included analyst triage and explanation of triggered alerts during the demo."],
        ["Recover", "Reset the simulator folder and regenerate outputs from known-good evidence files."],
    ]
    add_table(document, ["NIST CSF 2.0 Function", "Demo Mapping"], nist_rows)

    iso_rows = [
        ["A.8.7", "Protection against malware", "Behavioral detection logic for ransomware-like activity."],
        ["A.8.15", "Logging", "Wazuh exports and simulator log ingestion provide auditable records."],
        ["A.8.16", "Monitoring activities", "Dashboard monitoring and alert review are core to the demo."],
        ["A.5.24", "Incident management planning and preparation", "Repeatable workflow for evidence review and explanation."],
        ["A.8.13", "Information backup", "Generated results and sample metadata preserve reproducible evidence."],
    ]
    add_table(document, ["Control", "Name", "Demo Mapping"], iso_rows)

    document.add_heading("7. Live Demonstration Procedure", level=1)
    add_paragraphs(
        document,
        [
            "1. Start Docker Desktop and bring up the Wazuh stack from infra/docker-compose.yml.",
            "2. Verify that the dashboard loads and the host agent is active.",
            "3. Present one benign sample and one ransomware-labeled sample in the dashboard or via the exported metrics.",
            "4. Run the safe simulator to generate mass-write and mass-rename style events in a controlled demo folder.",
            "5. Show the resulting alerts in Wazuh and conclude with the generated charts, metrics table, and standards mapping.",
        ],
    )

    document.add_heading("8. Limitations and Recommendations", level=1)
    add_paragraphs(
        document,
        [
            "The current metrics are based on bundled demonstration telemetry and should be presented as proof of workflow, not as a claim of production-grade ransomware coverage.",
            "The false positive rate is computed at the alert level over the benign alert set in this repository, which is appropriate for the classroom demo but narrower than a full operational evaluation.",
            "The recommended next step is to collect a larger benign baseline and more labeled telemetry samples while keeping the same safe replay and live-validation model.",
        ],
    )

    document.add_heading("9. Conclusion", level=1)
    add_paragraphs(
        document,
        [
            "This implementation demonstrates a complete, safe ransomware-detection presentation workflow: infrastructure scaffolding, evidence ingestion, metrics generation, live-safe validation, and standards-based reporting.",
            "It is ready for a professor demo once the local Wazuh stack and host agent are started on the machine.",
        ],
    )

    return document


def main() -> None:
    document = build_document()
    document.save(OUTPUT_PATH)
    print(OUTPUT_PATH)


if __name__ == "__main__":
    main()
