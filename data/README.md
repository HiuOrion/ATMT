# Dataset Layout

This directory stores alert exports that the analysis pipeline consumes. The repository includes small synthetic examples so the code and report can be exercised end to end.

## Expected Structure

```text
data/
  benign_logs/
    alerts.csv
  ransomware_logs/
    sample_replay_wannacry/
      alerts.csv
      metadata.json
    sample_replay_ryuk/
      alerts.csv
      metadata.json
```

## CSV Expectations

The loader accepts common Wazuh-style columns and normalizes them into a shared schema. At minimum, each CSV needs fields that map to:

- `timestamp`
- `rule.id`
- `rule.level`

Optional fields are preserved when present, including:

- `agent.name`
- `rule.description`
- `data.win.eventdata.commandLine`
- `data.win.eventdata.image`
- `mitre.id`

## Metadata Expectations

Each ransomware sample directory must include a `metadata.json` file with:

```json
{
  "family": "WannaCry replay",
  "source": "Trusted prerecorded telemetry",
  "attack_start_time": "2026-03-25T09:15:00Z",
  "notes": "Explain where the telemetry came from and why it is safe to reuse."
}
```

## Safety Guidance

- Store telemetry exports only.
- Do not store live malware or executable samples in this repository.
- Treat all sample names and family labels as evidence metadata, not as instructions for execution.
