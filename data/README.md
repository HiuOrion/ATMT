# Dataset Layout

This directory stores the public-source telemetry and the derived artifacts that the analysis pipeline consumes.

## Expected Structure

```text
data/
  benign_logs/
    alerts.csv
  public_sources/
    lockbit_ransomware/
      public_lockbit_source.yml
      public_lockbit_sysmon.log
      summary.json
  public_replay/
    lockbit_public.jsonl
  ransomware_logs/
    lockbit_public/
      alerts.csv
      metadata.json
```

## CSV Expectations

The loader accepts common Wazuh-style columns and normalizes them into a shared schema. The generated CSVs already match the required structure.

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
  "family": "Lockbit public replay",
  "source": "https://github.com/splunk/attack_data/tree/master/datasets/malware/lockbit_ransomware",
  "attack_start_time": "2023-01-16T11:43:50.537416200Z",
  "notes": "Derived from the public Splunk attack_data Lockbit Sysmon log."
}
```

## Safety Guidance

- Store telemetry exports and derived replay artifacts only.
- Do not store live malware or executable samples in this repository.
- Treat all sample names and family labels as evidence metadata, not as instructions for execution.
