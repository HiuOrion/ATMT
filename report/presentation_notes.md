# Presentation Notes

## Suggested 5-7 Minute Flow

1. Introduce the problem: ransomware detection and why behavior matters.
2. Show the architecture diagram and explain why Dockerized Wazuh is used.
3. Clarify that the ransomware evidence comes from Splunk's public Lockbit Sysmon dataset and is replayed safely.
4. Show one benign background sample and the Lockbit-derived sample in the report outputs.
5. Start the Dockerized Wazuh manager and tail `alerts.json`.
6. Run the public replay script and wait for live alerts.
7. Show the generated metrics and explain precision, recall, and time to detect.
8. End with the standards mapping and limitations.

## Questions to Prepare For

- Why did you avoid live malware?
- Why did you choose a public dataset?
- What does the live replay prove?
- What are the limitations of alert-level false positive rate?
- How could the project be extended later with a stronger lab environment?

## Recommended Answer Shape

- State the safety reason first.
- Tie every design choice back to repeatability and evidence quality.
- Emphasize standards alignment and measurable detection performance.
