# Presentation Notes

## Suggested 5-7 Minute Flow

1. Introduce the problem: ransomware detection and why behavior matters.
2. Show the architecture diagram and explain why Dockerized Wazuh is used.
3. Clarify that the ransomware evidence is prerecorded telemetry for safety and repeatability.
4. Open the dashboard and show one benign sample and one ransomware-labeled sample.
5. Run the safe simulator and wait for live alerts.
6. Show the generated metrics and explain precision, recall, and time to detect.
7. End with the standards mapping and limitations.

## Questions to Prepare For

- Why did you avoid live malware?
- How were the prerecorded telemetry samples validated?
- What does the live simulation prove?
- What are the limitations of alert-level false positive rate?
- How could the project be extended later with a stronger lab environment?

## Recommended Answer Shape

- State the safety reason first.
- Tie every design choice back to repeatability and evidence quality.
- Emphasize standards alignment and measurable detection performance.
