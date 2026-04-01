# Framework Mapping

## NIST CSF 2.0

| Function | Demo Mapping |
|---|---|
| Govern | Documented roles, safe operating procedure, and evidence handling for the demo |
| Identify | Asset list includes the public source files, derived datasets, replay artifacts, Dockerized Wazuh manager, and generated results |
| Protect | Live demo avoids malware detonation, uses a public telemetry source, and replays JSON events into Dockerized Wazuh |
| Detect | Wazuh custom rules, alert review, metrics computation, and time-to-detect analysis |
| Respond | Analyst review of triggered alerts and documented triage steps during the presentation |
| Recover | Reset the demo target folder, retain reports and evidence, and restart the environment cleanly |

## ISO 27001:2022 Annex A

| Control | Demo Mapping |
|---|---|
| A.8.7 Protection against malware | Behavioral rules and monitoring logic show malware-oriented detection capability |
| A.8.15 Logging | Wazuh alert exports and replay JSON ingestion provide auditable logging flow |
| A.8.16 Monitoring activities | Wazuh monitoring and alert triage are central to the live demonstration |
| A.5.24 Information security incident management planning and preparation | The demo defines a repeatable response flow and evidence collection process |
| A.8.13 Information backup | Results and sample metadata preserve reproducible analysis evidence |

## Positioning Statement

This demo should be described as a behavior-based detection prototype. It demonstrates monitoring, detection logic, public-source evidence analysis, and Dockerized live replay without operationalizing live malware.
