# KB: Cloud Triage Workflow

## Overview

SecPipe-CloudOps extends the original SecPipe pipeline into a cloud security workflow:

`input -> triage -> remediation -> documentation -> deployment`

This is not a full CSPM platform. It is a small, explainable model of how a cloud security team can process posture findings across AWS, GCP, Azure, and OCI.

## End-to-End Flow

1. `cloud/cloud_findings.json` provides modeled findings from multiple cloud providers.
2. The `cloud` parser converts each finding into the existing SecPipe `Event` schema.
3. The `cloud_security_triage` detection converts those events into structured triage findings.
4. The ticket generator converts triaged findings into remediation records.
5. SOP and KB documents support the analyst handoff and owner response.
6. Docker and Kubernetes artifacts package the workflow for local and container-based execution.

## Core Commands

Ingest modeled cloud findings:

```bash
.venv/bin/python -m secpipe.cli ingest --source cloud --file cloud/cloud_findings.json --output output/cloud_events.jsonl
```

Run cloud triage:

```bash
.venv/bin/python -m secpipe.cli triage --events output/cloud_events.jsonl --output output/cloud_triage_findings.jsonl
```

Generate remediation tickets:

```bash
.venv/bin/python -m secpipe.cli tickets --findings output/cloud_triage_findings.jsonl --output output/remediation_tickets.json
```

## What the Triage Layer Adds

The triage finding keeps the normal SecPipe `Finding` shape but adds cloud-specific context in structured fields:

- `classification`
- `service_category`
- `priority`
- `owner_team`
- `owner_queue`
- `triage_status`
- `triage_notes`
- `remediation_guidance`
- `workflow_stage`

## Priority Guidance

- `P1`: critical issue or production exposure requiring immediate owner response
- `P2`: high-risk issue requiring prompt remediation
- `P3`: issue tracked through the standard remediation queue
- `P4`: low-risk cleanup item

## Analyst Workflow

1. Validate that the cloud finding is current.
2. Confirm the provider, resource, and environment.
3. Review the triage classification and priority.
4. Confirm or correct `owner_team`.
5. Create or update the remediation ticket.
6. Link the matching SOP or KB article.
7. Track the issue to documented closure.

## Common Finding Types

- Public storage bucket
- Excessive IAM permissions
- Overly broad service account permissions
- SSH open to the internet
- RDP exposed publicly
- Insecure network path

## Expected Outputs

- `output/cloud_events.jsonl`
- `output/cloud_triage_findings.jsonl`
- `output/remediation_tickets.json`

## Notes

This workflow is intentionally conservative. It demonstrates cloud security triage, owner routing, remediation tracking, and documentation discipline without claiming enterprise-scale automation.
