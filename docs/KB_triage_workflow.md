# KB: Cloud Triage Workflow

## Overview

SecPipe-CloudOps extends SecPipe's original ingest and detection pipeline into a cloud security triage workflow:

`input -> triage -> remediation -> documentation -> deployment`

## Workflow

1. `cloud/cloud_findings.json` provides modeled multi-cloud findings.
2. The `cloud` parser converts those records into normalized SecPipe events.
3. The `cloud_security_triage` detection turns cloud events into structured triage findings.
4. The `tickets` command converts triage findings into remediation ticket records.
5. SOP and KB documents support repeatable analyst response.

## Commands

Ingest cloud findings:

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

## What Triage Adds

- Classification
- Severity handling
- Priority mapping
- Owner routing
- Remediation guidance
- Structured finding output

## Priority Guidance

- `P1`: critical production exposure requiring immediate action
- `P2`: high-severity issue that should be routed quickly
- `P3`: medium-severity issue tracked through normal remediation
- `P4`: low-risk issue tracked for cleanup

## Analyst Expectations

- Validate the finding before escalating
- Confirm the correct owner team
- Route production issues faster than non-production issues
- Attach evidence and recommended action to the ticket
- Link relevant SOP or KB documentation

## Common Finding Types

- Public storage bucket
- Excessive IAM permissions
- Overly broad service account permissions
- SSH open to the internet
- RDP exposed publicly
- Insecure network path

## Notes

This workflow is intentionally simple. It models how a cloud security team could process posture findings without pretending to be a full enterprise CSPM platform.
