# Remediation Ticket Template

Use this template when creating or updating a SecPipe-CloudOps remediation ticket in an internal tracker.

## Required Fields

- **Title:** `[Provider] Issue Type on Resource ID`
- **Provider:** `AWS` | `Azure` | `GCP` | `OCI`
- **Resource ID:** Full resource identifier
- **Resource Type:** Example: `S3 Bucket`
- **Issue Type:** Example: `Public storage bucket`
- **Severity:** `critical` | `high` | `medium` | `low`
- **Priority:** `P1` | `P2` | `P3` | `P4`
- **Classification:** Example: `storage_exposure`
- **Service Category:** `storage` | `network` | `identity` | `configuration`
- **Owner Team:** Current remediation owner
- **Owner Queue:** Team or queue label used for routing
- **Environment:** `production` | `staging` | `development`
- **Description:** Analyst summary of the issue and risk
- **Recommended Action:** Immediate next step for the owner
- **Status:** `Open` | `In Progress` | `Blocked` | `Closed`
- **Escalation Path:** Who to notify if the issue is not acknowledged

## Example

**Title:** `[AWS] Public storage bucket on arn:aws:s3:::customer-export-prod`

**Provider:** AWS

**Resource ID:** `arn:aws:s3:::customer-export-prod`

**Resource Type:** S3 Bucket

**Issue Type:** Public storage bucket

**Severity:** critical

**Priority:** P1

**Classification:** storage_exposure

**Service Category:** storage

**Owner Team:** data-platform

**Owner Queue:** data-platform-aws

**Environment:** production

**Description:** Public read access is enabled on a production bucket that stores customer export data.

**Recommended Action:** Enable block public access and remove anonymous read permissions.

**Status:** Open

**Escalation Path:** Page data-platform immediately and notify the cloud security lead.

## Analyst Notes

- Attach the SecPipe-CloudOps finding or output record
- Link the matching SOP or KB article
- Record how owner routing was determined
- Update the ticket after validation and after remediation
