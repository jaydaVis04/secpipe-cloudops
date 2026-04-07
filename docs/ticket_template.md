# Remediation Ticket Template

Use this template when documenting a SecPipe-CloudOps remediation task in a ticketing system or internal tracker.

## Required Fields

- **Title:** `[Provider] Issue Type on Resource ID`
- **Provider:** AWS | Azure | GCP | OCI
- **Resource ID:** Full resource identifier when available
- **Issue Type:** Example: `Public storage bucket`
- **Severity:** `critical` | `high` | `medium` | `low`
- **Priority:** `P1` | `P2` | `P3` | `P4`
- **Owner Team:** Team currently responsible for remediation
- **Environment:** `production` | `staging` | `development`
- **Description:** Analyst summary of the issue and why it matters
- **Recommended Action:** Immediate next step for the owner
- **Status:** `Open`, `In Progress`, `Blocked`, or `Closed`
- **Escalation Path:** Who to notify if the issue is not acknowledged

## Example

**Title:** `[AWS] Public storage bucket on arn:aws:s3:::customer-export-prod`

**Provider:** AWS

**Resource ID:** `arn:aws:s3:::customer-export-prod`

**Issue Type:** Public storage bucket

**Severity:** critical

**Priority:** P1

**Owner Team:** data-platform

**Environment:** production

**Description:** Public read access is enabled on a production bucket that stores customer export data.

**Recommended Action:** Enable block public access and remove anonymous read permissions.

**Status:** Open

**Escalation Path:** Page data-platform immediately and notify the cloud security lead.

## Analyst Notes

- Attach the SecPipe-CloudOps finding or output record
- Link the matching SOP if one exists
- Record how owner routing was determined
- Update the ticket after validation and after remediation
