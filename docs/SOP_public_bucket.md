# SOP: Public Storage Bucket Response

## Purpose

Use this SOP when SecPipe-CloudOps raises a `Public storage bucket` finding for AWS S3, GCP Cloud Storage, Azure storage, or OCI Object Storage.

## When to Use This SOP

Use this runbook when the triage finding shows:

- `classification: storage_exposure`
- `issue_type: Public storage bucket`
- `workflow_stage: triage`

Typical finding:

`[AWS] Public storage bucket on S3 Bucket arn:aws:s3:::customer-export-prod`

## Analyst Intake Checklist

1. Confirm provider, resource ID, environment, severity, priority, and owner team from the SecPipe-CloudOps finding.
2. Check whether the bucket is expected to be public for a valid business reason.
3. Review the finding details and recommended action in the triage output.
4. Identify whether the bucket contains customer, internal, backup, or test data.
5. Open or update the remediation ticket before requesting owner action.

## Evidence to Review

- Bucket policy or access policy
- Public access block or equivalent provider control
- ACL settings if the provider still uses them
- Recent configuration changes
- Data classification notes
- Existing exceptions or approved public-sharing cases

## Triage Decision

Treat the finding as confirmed when:

- Public access is currently enabled
- The bucket stores data that should not be public
- There is no approved exception documented by the owner team

Treat the finding as informational only when:

- The bucket is intentionally public
- The data is approved for public hosting
- The owner confirms the configuration and documents the decision

## Containment Actions

1. Remove anonymous or broad public access where safe to do so.
2. Enable the provider control that blocks public access by default.
3. If public hosting is still needed, separate approved public content from internal data.

## Remediation Actions

1. Apply least-privilege policy changes.
2. Confirm the intended sharing model with the application or data owner.
3. Review storage access logs if sensitive data may have been exposed.
4. Record the final change in the remediation ticket.
5. Link the ticket back to this SOP if the issue required manual triage.

## Escalation Guidance

- `P1` or production sensitive data exposure: page the owner team and notify the cloud security lead.
- `P2` production exposure: route immediately and require acknowledgement.
- Non-production exposure: track through the normal remediation queue unless sensitive data is involved.

## Closure Criteria

- Public exposure has been removed or formally approved
- The owning team confirms the final configuration
- The remediation ticket includes change details and closure notes
- Any exception or business justification is documented

## Example Closure Note

`Public read access removed from arn:aws:s3:::customer-export-prod. Block Public Access enabled. Owner confirmed bucket is internal-only. Ticket closed after validation.`
