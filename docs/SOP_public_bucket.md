# SOP: Public Storage Bucket Response

## Purpose

Use this procedure when SecPipe-CloudOps flags a public storage bucket in AWS, Azure, GCP, or OCI.

## Scope

- Public object storage exposure
- Buckets containing internal, customer, or backup data
- Production, staging, and development environments

## Trigger

Typical finding title:

`[AWS] Public storage bucket on arn:aws:s3:::customer-export-prod`

Typical severity:

- `critical` for production buckets with sensitive data exposure
- `medium` or `high` for non-production exposure depending on the content

## Triage Steps

1. Confirm the provider, bucket name, environment, and owner team from the finding.
2. Validate whether the bucket is intentionally public.
3. Review the finding details and compare them to the provider policy or ACL settings.
4. Check whether the bucket contains sensitive, internal-only, or customer-related data.
5. Determine whether the exposure is current or was already corrected.

## Evidence to Review

- Bucket access policy
- Public access block or equivalent control
- Object ACL settings if used
- Recent storage configuration changes
- Data classification or project notes

## Containment

1. Remove anonymous or overly broad public access.
2. Enable the provider's public access protection control where available.
3. If business access is still required, move public content into a separate approved bucket.

## Remediation

1. Apply least-privilege bucket policy changes.
2. Confirm the correct sharing model with the application or data owner.
3. Review recent access logs if exposure involved sensitive data.
4. Update the remediation ticket with the final configuration change.

## Escalation

- `P1` or production customer data exposure: page the owning team and notify the cloud security lead.
- Non-production exposure: route to the owning team and track through the next remediation cycle.

## Closure Criteria

- Public access has been removed or formally approved
- The owning team confirms the final bucket configuration
- The remediation ticket is updated with the change reference
- Any follow-up documentation has been linked

## Notes

Do not assume a public bucket is always malicious. Some buckets are intentionally public. The goal is to verify intent, reduce unnecessary exposure, and document the final state.
