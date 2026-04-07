# SOP: Excessive IAM Permissions Response

## Purpose

Use this SOP when SecPipe-CloudOps raises `Excessive IAM permissions` or `Overly broad service account permissions` for AWS, Azure, GCP, or OCI.

## When to Use This SOP

Use this runbook when the triage finding shows:

- `classification: identity_exposure`
- `service_category: identity`
- `workflow_stage: triage`

Typical findings:

- `[Azure] Excessive IAM permissions on ...`
- `[GCP] Overly broad service account permissions on ...`

## Analyst Intake Checklist

1. Confirm the identity, resource ID, environment, priority, and owner team.
2. Record the assigned role, policy, or privilege scope.
3. Identify the expected job function for the user, service account, or automation identity.
4. Compare granted access against the minimum permissions required.
5. Open or update the remediation ticket before asking the owner team to change access.

## Evidence to Review

- Current role or policy assignment
- Scope of assignment
- Application or automation purpose
- Recent administrative activity
- Existing least-privilege baseline or team standard
- Any approved emergency or break-glass access note

## Triage Decision

Treat the finding as confirmed when:

- The identity has broader access than its current task requires
- The scope is account-wide, project-wide, subscription-wide, or tenancy-wide without justification
- The access remains active after the related maintenance or deployment activity

Treat the finding as lower urgency when:

- The access is temporary and documented
- The owner can show an approved exception with an end date
- The role is broad but currently limited to non-production test activity

## Containment Actions

1. Remove unused privileged access where it can be done safely.
2. Reduce scope before full role redesign if the workflow is sensitive.
3. Preserve emergency access only when it is approved, time-bound, and documented.

## Remediation Actions

1. Define the exact actions the identity must perform.
2. Replace broad roles with narrower roles or scoped policies.
3. Validate that the workload still functions after the change.
4. Record the final least-privilege mapping in the remediation ticket.
5. Link any related SOP or owner approval note.

## Escalation Guidance

- Production admin access with no clear justification: escalate to the cloud security lead.
- Privileged automation used across shared infrastructure: notify the platform or identity lead.
- Emergency access still active after the change window: escalate to the owning manager.

## Closure Criteria

- Broad access has been removed or reduced
- The approved permission model is documented
- The owner confirms the workload still runs
- The remediation ticket records the final role or policy state

## Example Closure Note

`Removed subscription Owner from support automation identity. Replaced with scoped role assignment for maintenance tasks only. Owner validated workflow after change.`
