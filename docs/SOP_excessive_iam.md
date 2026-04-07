# SOP: Excessive IAM Permissions Response

## Purpose

Use this procedure when SecPipe-CloudOps identifies excessive IAM permissions, overly broad service account permissions, or subscription or project-level admin access that exceeds the job function.

## Scope

- AWS IAM roles and policies
- Azure role assignments
- GCP IAM roles and service accounts
- OCI IAM policies and dynamic groups

## Trigger

Typical finding titles:

- `[Azure] Excessive IAM permissions on ...`
- `[GCP] Overly broad service account permissions on ...`

## Triage Steps

1. Confirm the identity, assigned role or policy, environment, and owner team.
2. Determine what the identity is supposed to do.
3. Compare the granted permissions to the actual business need.
4. Check whether the access is temporary, emergency, or left behind from a previous task.
5. Review recent activity if the access appears unusually broad for the role.

## Evidence to Review

- Current role or policy assignment
- Scope of the assignment
- Automation job or application purpose
- Recent deployment or administrative history
- Existing least-privilege baseline for the team

## Containment

1. Remove unused admin-level access where safe to do so.
2. Replace broad built-in roles with smaller scoped roles.
3. If immediate removal is risky, reduce scope first and coordinate a final cleanup with the owner.

## Remediation

1. Define the minimum actions the identity requires.
2. Replace the broad assignment with a least-privilege set of permissions.
3. Validate the workload after the permission change.
4. Record the final role mapping in the remediation ticket.

## Escalation

- Production admin access with no clear justification: escalate to the cloud security lead.
- Emergency access that is still active after the maintenance window: escalate to the owning manager.

## Closure Criteria

- Broad access has been removed or reduced
- The new role scope is documented
- The owner confirms the workflow still functions
- The ticket includes the final permission model

## Notes

IAM findings are not only about compromise risk. They also demonstrate least-privilege reasoning, separation of duties, and basic cloud governance.
