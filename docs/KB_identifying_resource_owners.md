# KB: Identifying Resource Owners

## Purpose

Use this guide when a SecPipe-CloudOps finding needs to be routed to the correct remediation owner.

## Primary Routing Order

Check these sources in order:

1. `owner_team` already attached to the triage finding
2. Resource naming convention
3. Cloud tag or label metadata
4. Previous ticket history
5. Team runbooks, service inventory, or project notes

## Practical Routing Rules

- Storage buckets used for exports, analytics, or shared application data usually route to the data or application platform team.
- Security groups, firewall rules, NSGs, security lists, and pathing issues usually route to network or infrastructure teams.
- IAM roles, service accounts, policies, and role assignments usually route to identity, platform, or DevOps teams.
- Backup, archive, or disaster recovery resources usually route to infrastructure or backup engineering.

## Environment-Based Guidance

- `production`: prefer confirmed ownership before closing triage
- `staging`: provisional routing is acceptable if the change is low risk
- `development`: route to the team operating the workload or deployment automation

## When Ownership Is Unclear

1. Start with the environment and resource type.
2. Review resource names for application, business unit, or team markers.
3. Check whether the issue matches a standard functional owner, such as network or identity.
4. Use the platform team as the provisional owner if no application owner can be confirmed.
5. Record in the ticket that the routing is provisional.

## Escalation Guidance

- `production` plus unclear ownership: escalate to cloud security or the platform lead
- repeated unresolved routing failures: raise as a process gap and document it in the ticket

## What to Record in the Ticket

- why the current owner was chosen
- which routing sources were checked
- whether ownership is confirmed or provisional
- what follow-up is required if ownership changes

## Example

Finding:

`[Azure] Insecure network path on /subscriptions/.../nsg-app-prod-01`

Suggested owner:

`network-security`

Reason:

The issue affects NSG rules and approved management paths, which normally belong to the network security function.
