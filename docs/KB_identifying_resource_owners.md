# KB: Identifying Resource Owners

## Purpose

Use this guide when a SecPipe-CloudOps finding needs to be routed to the correct owner team.

## Primary Sources

Check these sources in order:

1. `owner_team` already attached to the finding
2. Resource naming convention
3. Cloud tag or label metadata
4. Existing ticket history
5. Team runbooks or service inventory

## Practical Routing Rules

- Storage buckets used for exports or data sharing usually route to the data or application platform team.
- Security groups, firewall rules, NSGs, and network path issues usually route to network or infrastructure teams.
- IAM roles, service accounts, and role assignments usually route to identity, platform, or DevOps teams depending on ownership.
- Backup-related resources usually route to infrastructure or backup engineering.

## When Ownership Is Unclear

1. Check the environment first.
2. Review the resource name for application or team identifiers.
3. Search existing documentation for the project or subscription.
4. Route to the platform team if the application owner cannot be confirmed.
5. Note in the ticket that ownership is provisional.

## Escalation Guidance

- `production` plus unclear ownership: escalate to cloud security or the platform lead.
- Repeated unresolved routing failures: raise as a process gap, not only a technical issue.

## Good Ticket Notes

Document:

- Why the current owner was chosen
- Which sources were checked
- Whether the routing is confirmed or provisional
- What follow-up is needed if ownership changes

## Example

Finding:

`[Azure] Insecure network path on /subscriptions/.../nsg-app-prod-01`

Suggested owner:

`network-security`

Reason:

The issue affects NSG rules and cross-subnet traffic controls, which are normally managed by the network security function.
