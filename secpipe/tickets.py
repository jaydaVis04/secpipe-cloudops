from __future__ import annotations

"""
Remediation Ticket Generation

Builds structured remediation tickets from SecPipe findings.
"""

from dataclasses import asdict, dataclass
import json

from secpipe.schema import Finding


@dataclass
class RemediationTicket:
    """Structured remediation ticket derived from a triaged finding."""

    title: str
    provider: str
    resource_id: str
    issue_type: str
    severity: str
    priority: str
    owner_team: str
    environment: str
    description: str
    recommended_action: str
    status: str
    escalation_path: str
    resource_type: str
    classification: str
    service_category: str
    owner_queue: str

    def to_dict(self) -> dict[str, str]:
        """Serialize the ticket to a dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize the ticket to JSON."""
        return json.dumps(self.to_dict())


class TicketGenerator:
    """Convert SecPipe findings into ticket-like remediation records."""

    DEFAULT_STATUS = "Open"

    def build_ticket(self, finding: Finding) -> RemediationTicket:
        """Build a single remediation ticket from a finding."""
        provider = str(finding.extra.get("provider", "unknown"))
        resource_id = str(finding.extra.get("resource_id", "unknown"))
        resource_type = str(finding.extra.get("resource_type", "unknown"))
        issue_type = str(finding.extra.get("issue_type", finding.title))
        priority = str(finding.extra.get("priority", "P4"))
        owner_team = str(finding.extra.get("owner_team", "unassigned"))
        owner_queue = str(finding.extra.get("owner_queue", owner_team))
        environment = str(finding.extra.get("environment", "unknown"))
        classification = str(
            finding.extra.get("classification", "cloud_misconfiguration")
        )
        service_category = str(
            finding.extra.get("service_category", "configuration")
        )
        description = finding.description
        recommended_action = self._get_recommended_action(finding)

        return RemediationTicket(
            title=f"[{provider}] {issue_type} on {resource_id}",
            provider=provider,
            resource_id=resource_id,
            issue_type=issue_type,
            severity=finding.severity.value,
            priority=priority,
            owner_team=owner_team,
            environment=environment,
            description=description,
            recommended_action=recommended_action,
            status=self.DEFAULT_STATUS,
            escalation_path=self._build_escalation_path(
                priority=priority,
                owner_team=owner_team,
                environment=environment,
            ),
            resource_type=resource_type,
            classification=classification,
            service_category=service_category,
            owner_queue=owner_queue,
        )

    def build_tickets(self, findings: list[Finding]) -> list[RemediationTicket]:
        """Build remediation tickets for a list of findings."""
        return [self.build_ticket(finding) for finding in findings]

    def _get_recommended_action(self, finding: Finding) -> str:
        """Return the most useful next action for the ticket."""
        if finding.recommendations:
            return finding.recommendations[0]

        guidance = finding.extra.get("remediation_guidance")
        if isinstance(guidance, list) and guidance:
            return str(guidance[0])

        return "Review the finding, assign an owner, and reduce the exposed risk."

    def _build_escalation_path(
        self,
        priority: str,
        owner_team: str,
        environment: str,
    ) -> str:
        """Create a simple escalation path string."""
        if priority == "P1":
            return (
                f"Page {owner_team} immediately, notify the cloud security lead, "
                f"and track remediation through incident coordination for {environment}."
            )
        if environment.lower() == "production":
            return (
                f"Route to {owner_team}, escalate to the cloud security lead if not acknowledged, "
                "and track to production remediation closure."
            )
        return (
            f"Route to {owner_team}, review in the next remediation cycle, "
            "and track to closure."
        )
