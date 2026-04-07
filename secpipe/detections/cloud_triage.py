from __future__ import annotations

"""
Cloud Security Triage Detection

Turns modeled cloud findings into structured triage findings that can be
reviewed, routed, and tracked through remediation.
"""

from secpipe.detections.base import Detection, DetectionRegistry
from secpipe.schema import Event, Finding, Severity


@DetectionRegistry.register
class CloudSecurityTriageDetection(Detection):
    """
    Triage cloud posture findings into analyst-friendly SecPipe findings.

    Each cloud event becomes one finding with classification, priority,
    owner routing, and remediation guidance attached.
    """

    name = "cloud_security_triage"
    description = "Cloud security triage for multi-cloud posture findings"
    severity = Severity.MEDIUM
    categories = ["cloud", "triage"]

    PRIORITY_MAP = {
        Severity.CRITICAL: "P1",
        Severity.HIGH: "P2",
        Severity.MEDIUM: "P3",
        Severity.LOW: "P4",
    }

    ISSUE_CLASSIFICATION_MAP = {
        "public storage bucket": "storage_exposure",
        "ssh open to the internet": "network_exposure",
        "rdp exposed publicly": "network_exposure",
        "insecure network path": "network_exposure",
        "excessive iam permissions": "identity_exposure",
        "overly broad service account permissions": "identity_exposure",
    }

    def analyze(self, events: list[Event]) -> list[Finding]:
        """Convert cloud events into triaged findings."""
        findings = []

        for event in events:
            if event.source_parser != "cloud":
                continue

            findings.append(self._triage_event(event))

        return findings

    def _triage_event(self, event: Event) -> Finding:
        """Build one triage finding from one cloud event."""
        provider = str(event.extra.get("provider", "unknown"))
        resource_id = str(event.extra.get("resource_id", event.file_path or "unknown"))
        resource_type = str(event.extra.get("resource_type", "unknown"))
        issue_type = str(event.extra.get("issue_type", "unknown"))
        environment = str(event.extra.get("environment", "unknown"))
        owner_team = str(event.extra.get("owner_team", "unassigned"))
        details = str(event.extra.get("details", event.message or ""))
        recommended_action = str(
            event.extra.get(
                "recommended_action",
                "Review the finding and reduce the exposed risk.",
            )
        )

        severity = self._resolve_severity(event)
        priority = self.PRIORITY_MAP[severity]
        classification = self.ISSUE_CLASSIFICATION_MAP.get(
            issue_type.lower(),
            "cloud_misconfiguration",
        )

        title = f"[{provider}] {issue_type} on {resource_type} {resource_id}"
        description = (
            f"{provider} reported a {issue_type.lower()} issue affecting "
            f"{resource_type} {resource_id} in the {environment} environment. "
            f"Current owner routing points to {owner_team}. {details}"
        )

        remediation_guidance = self._build_remediation_guidance(
            classification,
            recommended_action,
            environment,
        )

        finding = self.create_finding(
            title=title,
            description=description,
            events=[event],
            severity=severity,
            provider=provider,
            resource_id=resource_id,
            resource_type=resource_type,
            issue_type=issue_type,
            environment=environment,
            owner_team=owner_team,
            classification=classification,
            priority=priority,
            remediation_guidance=remediation_guidance,
            workflow_stage="triage",
        )
        finding.recommendations = remediation_guidance
        return finding

    def _resolve_severity(self, event: Event) -> Severity:
        """Resolve severity from cloud event metadata."""
        raw_severity = str(event.extra.get("severity", self.severity.value)).lower()
        try:
            return Severity(raw_severity)
        except ValueError:
            return self.severity

    def _build_remediation_guidance(
        self,
        classification: str,
        recommended_action: str,
        environment: str,
    ) -> list[str]:
        """Return concise remediation guidance for analysts and owners."""
        guidance = [recommended_action]

        if classification == "storage_exposure":
            guidance.append(
                "Validate whether the resource is intended to be public and document the exposure decision."
            )
        elif classification == "identity_exposure":
            guidance.append(
                "Review granted roles against least-privilege expectations and remove unused permissions."
            )
        elif classification == "network_exposure":
            guidance.append(
                "Confirm the approved management or application traffic path before changing access rules."
            )
        else:
            guidance.append(
                "Review the resource configuration and compare it against the team's baseline."
            )

        if environment.lower() == "production":
            guidance.append(
                "Track this remediation through production change control and verify closure after the fix is applied."
            )
        else:
            guidance.append(
                "Record the planned fix owner and validate the update in the next review cycle."
            )

        return guidance
