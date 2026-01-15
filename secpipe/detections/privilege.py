"""
Privilege Escalation Detections

Detects attempts to gain elevated privileges through sudo abuse,
unusual privilege usage, and other escalation techniques.
"""

from collections import defaultdict
from datetime import timedelta

from secpipe.detections.base import Detection, DetectionRegistry
from secpipe.schema import Event, EventType, Finding, Severity


@DetectionRegistry.register
class UnusualSudoDetection(Detection):
    """
    Detect unusual sudo usage patterns.
    
    Identifies users executing sudo who don't normally use it,
    or suspicious sudo commands.
    """
    
    name = "unusual_sudo"
    description = "Detect unusual sudo usage patterns"
    severity = Severity.MEDIUM
    mitre_attack_id = "T1548.003"
    mitre_attack_technique = "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"
    categories = ["privilege_escalation"]
    
    # High-risk commands when run via sudo
    HIGH_RISK_COMMANDS = [
        "bash", "sh", "zsh", "fish",           # Shells
        "su", "passwd", "useradd", "usermod",  # User management
        "chmod", "chown",                       # Permissions
        "visudo",                               # Sudo config
        "systemctl", "service",                 # Service management
        "apt", "yum", "dnf", "pip",            # Package managers
        "curl", "wget",                         # Network downloads
        "nc", "netcat", "ncat",                # Network tools
        "python", "perl", "ruby",              # Script interpreters
        "dd", "mkfs",                           # Disk operations
        "iptables", "firewall-cmd",            # Firewall
    ]
    
    def analyze(self, events: list[Event]) -> list[Finding]:
        """Analyze events for unusual sudo patterns."""
        findings = []
        
        # Get sudo events
        sudo_events = [
            e for e in events
            if e.event_type == EventType.SUDO_COMMAND
            and e.username
        ]
        
        if not sudo_events:
            return []
        
        # Group by user
        by_user = self.group_events_by(sudo_events, lambda e: e.username)
        
        for username, user_events in by_user.items():
            # Analyze commands for risk
            high_risk_events = []
            for event in user_events:
                command = event.command or ""
                command_base = command.split()[0] if command else ""
                
                # Check if base command is high-risk
                for risk_cmd in self.HIGH_RISK_COMMANDS:
                    if risk_cmd in command_base.lower():
                        high_risk_events.append(event)
                        break
            
            if high_risk_events:
                commands = [e.command for e in high_risk_events[:5] if e.command]
                target_users = set(
                    e.extra.get("target_user") for e in high_risk_events
                    if e.extra.get("target_user")
                )
                
                finding = self.create_finding(
                    title=f"High-risk sudo commands by {username}",
                    description=(
                        f"User {username} executed {len(high_risk_events)} high-risk "
                        f"sudo command(s). Commands include: {', '.join(commands[:3])}. "
                        f"Target users: {', '.join(target_users) if target_users else 'root'}."
                    ),
                    events=high_risk_events,
                    commands_executed=commands,
                    target_users=list(target_users),
                )
                finding.recommendations = [
                    f"Review sudo access for user {username}",
                    "Check /var/log/auth.log for full command history",
                    "Verify commands were authorized",
                    "Consider principle of least privilege",
                ]
                findings.append(finding)
        
        return findings


@DetectionRegistry.register
class SudoFailuresDetection(Detection):
    """
    Detect repeated sudo authentication failures.
    
    Multiple sudo failures may indicate password guessing or
    unauthorized privilege escalation attempts.
    """
    
    name = "sudo_failures"
    description = "Detect repeated sudo authentication failures"
    severity = Severity.MEDIUM
    mitre_attack_id = "T1548.003"
    mitre_attack_technique = "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"
    categories = ["privilege_escalation", "credential_access"]
    
    DEFAULT_THRESHOLD = 3
    
    def __init__(self, options: dict | None = None):
        super().__init__(options)
        self.threshold = self.options.get("threshold", self.DEFAULT_THRESHOLD)
    
    def analyze(self, events: list[Event]) -> list[Finding]:
        """Analyze events for sudo failures."""
        findings = []
        
        # Get sudo failures
        sudo_failures = [
            e for e in events
            if e.event_type == EventType.AUTH_FAILURE
            and e.extra.get("pattern") == "sudo_failed"
            and e.username
        ]
        
        if not sudo_failures:
            return []
        
        # Group by user
        by_user = self.group_events_by(sudo_failures, lambda e: e.username)
        
        for username, user_events in by_user.items():
            if len(user_events) >= self.threshold:
                finding = self.create_finding(
                    title=f"Sudo authentication failures for {username}",
                    description=(
                        f"User {username} had {len(user_events)} failed sudo "
                        f"authentication attempts. This may indicate password guessing "
                        f"or unauthorized escalation attempts."
                    ),
                    events=user_events,
                    severity=Severity.HIGH if len(user_events) >= 5 else Severity.MEDIUM,
                    failure_count=len(user_events),
                )
                finding.recommendations = [
                    f"Investigate activity by user {username}",
                    "Check for successful sudo after failures",
                    "Verify user should have sudo access",
                    "Consider temporary sudo access suspension",
                ]
                findings.append(finding)
        
        return findings


@DetectionRegistry.register
class NewSudoerDetection(Detection):
    """
    Detect new users being granted sudo privileges.
    
    Adding users to sudo/wheel groups grants significant privileges
    and should be monitored.
    """
    
    name = "new_sudoer"
    description = "Detect users added to sudo group"
    severity = Severity.HIGH
    mitre_attack_id = "T1548.003"
    mitre_attack_technique = "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"
    categories = ["privilege_escalation", "persistence"]
    
    def analyze(self, events: list[Event]) -> list[Finding]:
        """Analyze events for new sudo users."""
        findings = []
        
        # Look for usermod adding to sudo/wheel
        sudo_group_events = [
            e for e in events
            if e.event_type == EventType.USER_MODIFY
            and e.extra.get("pattern") == "usermod"
        ]
        
        # Also check messages for sudo/wheel group additions
        group_events = [
            e for e in events
            if e.message and (
                "sudo" in e.message.lower() or "wheel" in e.message.lower()
            ) and "group" in e.message.lower()
        ]
        
        all_events = sudo_group_events + group_events
        
        for event in all_events:
            finding = self.create_finding(
                title=f"User added to privileged group",
                description=(
                    f"User modification detected that may grant sudo access. "
                    f"User: {event.username or 'unknown'}. "
                    f"Review to ensure this change is authorized."
                ),
                events=[event],
                affected_user=event.username,
            )
            finding.recommendations = [
                "Verify user should have sudo access",
                "Check who made the change: grep usermod /var/log/auth.log",
                "Review current sudo group: getent group sudo",
                "Audit sudo usage going forward",
            ]
            findings.append(finding)
        
        return findings
