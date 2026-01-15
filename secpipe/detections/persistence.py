"""
Persistence Detections

Detects techniques attackers use to maintain access to compromised systems,
including cron jobs, SSH keys, and service installation.
"""

import re
from collections import defaultdict

from secpipe.detections.base import Detection, DetectionRegistry
from secpipe.schema import Event, EventType, Finding, Severity


@DetectionRegistry.register
class CronPersistenceDetection(Detection):
    """
    Detect crontab modifications that may indicate persistence.
    
    Monitors for new cron jobs added by users or modifications to
    system cron directories.
    """
    
    name = "cron_persistence"
    description = "Detect suspicious crontab modifications"
    severity = Severity.MEDIUM
    mitre_attack_id = "T1053.003"
    mitre_attack_technique = "Scheduled Task/Job: Cron"
    categories = ["persistence", "execution"]
    
    # Suspicious patterns in cron commands
    SUSPICIOUS_PATTERNS = [
        r"curl.*\|.*sh",           # Curl pipe to shell
        r"wget.*\|.*sh",           # Wget pipe to shell
        r"nc\s+-[el]",             # Netcat listener
        r"bash\s+-i",              # Interactive bash
        r"/dev/tcp/",              # Bash TCP device
        r"python.*-c.*import",     # Python one-liner
        r"base64\s+-d",            # Base64 decode
        r"chmod\s+[47]",           # Chmod with suid/world-writable
        r"\$\(.*\)",               # Command substitution
    ]
    
    def analyze(self, events: list[Event]) -> list[Finding]:
        """Analyze events for cron persistence."""
        findings = []
        
        # Find cron-related events
        cron_events = [
            e for e in events
            if e.event_type == EventType.CRON_EDIT
            or (e.process_name and "cron" in e.process_name.lower())
            or (e.file_path and "/cron" in e.file_path)
        ]
        
        if not cron_events:
            return []
        
        # Group by user
        by_user = self.group_events_by(cron_events, lambda e: e.username or "unknown")
        
        for username, user_events in by_user.items():
            # Check for suspicious patterns in commands
            suspicious_events = []
            for event in user_events:
                command = event.command or event.message or ""
                for pattern in self.SUSPICIOUS_PATTERNS:
                    if re.search(pattern, command, re.IGNORECASE):
                        suspicious_events.append(event)
                        break
            
            # Report cron modifications
            if user_events:
                severity = Severity.HIGH if suspicious_events else Severity.MEDIUM
                
                finding = self.create_finding(
                    title=f"Crontab modification by {username}",
                    description=(
                        f"User {username} modified crontab with "
                        f"{len(user_events)} event(s). "
                        + (f"Suspicious patterns detected in {len(suspicious_events)} event(s)."
                           if suspicious_events else "Review for legitimacy.")
                    ),
                    events=user_events,
                    severity=severity,
                    suspicious_commands=[e.command for e in suspicious_events if e.command],
                )
                finding.recommendations = [
                    f"Review crontab for user {username}: crontab -l -u {username}",
                    "Check /var/log/cron for execution history",
                    "Verify legitimacy with system owner",
                    "Check /etc/cron.d/ for system-level cron jobs",
                ]
                findings.append(finding)
        
        return findings


@DetectionRegistry.register  
class SSHKeyPersistenceDetection(Detection):
    """
    Detect SSH authorized_keys modifications.
    
    New SSH keys added to authorized_keys can provide persistent access
    without passwords.
    """
    
    name = "ssh_key_persistence"
    description = "Detect SSH authorized_keys modifications"
    severity = Severity.HIGH
    mitre_attack_id = "T1098.004"
    mitre_attack_technique = "Account Manipulation: SSH Authorized Keys"
    categories = ["persistence", "credential_access"]
    
    def analyze(self, events: list[Event]) -> list[Finding]:
        """Analyze events for SSH key persistence."""
        findings = []
        
        # Look for authorized_keys modifications
        ssh_key_events = [
            e for e in events
            if (e.file_path and "authorized_keys" in e.file_path)
            or (e.message and "authorized_keys" in (e.message or ""))
            or (e.command and "authorized_keys" in (e.command or ""))
        ]
        
        if not ssh_key_events:
            return []
        
        # Group by affected user/path
        by_path = self.group_events_by(
            ssh_key_events,
            lambda e: e.file_path or e.username or "unknown"
        )
        
        for path, path_events in by_path.items():
            # Extract the user from path if possible
            user_match = re.search(r"/home/(\w+)/", path)
            affected_user = user_match.group(1) if user_match else "unknown"
            
            finding = self.create_finding(
                title=f"SSH authorized_keys modified for {affected_user}",
                description=(
                    f"Modification detected to SSH authorized_keys "
                    f"({'for ' + affected_user if affected_user != 'unknown' else 'path: ' + path}). "
                    f"This could indicate persistence mechanism installation."
                ),
                events=path_events,
                affected_user=affected_user,
                file_path=path,
            )
            finding.recommendations = [
                f"Review authorized_keys: cat {path}",
                "Compare keys to known legitimate keys",
                "Check SSH logs for connections using new keys",
                "Consider removing unauthorized keys",
            ]
            findings.append(finding)
        
        return findings


@DetectionRegistry.register
class ServicePersistenceDetection(Detection):
    """
    Detect new systemd service installation.
    
    Attackers may install malicious systemd services for persistence.
    """
    
    name = "service_persistence"
    description = "Detect suspicious systemd service installation"
    severity = Severity.HIGH
    mitre_attack_id = "T1543.002"
    mitre_attack_technique = "Create or Modify System Process: Systemd Service"
    categories = ["persistence", "privilege_escalation"]
    
    # Suspicious service characteristics
    SUSPICIOUS_PATTERNS = [
        r"ExecStart=.*/tmp/",           # Running from /tmp
        r"ExecStart=.*curl|wget",       # Download in service
        r"ExecStart=.*/dev/shm/",       # Running from shared memory
        r"User=root",                    # Running as root
        r"ExecStart=.*bash\s+-[ci]",    # Interactive/command bash
    ]
    
    def analyze(self, events: list[Event]) -> list[Finding]:
        """Analyze events for service persistence."""
        findings = []
        
        # Find service-related events
        service_events = [
            e for e in events
            if e.event_type == EventType.SERVICE_ACTION
            or (e.file_path and ("/systemd/" in e.file_path or ".service" in e.file_path))
            or (e.process_name and e.process_name in ["systemctl", "systemd"])
        ]
        
        if not service_events:
            return []
        
        # Analyze each service event
        for event in service_events:
            content = f"{event.command or ''} {event.message or ''} {event.file_path or ''}"
            
            suspicious_matches = []
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    suspicious_matches.append(pattern)
            
            severity = Severity.CRITICAL if suspicious_matches else Severity.MEDIUM
            
            service_name = "unknown"
            if event.file_path:
                match = re.search(r"(\w+)\.service", event.file_path)
                if match:
                    service_name = match.group(1)
            
            finding = self.create_finding(
                title=f"Systemd service modification: {service_name}",
                description=(
                    f"Detected systemd service activity for '{service_name}'. "
                    + (f"Suspicious patterns found: {len(suspicious_matches)}. "
                       if suspicious_matches else "")
                    + "Review for legitimacy."
                ),
                events=[event],
                severity=severity,
                service_name=service_name,
                suspicious_patterns=suspicious_matches,
            )
            finding.recommendations = [
                f"Review service: systemctl cat {service_name}",
                f"Check service status: systemctl status {service_name}",
                "List all services: systemctl list-units --type=service",
                "Check /etc/systemd/system/ for unexpected services",
            ]
            findings.append(finding)
        
        return findings


@DetectionRegistry.register
class SudoersPersistenceDetection(Detection):
    """
    Detect modifications to sudoers configuration.
    
    Changes to /etc/sudoers or /etc/sudoers.d/ can grant persistent
    elevated privileges.
    """
    
    name = "sudoers_modification"
    description = "Detect sudoers file modifications"
    severity = Severity.CRITICAL
    mitre_attack_id = "T1548.003"
    mitre_attack_technique = "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"
    categories = ["persistence", "privilege_escalation"]
    
    def analyze(self, events: list[Event]) -> list[Finding]:
        """Analyze events for sudoers modifications."""
        findings = []
        
        # Find sudoers-related events
        sudoers_events = [
            e for e in events
            if (e.file_path and "sudoers" in e.file_path)
            or (e.command and "visudo" in (e.command or ""))
            or (e.message and "sudoers" in (e.message or "").lower())
        ]
        
        if not sudoers_events:
            return []
        
        finding = self.create_finding(
            title="Sudoers configuration modified",
            description=(
                f"Detected {len(sudoers_events)} event(s) modifying sudoers configuration. "
                f"This could indicate privilege escalation or persistence. "
                f"Immediate review required."
            ),
            events=sudoers_events,
        )
        finding.recommendations = [
            "Review /etc/sudoers with visudo",
            "Check /etc/sudoers.d/ for unexpected files",
            "Compare against known good configuration",
            "Review sudo logs: grep sudo /var/log/auth.log",
        ]
        findings.append(finding)
        
        return findings
