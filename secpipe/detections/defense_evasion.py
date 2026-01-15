"""
Defense Evasion Detections

Detects techniques used to avoid detection, including log clearing,
timestomping, and disabling security tools.
"""

import re

from secpipe.detections.base import Detection, DetectionRegistry
from secpipe.schema import Event, EventType, Finding, Severity


@DetectionRegistry.register
class LogClearingDetection(Detection):
    """
    Detect log file clearing or manipulation.
    
    Attackers often clear logs to hide their activities after
    compromising a system.
    """
    
    name = "log_clearing"
    description = "Detect log file clearing attempts"
    severity = Severity.CRITICAL
    mitre_attack_id = "T1070.002"
    mitre_attack_technique = "Indicator Removal: Clear Linux or Mac System Logs"
    categories = ["defense_evasion"]
    
    # Log files commonly targeted
    SENSITIVE_LOGS = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/audit/audit.log",
        "/var/log/wtmp",
        "/var/log/btmp",
        "/var/log/lastlog",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/apache2/access.log",
        "/var/log/httpd/access_log",
        "~/.bash_history",
        "/root/.bash_history",
    ]
    
    # Commands that indicate log manipulation
    CLEAR_PATTERNS = [
        r">\s*/var/log/",           # Truncate log file
        r"cat\s*/dev/null\s*>\s*/var/log",
        r"truncate.*-s\s*0.*log",
        r"rm\s+-[rf]*\s*/var/log",
        r"shred.*log",
        r"wipe.*log",
        r"echo\s*>\s*/var/log",
        r"history\s+-c",            # Clear bash history
        r"unset\s+HISTFILE",
        r"export\s+HISTSIZE=0",
        r"ln\s+-sf\s*/dev/null.*history",
    ]
    
    def analyze(self, events: list[Event]) -> list[Finding]:
        """Analyze events for log clearing."""
        findings = []
        
        # Check for file delete events on log files
        log_delete_events = [
            e for e in events
            if e.event_type == EventType.FILE_DELETE
            and e.file_path
            and any(log in e.file_path for log in self.SENSITIVE_LOGS)
        ]
        
        # Check commands for log clearing patterns
        command_events = [
            e for e in events
            if e.command or e.message
        ]
        
        log_clear_events = []
        for event in command_events:
            text = f"{event.command or ''} {event.message or ''}"
            for pattern in self.CLEAR_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    log_clear_events.append(event)
                    break
        
        # Check for LOG_ACTION events (from syslog parser)
        log_action_events = [
            e for e in events
            if e.event_type == EventType.LOG_ACTION
            and e.message
            and any(word in e.message.lower() for word in ["clear", "truncat", "delet", "remov"])
        ]
        
        all_suspicious = log_delete_events + log_clear_events + log_action_events
        
        if all_suspicious:
            # Deduplicate by event ID
            seen = set()
            unique_events = []
            for e in all_suspicious:
                if e.event_id not in seen:
                    seen.add(e.event_id)
                    unique_events.append(e)
            
            finding = self.create_finding(
                title="Log clearing activity detected",
                description=(
                    f"Detected {len(unique_events)} event(s) indicating log manipulation. "
                    f"This is a strong indicator of attacker activity attempting to "
                    f"cover their tracks."
                ),
                events=unique_events,
                affected_logs=list(set(
                    e.file_path for e in unique_events if e.file_path
                )),
            )
            finding.recommendations = [
                "Preserve remaining logs immediately",
                "Check for backup logs (logrotate archives)",
                "Review other evidence sources (network logs, SIEM)",
                "Consider forensic acquisition of system",
                "Investigate all activity by associated users",
            ]
            findings.append(finding)
        
        return findings


@DetectionRegistry.register
class HistoryEvasionDetection(Detection):
    """
    Detect attempts to evade command history logging.
    
    Attackers may disable or clear bash history to hide their commands.
    """
    
    name = "history_evasion"
    description = "Detect command history evasion"
    severity = Severity.HIGH
    mitre_attack_id = "T1070.003"
    mitre_attack_technique = "Indicator Removal: Clear Command History"
    categories = ["defense_evasion"]
    
    EVASION_PATTERNS = [
        r"history\s+-c",
        r"history\s+-w\s*/dev/null",
        r"unset\s+HISTFILE",
        r"HISTFILE=/dev/null",
        r"HISTSIZE=0",
        r"HISTFILESIZE=0",
        r"set\s+\+o\s+history",
        r"shopt\s+-u\s+histappend",
        r"rm.*\.bash_history",
        r"cat\s*/dev/null\s*>.*history",
    ]
    
    def analyze(self, events: list[Event]) -> list[Finding]:
        """Analyze events for history evasion."""
        findings = []
        
        evasion_events = []
        for event in events:
            text = f"{event.command or ''} {event.message or ''}"
            for pattern in self.EVASION_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    evasion_events.append(event)
                    break
        
        if evasion_events:
            users = set(e.username for e in evasion_events if e.username)
            
            finding = self.create_finding(
                title="Command history evasion detected",
                description=(
                    f"Detected {len(evasion_events)} attempt(s) to disable or clear "
                    f"command history. Users involved: {', '.join(users) or 'unknown'}. "
                    f"This is suspicious behavior indicating potential malicious activity."
                ),
                events=evasion_events,
                involved_users=list(users),
            )
            finding.recommendations = [
                "Review all activity by involved users",
                "Check for other signs of compromise",
                "Consider centralized command logging (auditd)",
                "Preserve any remaining history files",
            ]
            findings.append(finding)
        
        return findings


@DetectionRegistry.register
class SecurityToolDisableDetection(Detection):
    """
    Detect attempts to disable security tools.
    
    Attackers may stop antivirus, firewalls, or other security services.
    """
    
    name = "security_tool_disable"
    description = "Detect security tool tampering"
    severity = Severity.CRITICAL
    mitre_attack_id = "T1562.001"
    mitre_attack_technique = "Impair Defenses: Disable or Modify Tools"
    categories = ["defense_evasion"]
    
    # Security-related services
    SECURITY_SERVICES = [
        "auditd", "rsyslog", "syslog-ng",
        "fail2ban", "ufw", "firewalld", "iptables",
        "clamav", "clamd", "freshclam",
        "ossec", "wazuh", "suricata", "snort",
        "apparmor", "selinux",
        "crowdstrike", "falcon-sensor",
        "carbonblack", "sentinel",
    ]
    
    def analyze(self, events: list[Event]) -> list[Finding]:
        """Analyze events for security tool disabling."""
        findings = []
        
        disable_events = []
        for event in events:
            text = f"{event.command or ''} {event.message or ''}"
            text_lower = text.lower()
            
            # Check for stop/disable commands on security services
            for service in self.SECURITY_SERVICES:
                if service in text_lower:
                    # Look for stop/disable indicators
                    if re.search(
                        rf"(stop|disable|kill|mask|remove).*{service}|{service}.*(stop|disable)",
                        text_lower
                    ):
                        disable_events.append(event)
                        break
        
        if disable_events:
            services_affected = []
            for event in disable_events:
                text = f"{event.command or ''} {event.message or ''}".lower()
                for service in self.SECURITY_SERVICES:
                    if service in text:
                        services_affected.append(service)
            
            finding = self.create_finding(
                title="Security tool tampering detected",
                description=(
                    f"Detected {len(disable_events)} attempt(s) to disable security tools. "
                    f"Services affected: {', '.join(set(services_affected))}. "
                    f"This is a critical indicator of active compromise."
                ),
                events=disable_events,
                services_affected=list(set(services_affected)),
            )
            finding.recommendations = [
                "Immediately verify status of security services",
                "Check for unauthorized changes to security configs",
                "Assume system may be compromised",
                "Initiate incident response procedures",
                "Preserve evidence before restoration",
            ]
            findings.append(finding)
        
        return findings
