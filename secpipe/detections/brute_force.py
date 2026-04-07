from __future__ import annotations

"""
Brute Force Detections

Detects brute force authentication attempts against SSH, web services,
and other authentication mechanisms.
"""

from collections import defaultdict
from datetime import timedelta

from secpipe.detections.base import Detection, DetectionRegistry
from secpipe.schema import Event, EventType, Finding, Severity


@DetectionRegistry.register
class BruteForceSSHDetection(Detection):
    """
    Detect SSH brute force attempts.
    
    Identifies multiple failed SSH authentication attempts from a single
    source IP within a time window.
    """
    
    name = "brute_force_ssh"
    description = "Detect SSH brute force attempts"
    severity = Severity.HIGH
    mitre_attack_id = "T1110.001"
    mitre_attack_technique = "Brute Force: Password Guessing"
    categories = ["brute_force", "initial_access", "credential_access"]
    
    # Default thresholds
    DEFAULT_THRESHOLD = 5  # failures to trigger
    DEFAULT_WINDOW = 300  # seconds (5 minutes)
    
    def __init__(self, options: dict | None = None):
        super().__init__(options)
        self.threshold = self.options.get("threshold", self.DEFAULT_THRESHOLD)
        self.window_seconds = self.options.get("window_seconds", self.DEFAULT_WINDOW)
    
    def analyze(self, events: list[Event]) -> list[Finding]:
        """Analyze events for SSH brute force patterns."""
        findings = []
        
        # Filter to SSH authentication failures
        ssh_failures = [
            e for e in events
            if e.event_type == EventType.AUTH_FAILURE
            and e.source_ip
            and e.extra.get("pattern") in ["ssh_failed", "ssh_invalid_user"]
        ]
        
        if not ssh_failures:
            return []
        
        # Group by source IP
        by_ip = self.group_events_by(ssh_failures, lambda e: e.source_ip)
        
        for source_ip, ip_events in by_ip.items():
            # Sort by timestamp
            ip_events.sort(key=lambda e: e.timestamp)
            
            # Sliding window analysis
            window_events = []
            for event in ip_events:
                # Remove events outside window
                cutoff = event.timestamp - timedelta(seconds=self.window_seconds)
                window_events = [
                    e for e in window_events if e.timestamp >= cutoff
                ]
                window_events.append(event)
                
                # Check threshold
                if len(window_events) >= self.threshold:
                    # Get unique usernames targeted
                    targeted_users = set(
                        e.username for e in window_events if e.username
                    )
                    
                    finding = self.create_finding(
                        title=f"SSH brute force from {source_ip}",
                        description=(
                            f"Detected {len(window_events)} failed SSH login attempts "
                            f"from {source_ip} within {self.window_seconds} seconds. "
                            f"Targeted users: {', '.join(targeted_users) or 'unknown'}."
                        ),
                        events=window_events,
                        targeted_users=list(targeted_users),
                    )
                    finding.recommendations = [
                        f"Block IP {source_ip} at firewall",
                        "Review SSH logs for successful logins from this IP",
                        "Consider implementing fail2ban or similar rate limiting",
                        "Verify targeted accounts have strong passwords",
                    ]
                    findings.append(finding)
                    
                    # Reset window to avoid duplicate findings
                    window_events = []
        
        return findings


@DetectionRegistry.register
class BruteForceWebDetection(Detection):
    """
    Detect web authentication brute force attempts.
    
    Identifies excessive 401/403 responses to a single client IP,
    indicating potential password guessing against web applications.
    """
    
    name = "brute_force_web"
    description = "Detect web authentication brute force attempts"
    severity = Severity.MEDIUM
    mitre_attack_id = "T1110.001"
    mitre_attack_technique = "Brute Force: Password Guessing"
    categories = ["brute_force", "initial_access", "credential_access"]
    
    DEFAULT_THRESHOLD = 10
    DEFAULT_WINDOW = 60  # 1 minute
    
    # Paths commonly targeted for auth brute force
    AUTH_PATHS = [
        "/login", "/signin", "/auth", "/api/login", "/api/auth",
        "/wp-login.php", "/admin", "/administrator",
        "/user/login", "/account/login",
    ]
    
    def __init__(self, options: dict | None = None):
        super().__init__(options)
        self.threshold = self.options.get("threshold", self.DEFAULT_THRESHOLD)
        self.window_seconds = self.options.get("window_seconds", self.DEFAULT_WINDOW)
    
    def analyze(self, events: list[Event]) -> list[Finding]:
        """Analyze events for web brute force patterns."""
        findings = []
        
        # Filter to HTTP auth failures (401, 403)
        auth_failures = [
            e for e in events
            if e.event_type in [EventType.AUTH_FAILURE, EventType.HTTP_REQUEST]
            and e.http_status in [401, 403]
            and e.source_ip
        ]
        
        if not auth_failures:
            return []
        
        # Group by source IP
        by_ip = self.group_events_by(auth_failures, lambda e: e.source_ip)
        
        for source_ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda e: e.timestamp)
            
            # Check for concentrated failures
            window_events = []
            for event in ip_events:
                cutoff = event.timestamp - timedelta(seconds=self.window_seconds)
                window_events = [e for e in window_events if e.timestamp >= cutoff]
                window_events.append(event)
                
                if len(window_events) >= self.threshold:
                    # Analyze targeted paths
                    targeted_paths = set(
                        e.http_path for e in window_events if e.http_path
                    )
                    auth_path_hits = [
                        p for p in targeted_paths
                        if any(auth in p.lower() for auth in self.AUTH_PATHS)
                    ]
                    
                    # Higher severity if targeting known auth endpoints
                    severity = Severity.HIGH if auth_path_hits else Severity.MEDIUM
                    
                    finding = self.create_finding(
                        title=f"Web auth brute force from {source_ip}",
                        description=(
                            f"Detected {len(window_events)} authentication failures "
                            f"from {source_ip} within {self.window_seconds} seconds. "
                            f"Targeted paths include: {', '.join(list(targeted_paths)[:5])}."
                        ),
                        events=window_events,
                        severity=severity,
                        targeted_paths=list(targeted_paths),
                        auth_endpoints_targeted=auth_path_hits,
                    )
                    finding.recommendations = [
                        f"Implement rate limiting for IP {source_ip}",
                        "Consider CAPTCHA on authentication endpoints",
                        "Review web application firewall rules",
                        "Check for successful logins from this IP",
                    ]
                    findings.append(finding)
                    window_events = []
        
        return findings


@DetectionRegistry.register
class PasswordSprayingDetection(Detection):
    """
    Detect password spraying attacks.
    
    Password spraying targets many accounts with a few common passwords,
    producing failures across multiple usernames from similar sources.
    """
    
    name = "password_spraying"
    description = "Detect password spraying attacks"
    severity = Severity.HIGH
    mitre_attack_id = "T1110.003"
    mitre_attack_technique = "Brute Force: Password Spraying"
    categories = ["brute_force", "initial_access", "credential_access"]
    
    DEFAULT_MIN_USERS = 5  # Minimum unique users targeted
    DEFAULT_WINDOW = 600  # 10 minutes
    
    def __init__(self, options: dict | None = None):
        super().__init__(options)
        self.min_users = self.options.get("min_users", self.DEFAULT_MIN_USERS)
        self.window_seconds = self.options.get("window_seconds", self.DEFAULT_WINDOW)
    
    def analyze(self, events: list[Event]) -> list[Finding]:
        """Analyze events for password spraying patterns."""
        findings = []
        
        # Get auth failures with username
        auth_failures = [
            e for e in events
            if e.event_type == EventType.AUTH_FAILURE
            and e.username
            and e.source_ip
        ]
        
        if not auth_failures:
            return []
        
        # Group by source IP
        by_ip = self.group_events_by(auth_failures, lambda e: e.source_ip)
        
        for source_ip, ip_events in by_ip.items():
            # Get events within window
            ip_events.sort(key=lambda e: e.timestamp)
            if not ip_events:
                continue
            
            latest = ip_events[-1].timestamp
            window_events = self.filter_events_by_window(
                ip_events, self.window_seconds, latest
            )
            
            # Count unique users targeted
            targeted_users = set(e.username for e in window_events)
            
            if len(targeted_users) >= self.min_users:
                finding = self.create_finding(
                    title=f"Password spraying from {source_ip}",
                    description=(
                        f"Detected potential password spraying attack from {source_ip}. "
                        f"{len(targeted_users)} unique users targeted with "
                        f"{len(window_events)} total failures in {self.window_seconds} seconds. "
                        f"Users: {', '.join(list(targeted_users)[:10])}..."
                    ),
                    events=window_events,
                    targeted_users=list(targeted_users),
                    unique_user_count=len(targeted_users),
                )
                finding.recommendations = [
                    f"Block IP {source_ip} immediately",
                    "Force password resets for targeted accounts",
                    "Check for any successful authentications",
                    "Implement account lockout policies",
                    "Consider multi-factor authentication",
                ]
                findings.append(finding)
        
        return findings
