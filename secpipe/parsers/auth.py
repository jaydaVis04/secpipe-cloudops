from __future__ import annotations

"""
Linux Auth Log Parser

Parses /var/log/auth.log and /var/log/secure format logs.
Handles SSH authentication, sudo commands, and PAM events.
"""

import re
from datetime import datetime
from typing import Any

from secpipe.parsers.base import Parser, ParserRegistry
from secpipe.schema import Event, EventType


@ParserRegistry.register
class AuthLogParser(Parser):
    """
    Parser for Linux authentication logs.
    
    Handles common formats from:
    - /var/log/auth.log (Debian/Ubuntu)
    - /var/log/secure (RHEL/CentOS)
    """
    
    name = "auth"
    description = "Linux authentication log parser (auth.log, secure)"
    supported_extensions = [".log", ""]
    
    # Regex patterns for different auth log entries
    PATTERNS = {
        # SSH authentication
        "ssh_accepted": re.compile(
            r"(?P<process>sshd)\[(?P<pid>\d+)\]: "
            r"Accepted (?P<method>\w+) for (?P<user>\w+) from (?P<ip>[\d.]+) "
            r"port (?P<port>\d+)"
        ),
        "ssh_failed": re.compile(
            r"(?P<process>sshd)\[(?P<pid>\d+)\]: "
            r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) "
            r"from (?P<ip>[\d.]+) port (?P<port>\d+)"
        ),
        "ssh_invalid_user": re.compile(
            r"(?P<process>sshd)\[(?P<pid>\d+)\]: "
            r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"
        ),
        "ssh_disconnect": re.compile(
            r"(?P<process>sshd)\[(?P<pid>\d+)\]: "
            r"Disconnected from (?:user (?P<user>\S+) )?(?P<ip>[\d.]+) port (?P<port>\d+)"
        ),
        
        # Sudo
        "sudo_command": re.compile(
            r"(?P<process>sudo)\[?\d*\]?: \s*(?P<user>\w+) : "
            r"TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<target_user>\w+) ; "
            r"COMMAND=(?P<command>.+)"
        ),
        "sudo_failed": re.compile(
            r"(?P<process>sudo)\[?\d*\]?: \s*(?P<user>\w+) : "
            r"(?P<failures>\d+) incorrect password attempt"
        ),
        
        # PAM
        "pam_session_open": re.compile(
            r"pam_unix\((?P<service>\w+):session\): session opened for user (?P<user>\w+)"
        ),
        "pam_session_close": re.compile(
            r"pam_unix\((?P<service>\w+):session\): session closed for user (?P<user>\w+)"
        ),
        "pam_auth_failure": re.compile(
            r"pam_unix\((?P<service>\w+):auth\): authentication failure;.*"
            r"user=(?P<user>\w+)"
        ),
        
        # User/group changes
        "useradd": re.compile(
            r"(?P<process>useradd)\[(?P<pid>\d+)\]: "
            r"new user: name=(?P<user>\w+)"
        ),
        "usermod": re.compile(
            r"(?P<process>usermod)\[(?P<pid>\d+)\]: "
            r"(?:add|change) (?P<user>\w+) to group"
        ),
        "passwd_change": re.compile(
            r"(?P<process>passwd)\[(?P<pid>\d+)\]: "
            r"password changed for (?P<user>\w+)"
        ),
        
        # Cron
        "cron_edit": re.compile(
            r"(?P<process>crontab)\[(?P<pid>\d+)\]: "
            r"\((?P<user>\w+)\) (?P<action>BEGIN|END|REPLACE)"
        ),
    }
    
    # Syslog timestamp pattern (Jan  1 00:00:00 or 2024-01-01T00:00:00)
    TIMESTAMP_PATTERN = re.compile(
        r"^(?P<timestamp>"
        r"(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|"  # Jan  1 00:00:00
        r"(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"     # ISO format
        r"(?:\.\d+)?"                                 # optional fractional seconds
        r"(?:Z|[+-]\d{2}:\d{2})?)"                    # optional timezone
        r")\s+(?P<host>\S+)\s+(?P<rest>.+)"
    )
    
    def __init__(self, options: dict | None = None):
        super().__init__(options)
        self.year = options.get("year") if options else None
        if self.year is None:
            self.year = datetime.now().year
    
    def _parse_timestamp(self, ts_str: str) -> datetime:
        """Parse syslog timestamp format."""
        try:
            # ISO format
            if "T" in ts_str:
                return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            
            # Traditional syslog format (Jan  1 00:00:00)
            # Add year since it's not in the timestamp
            ts_with_year = f"{ts_str} {self.year}"
            return datetime.strptime(ts_with_year, "%b %d %H:%M:%S %Y")
        except ValueError:
            # Fallback to current time if parsing fails
            return datetime.now()
    
    def parse_line(self, line: str) -> Event | None:
        """Parse a single auth log line."""
        # Extract timestamp and hostname
        ts_match = self.TIMESTAMP_PATTERN.match(line)
        if not ts_match:
            return None
        
        timestamp = self._parse_timestamp(ts_match.group("timestamp"))
        hostname = ts_match.group("host")
        rest = ts_match.group("rest")
        
        # Try each pattern
        for pattern_name, pattern in self.PATTERNS.items():
            match = pattern.search(rest)
            if match:
                return self._create_event(
                    pattern_name, match.groupdict(), timestamp, hostname, line
                )
        
        # Return generic event if no specific pattern matched
        return Event(
            timestamp=timestamp,
            event_type=EventType.UNKNOWN,
            source_parser=self.name,
            raw_line=line,
            hostname=hostname,
            message=rest,
        )
    
    def _create_event(
        self,
        pattern_name: str,
        groups: dict[str, Any],
        timestamp: datetime,
        hostname: str,
        raw_line: str,
    ) -> Event:
        """Create an Event from a matched pattern."""
        
        # Map patterns to event types
        event_type_map = {
            "ssh_accepted": EventType.AUTH_SUCCESS,
            "ssh_failed": EventType.AUTH_FAILURE,
            "ssh_invalid_user": EventType.AUTH_FAILURE,
            "ssh_disconnect": EventType.AUTH_LOGOUT,
            "sudo_command": EventType.SUDO_COMMAND,
            "sudo_failed": EventType.AUTH_FAILURE,
            "pam_session_open": EventType.AUTH_SUCCESS,
            "pam_session_close": EventType.AUTH_LOGOUT,
            "pam_auth_failure": EventType.AUTH_FAILURE,
            "useradd": EventType.USER_MODIFY,
            "usermod": EventType.USER_MODIFY,
            "passwd_change": EventType.USER_MODIFY,
            "cron_edit": EventType.CRON_EDIT,
        }
        
        event_type = event_type_map.get(pattern_name, EventType.UNKNOWN)
        
        # Extract common fields
        event = Event(
            timestamp=timestamp,
            event_type=event_type,
            source_parser=self.name,
            raw_line=raw_line,
            hostname=hostname,
            username=groups.get("user"),
            process_name=groups.get("process"),
            pid=int(groups["pid"]) if groups.get("pid") else None,
            source_ip=groups.get("ip"),
            source_port=int(groups["port"]) if groups.get("port") else None,
            command=groups.get("command"),
            extra={
                "pattern": pattern_name,
                "method": groups.get("method"),
                "target_user": groups.get("target_user"),
                "service": groups.get("service"),
                "action": groups.get("action"),
            },
        )
        
        return event
