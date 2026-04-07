from __future__ import annotations

"""
Syslog Parser

Parses standard syslog format logs from /var/log/syslog and /var/log/messages.
"""

import re
from datetime import datetime

from secpipe.parsers.base import Parser, ParserRegistry
from secpipe.schema import Event, EventType


@ParserRegistry.register
class SyslogParser(Parser):
    """
    Parser for standard syslog format.
    
    Handles:
    - Traditional BSD syslog format
    - rsyslog format
    - systemd journal export format
    """
    
    name = "syslog"
    description = "Standard syslog parser"
    supported_extensions = [".log", ""]
    
    # BSD syslog pattern: Jan  1 00:00:00 hostname program[pid]: message
    BSD_PATTERN = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<program>[^\s\[:]+)"
        r"(?:\[(?P<pid>\d+)\])?"
        r":\s*(?P<message>.*)$"
    )
    
    # ISO timestamp variant: 2024-01-01T00:00:00 hostname program[pid]: message
    ISO_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<program>[^\s\[:]+)"
        r"(?:\[(?P<pid>\d+)\])?"
        r":\s*(?P<message>.*)$"
    )
    
    # Keywords that indicate specific event types
    EVENT_KEYWORDS = {
        EventType.SERVICE_ACTION: [
            r"started|stopped|starting|stopping|restarting",
            r"service\s+\w+\s+(start|stop|restart)",
            r"systemd.*started|stopped",
        ],
        EventType.CONFIG_CHANGE: [
            r"configuration\s+changed",
            r"config\s+reload",
            r"reloading\s+configuration",
        ],
        EventType.NETWORK_CONNECTION: [
            r"connection\s+from",
            r"connected\s+to",
            r"listening\s+on",
        ],
        EventType.FILE_MODIFY: [
            r"file\s+modified",
            r"wrote\s+to",
            r"updated\s+file",
        ],
        EventType.LOG_ACTION: [
            r"log\s+rotated",
            r"logrotate",
            r"rsyslogd.*start",
        ],
    }
    
    def __init__(self, options: dict | None = None):
        super().__init__(options)
        self.year = options.get("year") if options else None
        if self.year is None:
            self.year = datetime.now().year
    
    def parse_line(self, line: str) -> Event | None:
        """Parse a single syslog line."""
        # Try ISO format first
        match = self.ISO_PATTERN.match(line)
        if match:
            timestamp = self._parse_iso_timestamp(match.group("timestamp"))
        else:
            # Try BSD format
            match = self.BSD_PATTERN.match(line)
            if match:
                timestamp = self._parse_bsd_timestamp(match.group("timestamp"))
            else:
                return None
        
        groups = match.groupdict()
        event_type = self._infer_event_type(groups["message"])
        
        return Event(
            timestamp=timestamp,
            event_type=event_type,
            source_parser=self.name,
            raw_line=line,
            hostname=groups["hostname"],
            process_name=groups["program"],
            pid=int(groups["pid"]) if groups.get("pid") else None,
            message=groups["message"],
        )
    
    def _parse_bsd_timestamp(self, ts_str: str) -> datetime:
        """Parse BSD syslog timestamp (Jan  1 00:00:00)."""
        try:
            ts_with_year = f"{ts_str} {self.year}"
            return datetime.strptime(ts_with_year, "%b %d %H:%M:%S %Y")
        except ValueError:
            return datetime.now()
    
    def _parse_iso_timestamp(self, ts_str: str) -> datetime:
        """Parse ISO format timestamp."""
        try:
            # Handle Z suffix
            ts_str = ts_str.replace("Z", "+00:00")
            return datetime.fromisoformat(ts_str)
        except ValueError:
            return datetime.now()
    
    def _infer_event_type(self, message: str) -> EventType:
        """Infer event type from message content."""
        message_lower = message.lower()
        
        for event_type, patterns in self.EVENT_KEYWORDS.items():
            for pattern in patterns:
                if re.search(pattern, message_lower):
                    return event_type
        
        return EventType.UNKNOWN
