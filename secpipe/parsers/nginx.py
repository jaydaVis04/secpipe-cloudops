"""
Nginx Access Log Parser

Parses Nginx access logs in common and combined formats.
"""

import re
from datetime import datetime

from secpipe.parsers.base import Parser, ParserRegistry
from secpipe.schema import Event, EventType


@ParserRegistry.register
class NginxParser(Parser):
    """
    Parser for Nginx access logs.
    
    Supports:
    - Common log format
    - Combined log format (includes referer and user-agent)
    - JSON format (when configured in Nginx)
    """
    
    name = "nginx"
    description = "Nginx access log parser"
    supported_extensions = [".log", ".access"]
    
    # Combined log format pattern
    # Example: 192.168.1.1 - user [01/Jan/2024:12:00:00 +0000] "GET /path HTTP/1.1" 200 1234 "http://referer" "Mozilla/5.0"
    COMBINED_PATTERN = re.compile(
        r'^(?P<ip>[\d.]+)\s+'           # Client IP
        r'(?P<ident>\S+)\s+'             # Ident (usually -)
        r'(?P<user>\S+)\s+'              # Remote user
        r'\[(?P<timestamp>[^\]]+)\]\s+'  # Timestamp
        r'"(?P<method>\w+)\s+'           # HTTP method
        r'(?P<path>\S+)\s+'              # Request path
        r'(?P<protocol>[^"]+)"\s+'       # Protocol
        r'(?P<status>\d+)\s+'            # Status code
        r'(?P<bytes>\d+|-)\s*'           # Bytes sent
        r'(?:"(?P<referer>[^"]*)"\s*)?'  # Referer (optional)
        r'(?:"(?P<user_agent>[^"]*)")?'  # User agent (optional)
    )
    
    # Common log format (without referer/user-agent)
    COMMON_PATTERN = re.compile(
        r'^(?P<ip>[\d.]+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+'
        r'(?P<path>\S+)\s+'
        r'(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<bytes>\d+|-)'
    )
    
    # Nginx timestamp format
    TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
    
    def parse_line(self, line: str) -> Event | None:
        """Parse a single Nginx access log line."""
        # Try combined format first
        match = self.COMBINED_PATTERN.match(line)
        if not match:
            # Fall back to common format
            match = self.COMMON_PATTERN.match(line)
        
        if not match:
            return None
        
        groups = match.groupdict()
        
        # Parse timestamp
        try:
            timestamp = datetime.strptime(
                groups["timestamp"], self.TIMESTAMP_FORMAT
            )
        except ValueError:
            # Try without timezone
            try:
                ts_str = groups["timestamp"].split()[0]
                timestamp = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                timestamp = datetime.now()
        
        # Parse bytes (can be '-' for no content)
        bytes_sent = groups.get("bytes", "0")
        bytes_sent = int(bytes_sent) if bytes_sent != "-" else 0
        
        # Parse status code
        status_code = int(groups.get("status", 0))
        
        # Determine event type based on status code
        if 200 <= status_code < 300:
            event_type = EventType.HTTP_REQUEST
        elif status_code == 401 or status_code == 403:
            event_type = EventType.AUTH_FAILURE
        elif status_code == 404:
            event_type = EventType.HTTP_REQUEST
        elif status_code >= 500:
            event_type = EventType.HTTP_REQUEST
        else:
            event_type = EventType.HTTP_REQUEST
        
        # Extract username (if not '-')
        username = groups.get("user")
        if username == "-":
            username = None
        
        # Extract user agent
        user_agent = groups.get("user_agent")
        if user_agent == "-":
            user_agent = None
        
        return Event(
            timestamp=timestamp,
            event_type=event_type,
            source_parser=self.name,
            raw_line=line,
            source_ip=groups["ip"],
            username=username,
            http_method=groups["method"],
            http_path=groups["path"],
            http_status=status_code,
            http_user_agent=user_agent,
            http_bytes=bytes_sent,
            extra={
                "protocol": groups.get("protocol"),
                "referer": groups.get("referer"),
                "ident": groups.get("ident"),
            },
        )
    
    def is_suspicious_path(self, path: str) -> bool:
        """Check if a request path looks suspicious."""
        suspicious_patterns = [
            r"\.\.\/",           # Path traversal
            r"\/etc\/passwd",    # Sensitive files
            r"\/\.env",          # Environment files
            r"\/wp-admin",       # WordPress admin
            r"\/phpMyAdmin",     # Database admin
            r"\/\.git",          # Git directory
            r"\/\.svn",          # SVN directory
            r"<script",          # XSS attempt
            r"SELECT.*FROM",     # SQL injection
            r"UNION.*SELECT",    # SQL injection
            r"\/shell",          # Web shell
            r"\/cmd",            # Command execution
            r"\/eval\(",         # Code execution
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        return False
    
    def is_scanner_user_agent(self, user_agent: str | None) -> bool:
        """Check if user agent belongs to a known scanner."""
        if not user_agent:
            return False
        
        scanner_patterns = [
            r"nikto",
            r"sqlmap",
            r"nmap",
            r"masscan",
            r"dirbuster",
            r"gobuster",
            r"wfuzz",
            r"burp",
            r"zap",
            r"acunetix",
            r"nessus",
            r"openvas",
        ]
        
        user_agent_lower = user_agent.lower()
        for pattern in scanner_patterns:
            if pattern in user_agent_lower:
                return True
        return False
