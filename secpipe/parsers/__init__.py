"""
SecPipe Parsers Package

Provides log parsers for various sources:
- auth: Linux authentication logs (auth.log, secure)
- nginx: Nginx access logs
- syslog: Standard syslog format
- json: JSON-formatted events
- cloud: Modeled cloud security findings

Usage:
    from secpipe.parsers import ParserRegistry
    
    parser = ParserRegistry.create("auth")
    events = list(parser.parse_file("/var/log/auth.log"))
"""

from secpipe.parsers.base import Parser, ParserRegistry

# Import parsers to register them
from secpipe.parsers.auth import AuthLogParser
from secpipe.parsers.nginx import NginxParser
from secpipe.parsers.syslog import SyslogParser
from secpipe.parsers.json_events import JSONEventsParser
from secpipe.parsers.cloud_findings import CloudFindingsParser

__all__ = [
    "Parser",
    "ParserRegistry",
    "AuthLogParser",
    "NginxParser",
    "SyslogParser",
    "JSONEventsParser",
    "CloudFindingsParser",
]
