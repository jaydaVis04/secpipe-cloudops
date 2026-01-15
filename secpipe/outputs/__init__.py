"""
SecPipe Outputs Package

Provides output sinks for exporting findings:
- jsonl: Newline-delimited JSON files
- sqlite: SQLite database for querying
- markdown: Human-readable reports
- webhook: HTTP POST to alerting systems

Usage:
    from secpipe.outputs import OutputRegistry
    
    # Create output
    output = OutputRegistry.create("jsonl", {"path": "findings.jsonl"})
    output.write(findings)
"""

from secpipe.outputs.base import Output, OutputRegistry
from secpipe.outputs.jsonl import JSONLOutput
from secpipe.outputs.sqlite import SQLiteOutput
from secpipe.outputs.markdown import MarkdownOutput
from secpipe.outputs.webhook import WebhookOutput

__all__ = [
    "Output",
    "OutputRegistry",
    "JSONLOutput",
    "SQLiteOutput",
    "MarkdownOutput",
    "WebhookOutput",
]
