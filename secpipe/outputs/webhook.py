from __future__ import annotations

"""
Webhook Output

Sends findings to a webhook endpoint for integration with
alerting systems, SIEM, or other security tools.
"""

import os
import json
import urllib.request
import urllib.error
from datetime import datetime
from typing import Any

from secpipe.outputs.base import Output, OutputRegistry
from secpipe.schema import Finding


@OutputRegistry.register
class WebhookOutput(Output):
    """
    Export findings to a webhook endpoint.
    
    Supports generic webhooks, Slack-formatted webhooks, and
    custom payload templates.
    """
    
    name = "webhook"
    description = "Webhook HTTP POST output"
    
    def __init__(self, options: dict | None = None):
        super().__init__(options)
        
        # URL from options or environment variable (never stored in config)
        self.url = None
        if options:
            self.url = options.get("url")
            if not self.url and options.get("url_env"):
                self.url = os.environ.get(options["url_env"])
        
        self.format = options.get("format", "generic") if options else "generic"
        self.headers = options.get("headers", {}) if options else {}
        self.batch = options.get("batch", True) if options else True
        self.timeout = options.get("timeout", 30) if options else 30
    
    def write(self, findings: list[Finding]) -> None:
        """Send findings to webhook."""
        if not self.url:
            raise ValueError(
                "Webhook URL not configured. Set url in options or "
                "url_env to read from environment variable."
            )
        
        if not findings:
            return
        
        if self.batch:
            # Send all findings in one request
            payload = self._format_batch(findings)
            self._send(payload)
        else:
            # Send each finding separately
            for finding in findings:
                payload = self._format_single(finding)
                self._send(payload)
    
    def _format_batch(self, findings: list[Finding]) -> dict[str, Any]:
        """Format multiple findings for batch sending."""
        if self.format == "slack":
            return self._format_slack_batch(findings)
        return self._format_generic_batch(findings)
    
    def _format_single(self, finding: Finding) -> dict[str, Any]:
        """Format a single finding."""
        if self.format == "slack":
            return self._format_slack_single(finding)
        return self._format_generic_single(finding)
    
    def _format_generic_batch(self, findings: list[Finding]) -> dict[str, Any]:
        """Generic JSON format for batch."""
        return {
            "source": "secpipe",
            "timestamp": datetime.now().isoformat(),
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
    
    def _format_generic_single(self, finding: Finding) -> dict[str, Any]:
        """Generic JSON format for single finding."""
        return {
            "source": "secpipe",
            "timestamp": datetime.now().isoformat(),
            **finding.to_dict(),
        }
    
    def _format_slack_batch(self, findings: list[Finding]) -> dict[str, Any]:
        """Slack webhook format for batch."""
        # Group by severity
        critical = [f for f in findings if f.severity.value == "critical"]
        high = [f for f in findings if f.severity.value == "high"]
        medium = [f for f in findings if f.severity.value == "medium"]
        low = [f for f in findings if f.severity.value == "low"]
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔔 SecPipe: {len(findings)} Security Finding(s)",
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Summary:*\n"
                        f"🔴 Critical: {len(critical)} | "
                        f"🟠 High: {len(high)} | "
                        f"🟡 Medium: {len(medium)} | "
                        f"🟢 Low: {len(low)}"
                    )
                }
            },
            {"type": "divider"},
        ]
        
        # Add top findings (limit to avoid message size limits)
        for finding in findings[:5]:
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
            }.get(finding.severity.value, "⚪")
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{severity_emoji} *{finding.title}*\n"
                        f"_{finding.detection_name}_\n"
                        f"{finding.description[:200]}..."
                    )
                }
            })
        
        if len(findings) > 5:
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"_...and {len(findings) - 5} more finding(s)_"
                }]
            })
        
        return {"blocks": blocks}
    
    def _format_slack_single(self, finding: Finding) -> dict[str, Any]:
        """Slack webhook format for single finding."""
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
        }.get(finding.severity.value, "⚪")
        
        return {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{severity_emoji} {finding.title}",
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": finding.description,
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Detection:*\n{finding.detection_name}"},
                        {"type": "mrkdwn", "text": f"*Severity:*\n{finding.severity.value.upper()}"},
                        {"type": "mrkdwn", "text": f"*Source IP:*\n{finding.source_ip or 'N/A'}"},
                        {"type": "mrkdwn", "text": f"*Username:*\n{finding.username or 'N/A'}"},
                    ]
                },
            ]
        }
    
    def _send(self, payload: dict[str, Any]) -> None:
        """Send payload to webhook URL."""
        data = json.dumps(payload).encode("utf-8")
        
        headers = {
            "Content-Type": "application/json",
            **self.headers,
        }
        
        request = urllib.request.Request(
            self.url,
            data=data,
            headers=headers,
            method="POST",
        )
        
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if response.status >= 400:
                    raise RuntimeError(
                        f"Webhook returned status {response.status}"
                    )
        except urllib.error.URLError as e:
            raise RuntimeError(f"Webhook request failed: {e}")
