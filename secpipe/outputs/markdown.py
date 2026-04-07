from __future__ import annotations

"""
Markdown Report Output

Generates human-readable Markdown reports from findings.
"""

from pathlib import Path
from datetime import datetime
from collections import defaultdict

from secpipe.outputs.base import Output, OutputRegistry
from secpipe.schema import Finding, Severity


@OutputRegistry.register
class MarkdownOutput(Output):
    """
    Export findings as a Markdown report.
    
    Generates a structured, human-readable report suitable for
    sharing with stakeholders or inclusion in documentation.
    """
    
    name = "markdown"
    description = "Markdown report output"
    
    SEVERITY_EMOJI = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🟢",
    }
    
    def __init__(self, options: dict | None = None):
        super().__init__(options)
        self.path = Path(options.get("path", "findings.md")) if options else Path("findings.md")
        self.title = options.get("title", "Security Findings Report") if options else "Security Findings Report"
        self.include_evidence = options.get("include_evidence", True) if options else True
    
    def write(self, findings: list[Finding]) -> None:
        """Write findings to Markdown report."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        
        report_lines = []
        
        # Header
        report_lines.append(f"# {self.title}")
        report_lines.append("")
        report_lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"**Total Findings:** {len(findings)}")
        report_lines.append("")
        
        # Executive Summary
        report_lines.extend(self._generate_summary(findings))
        
        # Findings by severity
        report_lines.append("## Detailed Findings")
        report_lines.append("")
        
        # Group by severity
        by_severity = defaultdict(list)
        for finding in findings:
            by_severity[finding.severity].append(finding)
        
        # Output in severity order
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            if severity in by_severity:
                report_lines.extend(
                    self._generate_severity_section(severity, by_severity[severity])
                )
        
        # Write to file
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))
    
    def _generate_summary(self, findings: list[Finding]) -> list[str]:
        """Generate executive summary section."""
        lines = [
            "## Executive Summary",
            "",
        ]
        
        if not findings:
            lines.append("No security findings detected.")
            lines.append("")
            return lines
        
        # Count by severity
        severity_counts = defaultdict(int)
        for finding in findings:
            severity_counts[finding.severity] += 1
        
        lines.append("### Severity Distribution")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = severity_counts.get(severity, 0)
            emoji = self.SEVERITY_EMOJI.get(severity, "")
            lines.append(f"| {emoji} {severity.value.upper()} | {count} |")
        lines.append("")
        
        # Top detections
        detection_counts = defaultdict(int)
        for finding in findings:
            detection_counts[finding.detection_name] += 1
        
        top_detections = sorted(
            detection_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        lines.append("### Top Detection Types")
        lines.append("")
        for detection, count in top_detections:
            lines.append(f"- **{detection}**: {count} finding(s)")
        lines.append("")
        
        # Unique indicators
        unique_ips = set()
        unique_users = set()
        for finding in findings:
            if finding.source_ip:
                unique_ips.add(finding.source_ip)
            if finding.username:
                unique_users.add(finding.username)
        
        lines.append("### Key Indicators")
        lines.append("")
        lines.append(f"- **Unique Source IPs:** {len(unique_ips)}")
        lines.append(f"- **Unique Usernames:** {len(unique_users)}")
        lines.append("")
        
        return lines
    
    def _generate_severity_section(
        self,
        severity: Severity,
        findings: list[Finding]
    ) -> list[str]:
        """Generate section for a severity level."""
        emoji = self.SEVERITY_EMOJI.get(severity, "")
        lines = [
            f"### {emoji} {severity.value.upper()} Severity ({len(findings)})",
            "",
        ]
        
        for i, finding in enumerate(findings, 1):
            lines.extend(self._generate_finding(finding, i))
        
        return lines
    
    def _generate_finding(self, finding: Finding, index: int) -> list[str]:
        """Generate content for a single finding."""
        lines = [
            f"#### {index}. {finding.title}",
            "",
            f"**Detection:** {finding.detection_name}",
            "",
            finding.description,
            "",
        ]
        
        # MITRE ATT&CK
        if finding.mitre_attack_id:
            lines.append(
                f"**MITRE ATT&CK:** [{finding.mitre_attack_id}]"
                f"(https://attack.mitre.org/techniques/{finding.mitre_attack_id.replace('.', '/')}) "
                f"- {finding.mitre_attack_technique or ''}"
            )
            lines.append("")
        
        # Context
        context_items = []
        if finding.source_ip:
            context_items.append(f"**Source IP:** `{finding.source_ip}`")
        if finding.username:
            context_items.append(f"**Username:** `{finding.username}`")
        if finding.hostname:
            context_items.append(f"**Hostname:** `{finding.hostname}`")
        if finding.first_seen:
            context_items.append(f"**First Seen:** {finding.first_seen}")
        if finding.last_seen:
            context_items.append(f"**Last Seen:** {finding.last_seen}")
        if finding.event_count:
            context_items.append(f"**Event Count:** {finding.event_count}")
        
        if context_items:
            lines.append("**Context:**")
            for item in context_items:
                lines.append(f"- {item}")
            lines.append("")
        
        # Recommendations
        if finding.recommendations:
            lines.append("**Recommendations:**")
            for rec in finding.recommendations:
                lines.append(f"1. {rec}")
            lines.append("")
        
        # Evidence (optional)
        if self.include_evidence and finding.raw_samples:
            lines.append("<details>")
            lines.append("<summary>Evidence Samples</summary>")
            lines.append("")
            lines.append("```")
            for sample in finding.raw_samples[:3]:
                lines.append(sample[:200] + "..." if len(sample) > 200 else sample)
            lines.append("```")
            lines.append("")
            lines.append("</details>")
            lines.append("")
        
        lines.append("---")
        lines.append("")
        
        return lines
