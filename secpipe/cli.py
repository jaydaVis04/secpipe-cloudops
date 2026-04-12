"""
SecPipe Command-Line Interface

Provides CLI commands for running the security telemetry pipeline.
"""

import argparse
import sys
from pathlib import Path

from secpipe.pipeline import Pipeline
from secpipe.parsers import ParserRegistry
from secpipe.detections import DetectionRegistry
from secpipe.outputs import OutputRegistry
from secpipe.schema import Severity


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="secpipe",
        description="Security telemetry pipeline for log analysis and detection",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Run command - full pipeline
    run_parser = subparsers.add_parser(
        "run",
        help="Run the full pipeline from config",
    )
    run_parser.add_argument(
        "--config", "-c",
        type=Path,
        default=Path("config.yaml"),
        help="Configuration file path",
    )
    
    # Ingest command
    ingest_parser = subparsers.add_parser(
        "ingest",
        help="Ingest logs from a file",
    )
    ingest_parser.add_argument(
        "--source", "-s",
        required=True,
        choices=ParserRegistry.list_parsers(),
        help="Log source type",
    )
    ingest_parser.add_argument(
        "--file", "-f",
        type=Path,
        required=True,
        help="Log file to ingest",
    )
    ingest_parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("events.jsonl"),
        help="Output file for normalized events",
    )
    
    # Detect command
    detect_parser = subparsers.add_parser(
        "detect",
        help="Run detections on events",
    )
    detect_parser.add_argument(
        "--events", "-e",
        type=Path,
        default=Path("events.jsonl"),
        help="Events file to analyze",
    )
    detect_parser.add_argument(
        "--rules", "-r",
        nargs="*",
        help="Specific detections to run",
    )
    detect_parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity to report",
    )
    detect_parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("findings.jsonl"),
        help="Output file for findings",
    )

    # Triage command
    triage_parser = subparsers.add_parser(
        "triage",
        help="Run cloud triage on normalized events",
    )
    triage_parser.add_argument(
        "--events", "-e",
        type=Path,
        default=Path("events.jsonl"),
        help="Events file to analyze",
    )
    triage_parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity to report",
    )
    triage_parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("cloud_triage_findings.jsonl"),
        help="Output file for triage findings",
    )

    # Tickets command
    tickets_parser = subparsers.add_parser(
        "tickets",
        help="Generate remediation tickets from triage findings",
    )
    tickets_parser.add_argument(
        "--findings", "-f",
        type=Path,
        default=Path("cloud_triage_findings.jsonl"),
        help="Triage findings file to convert into tickets",
    )
    tickets_parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("output/remediation_tickets.json"),
        help="Output file for remediation tickets",
    )
    
    # Report command
    report_parser = subparsers.add_parser(
        "report",
        help="Generate report from findings",
    )
    report_parser.add_argument(
        "--findings", "-f",
        type=Path,
        default=Path("findings.jsonl"),
        help="Findings file to report on",
    )
    report_parser.add_argument(
        "--format",
        choices=OutputRegistry.list_outputs(),
        default="markdown",
        help="Output format",
    )
    report_parser.add_argument(
        "--output", "-o",
        type=Path,
        help="Output file path",
    )
    
    # List command
    list_parser = subparsers.add_parser(
        "list",
        help="List available components",
    )
    list_parser.add_argument(
        "component",
        choices=["parsers", "detections", "outputs"],
        help="Component type to list",
    )
    
    # Analyze command - quick analysis of a single file
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Quick analysis of a log file",
    )
    analyze_parser.add_argument(
        "file",
        type=Path,
        help="Log file to analyze",
    )
    analyze_parser.add_argument(
        "--source", "-s",
        choices=ParserRegistry.list_parsers(),
        help="Log source type (auto-detected if not specified)",
    )
    analyze_parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format",
    )
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return 0
    
    try:
        if args.command == "run":
            return cmd_run(args)
        elif args.command == "ingest":
            return cmd_ingest(args)
        elif args.command == "detect":
            return cmd_detect(args)
        elif args.command == "triage":
            return cmd_triage(args)
        elif args.command == "tickets":
            return cmd_tickets(args)
        elif args.command == "report":
            return cmd_report(args)
        elif args.command == "list":
            return cmd_list(args)
        elif args.command == "analyze":
            return cmd_analyze(args)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    return 0


def cmd_run(args) -> int:
    """Run full pipeline from config."""
    if not args.config.exists():
        print(f"Config file not found: {args.config}", file=sys.stderr)
        return 1
    
    pipeline = Pipeline.from_config_file(args.config)
    findings = pipeline.run()
    
    summary = pipeline.get_summary()
    print(f"Events ingested: {summary['events_ingested']}")
    print(f"Findings: {summary['findings_count']}")
    
    for severity, count in summary.get("by_severity", {}).items():
        print(f"  {severity.upper()}: {count}")
    
    return 0


def cmd_ingest(args) -> int:
    """Ingest logs from file."""
    pipeline = Pipeline()
    count = pipeline.ingest(args.source, args.file)
    
    # Export normalized events
    from secpipe.outputs.jsonl import JSONLOutput
    import json
    
    with open(args.output, "w") as f:
        for event in pipeline.events:
            f.write(event.to_json() + "\n")
    
    print(f"Ingested {count} events from {args.file}")
    print(f"Events written to {args.output}")
    return 0


def cmd_detect(args) -> int:
    """Run detections on events."""
    from secpipe.schema import Event
    import json
    
    # Load events
    events = []
    with open(args.events, "r") as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                events.append(Event.from_dict(data))
    
    print(f"Loaded {len(events)} events")
    
    # Create detection engine
    min_severity = Severity(args.min_severity)
    
    if args.rules:
        detections = [
            DetectionRegistry.create(name)
            for name in args.rules
            if DetectionRegistry.get(name)
        ]
    else:
        detections = DetectionRegistry.create_all()
    
    from secpipe.detections import DetectionEngine
    engine = DetectionEngine(detections=detections, min_severity=min_severity)
    
    findings = engine.run(events)
    
    # Write findings
    with open(args.output, "w") as f:
        for finding in findings:
            f.write(finding.to_json() + "\n")
    
    print(f"Found {len(findings)} finding(s)")
    print(f"Findings written to {args.output}")
    return 0


def cmd_triage(args) -> int:
    """Run cloud triage detection on normalized events."""
    import json

    from secpipe.detections import DetectionEngine
    from secpipe.schema import Event

    events = []
    with open(args.events, "r") as f:
        for line in f:
            if line.strip():
                events.append(Event.from_dict(json.loads(line)))

    print(f"Loaded {len(events)} events")

    detection = DetectionRegistry.create("cloud_security_triage")
    engine = DetectionEngine(
        detections=[detection],
        min_severity=Severity(args.min_severity),
    )
    findings = engine.run(events)

    with open(args.output, "w") as f:
        for finding in findings:
            f.write(finding.to_json() + "\n")

    print(f"Triaged {len(findings)} finding(s)")
    print(f"Findings written to {args.output}")
    return 0


def cmd_tickets(args) -> int:
    """Generate structured remediation tickets from findings."""
    import json

    from secpipe.outputs.markdown import MarkdownOutput
    from secpipe.schema import Finding
    from secpipe.tickets import TicketGenerator

    findings = []
    with open(args.findings, "r") as f:
        for line in f:
            if line.strip():
                findings.append(Finding.from_dict(json.loads(line)))

    generator = TicketGenerator()
    tickets = generator.build_tickets(findings)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump([ticket.to_dict() for ticket in tickets], f, indent=2)

    markdown_path = args.output.with_suffix(".md")
    MarkdownOutput(
        {
            "path": str(markdown_path),
            "title": "SecPipe-CloudOps Triage Summary",
            "include_evidence": False,
        }
    ).write(findings)

    print(f"Generated {len(tickets)} remediation ticket(s)")
    print(f"Tickets written to {args.output}")
    print(f"Human-readable summary written to {markdown_path}")
    return 0


def cmd_report(args) -> int:
    """Generate report from findings."""
    from secpipe.schema import Finding
    import json
    
    # Load findings
    findings = []
    with open(args.findings, "r") as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                findings.append(Finding.from_dict(data))
    
    # Determine output path
    output_path = args.output
    if output_path is None:
        extensions = {
            "jsonl": ".jsonl",
            "sqlite": ".db",
            "markdown": ".md",
            "webhook": None,
        }
        ext = extensions.get(args.format, ".out")
        if ext:
            output_path = Path(f"report{ext}")
    
    # Create output
    options = {"path": str(output_path)} if output_path else {}
    output = OutputRegistry.create(args.format, options)
    output.write(findings)
    
    if output_path:
        print(f"Report written to {output_path}")
    else:
        print("Report sent")
    
    return 0


def cmd_list(args) -> int:
    """List available components."""
    if args.component == "parsers":
        print("Available parsers:")
        for name in ParserRegistry.list_parsers():
            parser_class = ParserRegistry.get(name)
            print(f"  {name}: {parser_class.description}")
    
    elif args.component == "detections":
        print("Available detections:")
        for name in DetectionRegistry.list_detections():
            det_class = DetectionRegistry.get(name)
            print(f"  {name}")
            print(f"    {det_class.description}")
            if det_class.mitre_attack_id:
                print(f"    MITRE: {det_class.mitre_attack_id}")
    
    elif args.component == "outputs":
        print("Available outputs:")
        for name in OutputRegistry.list_outputs():
            output_class = OutputRegistry.get(name)
            print(f"  {name}: {output_class.description}")
    
    return 0


def cmd_analyze(args) -> int:
    """Quick analysis of a log file."""
    # Auto-detect source type if not specified
    source_type = args.source
    if source_type is None:
        filename = args.file.name.lower()
        if "auth" in filename or "secure" in filename:
            source_type = "auth"
        elif "nginx" in filename or "access" in filename:
            source_type = "nginx"
        elif "syslog" in filename or "messages" in filename:
            source_type = "syslog"
        elif filename.endswith(".json") or filename.endswith(".jsonl"):
            source_type = "json"
        else:
            print("Could not auto-detect log type. Use --source to specify.", file=sys.stderr)
            return 1
    
    print(f"Analyzing {args.file} as {source_type} log...")
    
    # Run pipeline
    pipeline = Pipeline()
    count = pipeline.ingest(source_type, args.file)
    findings = pipeline.detect()
    
    print(f"Parsed {count} events")
    print(f"Found {len(findings)} finding(s)")
    print()
    
    if args.format == "text":
        # Text output
        if not findings:
            print("No security findings detected.")
        else:
            for finding in findings:
                severity_symbol = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢",
                }.get(finding.severity.value, "⚪")
                
                print(f"{severity_symbol} [{finding.severity.value.upper()}] {finding.title}")
                print(f"   {finding.description}")
                if finding.recommendations:
                    print(f"   Recommendation: {finding.recommendations[0]}")
                print()
    
    elif args.format == "json":
        import json
        output = {
            "file": str(args.file),
            "events_parsed": count,
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(output, indent=2, default=str))
    
    elif args.format == "markdown":
        output = OutputRegistry.create("markdown", {
            "path": args.file.stem + "_findings.md"
        })
        output.write(findings)
        print(f"Report written to {args.file.stem}_findings.md")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
