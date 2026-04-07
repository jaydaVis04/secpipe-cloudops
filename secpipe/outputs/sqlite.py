from __future__ import annotations

"""
SQLite Output

Exports findings to a SQLite database for querying and analysis.
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime

from secpipe.outputs.base import Output, OutputRegistry
from secpipe.schema import Finding


@OutputRegistry.register
class SQLiteOutput(Output):
    """
    Export findings to SQLite database.
    
    Creates a queryable database of findings with proper schema
    and indexes for efficient analysis.
    """
    
    name = "sqlite"
    description = "SQLite database output"
    
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id TEXT UNIQUE,
        detection_name TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL,
        mitre_attack_id TEXT,
        mitre_attack_technique TEXT,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        source_ip TEXT,
        username TEXT,
        hostname TEXT,
        event_count INTEGER,
        evidence_events TEXT,
        raw_samples TEXT,
        recommendations TEXT,
        extra TEXT,
        exported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_findings_detection ON findings(detection_name);
    CREATE INDEX IF NOT EXISTS idx_findings_first_seen ON findings(first_seen);
    CREATE INDEX IF NOT EXISTS idx_findings_source_ip ON findings(source_ip);
    CREATE INDEX IF NOT EXISTS idx_findings_username ON findings(username);
    """
    
    def __init__(self, options: dict | None = None):
        super().__init__(options)
        self.path = Path(options.get("path", "findings.db")) if options else Path("findings.db")
        self._conn = None
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize database with schema."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(str(self.path))
        conn.executescript(self.SCHEMA)
        conn.commit()
        conn.close()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.path))
        return self._conn
    
    def write(self, findings: list[Finding]) -> None:
        """Write findings to database."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        for finding in findings:
            data = finding.to_dict()
            
            cursor.execute("""
                INSERT OR REPLACE INTO findings (
                    finding_id, detection_name, title, description,
                    severity, mitre_attack_id, mitre_attack_technique,
                    first_seen, last_seen, source_ip, username, hostname,
                    event_count, evidence_events, raw_samples,
                    recommendations, extra, exported_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data["finding_id"],
                data["detection_name"],
                data["title"],
                data["description"],
                data["severity"],
                data.get("mitre_attack_id"),
                data.get("mitre_attack_technique"),
                data.get("first_seen"),
                data.get("last_seen"),
                data.get("source_ip"),
                data.get("username"),
                data.get("hostname"),
                data.get("event_count"),
                json.dumps(data.get("evidence_events", [])),
                json.dumps(data.get("raw_samples", [])),
                json.dumps(data.get("recommendations", [])),
                json.dumps(data.get("extra", {})),
                datetime.now().isoformat(),
            ))
        
        conn.commit()
    
    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        """Execute a query and return results as dictionaries."""
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(sql, params)
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_summary(self) -> dict:
        """Get summary statistics from the database."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Total findings
        cursor.execute("SELECT COUNT(*) FROM findings")
        total = cursor.fetchone()[0]
        
        # By severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM findings 
            GROUP BY severity
        """)
        by_severity = {row[0]: row[1] for row in cursor.fetchall()}
        
        # By detection
        cursor.execute("""
            SELECT detection_name, COUNT(*) as count 
            FROM findings 
            GROUP BY detection_name
            ORDER BY count DESC
        """)
        by_detection = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Unique source IPs
        cursor.execute("""
            SELECT COUNT(DISTINCT source_ip) 
            FROM findings 
            WHERE source_ip IS NOT NULL
        """)
        unique_ips = cursor.fetchone()[0]
        
        return {
            "total_findings": total,
            "by_severity": by_severity,
            "by_detection": by_detection,
            "unique_source_ips": unique_ips,
        }
    
    def close(self) -> None:
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
