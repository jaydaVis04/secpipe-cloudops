"""
SecPipe Detections Package

Provides security detections organized by MITRE ATT&CK tactics:
- brute_force: Credential access through password guessing
- persistence: Maintaining access via cron, SSH keys, services
- privilege: Privilege escalation via sudo abuse
- defense_evasion: Log clearing and security tool tampering

Usage:
    from secpipe.detections import DetectionRegistry, DetectionEngine
    
    # Create all detections
    engine = DetectionEngine()
    findings = engine.run(events)
    
    # Create specific detections
    detection = DetectionRegistry.create("brute_force_ssh")
    findings = detection.analyze(events)
"""

from secpipe.detections.base import (
    Detection,
    DetectionRegistry,
    DetectionEngine,
)

# Import detections to register them
from secpipe.detections.brute_force import (
    BruteForceSSHDetection,
    BruteForceWebDetection,
    PasswordSprayingDetection,
)
from secpipe.detections.persistence import (
    CronPersistenceDetection,
    SSHKeyPersistenceDetection,
    ServicePersistenceDetection,
    SudoersPersistenceDetection,
)
from secpipe.detections.privilege import (
    UnusualSudoDetection,
    SudoFailuresDetection,
    NewSudoerDetection,
)
from secpipe.detections.defense_evasion import (
    LogClearingDetection,
    HistoryEvasionDetection,
    SecurityToolDisableDetection,
)

__all__ = [
    "Detection",
    "DetectionRegistry",
    "DetectionEngine",
    "BruteForceSSHDetection",
    "BruteForceWebDetection",
    "PasswordSprayingDetection",
    "CronPersistenceDetection",
    "SSHKeyPersistenceDetection",
    "ServicePersistenceDetection",
    "SudoersPersistenceDetection",
    "UnusualSudoDetection",
    "SudoFailuresDetection",
    "NewSudoerDetection",
    "LogClearingDetection",
    "HistoryEvasionDetection",
    "SecurityToolDisableDetection",
]
