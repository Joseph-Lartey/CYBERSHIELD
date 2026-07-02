"""
Incident Logger
---------------
Records every threat and response action as a structured JSON log entry.

WHY STRUCTURED JSON LOGS?
Plain text logs ("THREAT DETECTED at 14:32") are readable but useless for
analysis.  JSON logs can be:
  - Queried programmatically (find all High-severity events this week)
  - Loaded into a dashboard (Phase 4)
  - Exported for forensic analysis
  - Fed back into ML training (Phase 3)

Each log entry is one JSON object per line (JSONL format — JSON Lines).
This format is used by security tools like Splunk, Elastic, and Datadog
because you can append to it cheaply and stream it line by line.

LOG ROTATION:
Log files grow forever if you don't manage them.  We rotate at 10 MB —
the current file gets renamed with a timestamp and a fresh file starts.
This keeps individual files manageable while preserving history.
"""

import os
import json
import time
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("cybershield.incident_logger")

LOGS_DIR = Path(__file__).parent.parent / "logs"
LOG_FILE = LOGS_DIR / "incidents.jsonl"
MAX_LOG_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB


def _ensure_logs_dir():
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


def _rotate_if_needed():
    """Rename the current log file if it exceeds MAX_LOG_SIZE_BYTES."""
    if LOG_FILE.exists() and LOG_FILE.stat().st_size >= MAX_LOG_SIZE_BYTES:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rotated = LOGS_DIR / f"incidents_{timestamp}.jsonl"
        LOG_FILE.rename(rotated)
        logger.info("Log rotated to: %s", rotated)


def log_incident(
    threat_event: dict,
    response_action: dict = None,
    quarantine_result: dict = None,
) -> dict:
    """
    Writes a complete incident record to the log file.

    Parameters:
        threat_event    — the raw threat dict from the agent queue
                          (type, threat_type, severity, details, timestamp)
        response_action — result from process_killer.respond_to_threat()
        quarantine_result — result from quarantine_manager.quarantine_file()

    Returns the full incident record that was written.
    """
    _ensure_logs_dir()
    _rotate_if_needed()

    incident = {
        "id": f"INC-{int(time.time() * 1000)}",   # millisecond timestamp as ID
        "logged_at": datetime.now().isoformat(),

        # Threat details
        "threat": {
            "type": threat_event.get("threat_type", "unknown"),
            "severity": threat_event.get("severity", "unknown"),
            "details": threat_event.get("details", ""),
            "detected_at": datetime.fromtimestamp(
                threat_event.get("timestamp", time.time())
            ).isoformat(),
        },

        # What the response engine did about it
        "response": {
            "process_action": response_action.get("action") if response_action else "none",
            "process_name": response_action.get("process_name") if response_action else None,
            "pid": response_action.get("pid") if response_action else None,
            "process_kill_success": response_action.get("success", False) if response_action else False,
            "file_quarantined": quarantine_result.get("success", False) if quarantine_result else False,
            "quarantine_path": quarantine_result.get("quarantine_path") if quarantine_result else None,
            "original_path": quarantine_result.get("original_path") if quarantine_result else None,
        },
    }

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(incident) + "\n")

        logger.info(
            "Incident logged: %s | severity=%s | process=%s",
            incident["id"],
            incident["threat"]["severity"],
            incident["response"]["process_name"],
        )

    except OSError as e:
        logger.error("Failed to write incident log: %s", e)

    return incident


def get_recent_incidents(limit: int = 50) -> list:
    """
    Returns the most recent N incidents from the log file.

    Reads from the end of the file so it's efficient even on large logs.
    Used by the dashboard (Phase 4) to populate the threat feed.
    """
    _ensure_logs_dir()

    if not LOG_FILE.exists():
        return []

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

        incidents = []
        for line in reversed(lines[-limit:]):
            line = line.strip()
            if line:
                try:
                    incidents.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        return incidents

    except OSError as e:
        logger.error("Could not read incident log: %s", e)
        return []


def get_summary() -> dict:
    """
    Returns aggregate stats across all logged incidents.
    Used by the dashboard status card.
    """
    _ensure_logs_dir()

    summary = {
        "total": 0,
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "by_type": {},
        "processes_killed": 0,
        "files_quarantined": 0,
    }

    if not LOG_FILE.exists():
        return summary

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    inc = json.loads(line)
                    summary["total"] += 1

                    sev = inc.get("threat", {}).get("severity", "").lower()
                    if sev in summary["by_severity"]:
                        summary["by_severity"][sev] += 1

                    ttype = inc.get("threat", {}).get("type", "unknown")
                    summary["by_type"][ttype] = summary["by_type"].get(ttype, 0) + 1

                    if inc.get("response", {}).get("process_kill_success"):
                        summary["processes_killed"] += 1

                    if inc.get("response", {}).get("file_quarantined"):
                        summary["files_quarantined"] += 1

                except json.JSONDecodeError:
                    continue

    except OSError as e:
        logger.error("Could not read log for summary: %s", e)

    return summary
