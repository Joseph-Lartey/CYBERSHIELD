"""
Response Engine
---------------
Orchestrates the full response to a confirmed threat.

WHAT IT DOES (in order):
  1. Notify the user immediately ("threat detected")
  2. Kill or suspend the responsible process (stop the encryption NOW)
  3. Quarantine the triggering file (isolate the damage)
  4. Log the full incident with all actions taken
  5. Notify the user again ("threat blocked, here's what we did")

WHY THIS ORDER?
  - Notify first: the user should know immediately, before we do anything else.
    If steps 2-4 crash, the user still got the warning.
  - Kill before quarantine: if the process is still running it will re-encrypt
    the file the moment we quarantine it.  Stop the process first.
  - Log last: we want the log to capture the outcome of steps 2 and 3,
    not just the detection.

DEDUPLICATION:
The same threat can fire multiple times in quick succession (e.g. the file
monitor fires once per write, not once per ransomware run).  We keep a short
cache of recently responded-to threats and skip duplicates within a cooldown
window.  This prevents hammering the system with parallel response actions
for the same attack.
"""

import time
import logging
import threading
from typing import Optional

from response.process_killer import respond_to_threat
from response.quarantine_manager import quarantine_file
from response.incident_logger import log_incident
from response import notifier

logger = logging.getLogger("cybershield.response_engine")

# How many seconds to suppress duplicate responses for the same threat type.
RESPONSE_COOLDOWN_SECONDS = 15

# Threat types we respond to with full force (kill + quarantine).
# Lower severity types get logged and notified but no process kill.
AGGRESSIVE_RESPONSE_SEVERITIES = {"critical", "high"}


class ResponseEngine:
    """
    Receives threat events and coordinates the full response pipeline.

    Usage:
        engine = ResponseEngine()
        engine.handle(threat_event)   # called from agent's event loop
    """

    def __init__(self):
        self._recent_responses: dict = {}   # threat_type → last response timestamp
        self._lock = threading.Lock()

    def handle(self, threat_event: dict):
        """
        Main entry point.  Called by the agent for every confirmed threat.

        Runs in a separate thread so it doesn't block the event processor —
        killing a process and quarantining a file can take a few hundred ms.
        """
        thread = threading.Thread(
            target=self._respond,
            args=(threat_event,),
            daemon=True,
            name="ResponseThread",
        )
        thread.start()

    def _respond(self, threat_event: dict):
        threat_type = threat_event.get("threat_type", "unknown")
        severity    = threat_event.get("severity", "low")
        details     = threat_event.get("details", "")
        path        = threat_event.get("triggering_path", "")

        # --- Deduplication check ---
        if self._is_duplicate(threat_type):
            logger.debug("Duplicate response suppressed for: %s", threat_type)
            return

        self._mark_responded(threat_type)

        logger.warning(
            "ResponseEngine handling: type=%s severity=%s",
            threat_type, severity,
        )

        # ------------------------------------------------------------------
        # Step 1: Notify user — threat detected
        # ------------------------------------------------------------------
        notifier.notify_threat_detected(threat_type, severity, details)

        response_result   = {"action": "none", "process_name": None, "pid": None, "success": False}
        quarantine_result = None

        # ------------------------------------------------------------------
        # Step 2 & 3: For high/critical threats — kill process + quarantine
        # ------------------------------------------------------------------
        if severity.lower() in AGGRESSIVE_RESPONSE_SEVERITIES:

            # 2. Kill / suspend the process
            response_result = respond_to_threat(triggering_path=path)

            if response_result["success"]:
                notifier.notify_threat_blocked(
                    process_name=response_result["process_name"],
                    severity=severity,
                    action=response_result["action"],
                )
            else:
                logger.warning(
                    "Process kill failed or no culprit found for threat: %s",
                    threat_type,
                )

            # 3. Quarantine the triggering file (if we have one)
            if path:
                quarantine_result = quarantine_file(path, reason=threat_type)
                if quarantine_result["success"]:
                    notifier.notify_file_quarantined(path)

        # ------------------------------------------------------------------
        # Step 4: Log the full incident
        # ------------------------------------------------------------------
        log_incident(
            threat_event=threat_event,
            response_action=response_result,
            quarantine_result=quarantine_result,
        )

        logger.info(
            "Response complete: type=%s | process=%s | quarantine=%s",
            threat_type,
            response_result.get("process_name", "none"),
            quarantine_result.get("success", False) if quarantine_result else False,
        )

    # ------------------------------------------------------------------
    # Deduplication helpers
    # ------------------------------------------------------------------

    def _is_duplicate(self, threat_type: str) -> bool:
        with self._lock:
            last = self._recent_responses.get(threat_type, 0)
            return (time.time() - last) < RESPONSE_COOLDOWN_SECONDS

    def _mark_responded(self, threat_type: str):
        with self._lock:
            self._recent_responses[threat_type] = time.time()
