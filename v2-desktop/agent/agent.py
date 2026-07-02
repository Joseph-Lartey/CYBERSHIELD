"""
CyberShield v2 — Main Agent
----------------------------
This is the entry point for the detection engine.  It:

  1. Plants honey files in key directories
  2. Starts the file system monitor (watching for mass writes / extension changes)
  3. Reads events from the shared queue in a loop
  4. For each "modified" or "created" event, runs the entropy analyser
  5. Logs all threats to the console (and later to the alert service)

Run this script directly to start the agent:
    python agent.py

On Windows in production this will run as a Windows Service.
For now it runs in the terminal so you can see exactly what it's doing.
"""

import os
import sys
import time
import signal
import logging
import threading
from queue import Queue, Empty
from pathlib import Path

# Make sure Python can find our sibling modules regardless of how it's invoked
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.file_monitor import FileMonitor
from agent.entropy_analyzer import analyse_file
from agent.honey_watcher import HoneyWatcher
from agent.process_monitor import collect_features
from ml.classifier import RansomwareClassifier, THREAT_THRESHOLD
from response.response_engine import ResponseEngine

# ---------------------------------------------------------------------------
# Logging setup — coloured output so threats stand out in the terminal
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("cybershield.agent")

# ---------------------------------------------------------------------------
# Which directories to watch
# ---------------------------------------------------------------------------

def get_watch_paths() -> list[str]:
    """
    Returns a list of paths to monitor.

    On Windows:   C:\\Users\\<name>  (the user's home folder and everything in it)
    On Mac/Linux: ~/  (for development and testing)

    We watch the user's home folder because that is where ransomware targets —
    your Documents, Desktop, Pictures, Downloads.  System files are not
    typically the primary target, and watching all of C:\\ would produce too
    much noise.
    """
    if sys.platform == "win32":
        userprofile = os.environ.get("USERPROFILE", "C:\\Users")
        return [userprofile]
    else:
        # Mac/Linux — for development
        return [str(Path.home())]


# ---------------------------------------------------------------------------
# The event processing loop
# ---------------------------------------------------------------------------

def process_events(event_queue: Queue, shutdown_event: threading.Event, response_engine: ResponseEngine):
    """
    Reads events from the shared queue and acts on them.

    This runs in its own thread so it doesn't block the watchdog observer.

    The queue is the "highway" between the file monitor (which produces events)
    and this processor (which consumes them).  The Queue class is thread-safe —
    multiple threads can push/pop without corrupting data.
    """
    logger.info("Event processor started.")

    while not shutdown_event.is_set():
        try:
            # Wait up to 1 second for an event before looping back
            # (so we can check shutdown_event regularly)
            event = event_queue.get(timeout=1.0)
        except Empty:
            continue

        event_type = event.get("type")

        # ------------------------------------------------------------------
        # Threat event — already classified by the file monitor or honey watcher
        # ------------------------------------------------------------------
        if event_type == "threat":
            severity = event.get("severity", "unknown").upper()
            threat_type = event.get("threat_type", "unknown")
            details = event.get("details", "")

            if severity == "CRITICAL":
                logger.critical("🚨 CRITICAL THREAT — %s — %s", threat_type, details)
            elif severity == "HIGH":
                logger.warning("⚠️  HIGH THREAT    — %s — %s", threat_type, details)
            else:
                logger.warning("⚠️  THREAT         — %s — %s", threat_type, details)

            # Hand off to Phase 2 response engine — runs in its own thread
            response_engine.handle(event)

        # ------------------------------------------------------------------
        # File modification or creation — run entropy analysis
        # ------------------------------------------------------------------
        elif event_type in ("modified", "created"):
            path = event.get("path", "")
            if not path:
                continue

            result = analyse_file(path)
            if result and result.get("suspicious"):
                logger.warning(
                    "🔬 HIGH ENTROPY FILE — %s (entropy=%.3f)",
                    path, result["entropy"],
                )
                event_queue.put({
                    "type": "threat",
                    "threat_type": "high_entropy_file",
                    "details": f"Entropy {result['entropy']:.3f} at {path}",
                    "severity": "high",
                    "timestamp": time.time(),
                })

        # ------------------------------------------------------------------
        # Rename event — log it; mass rename check is done in file_monitor.py
        # ------------------------------------------------------------------
        elif event_type == "rename":
            if event.get("suspicious_extension"):
                logger.warning(
                    "🔤 SUSPICIOUS RENAME — %s → %s",
                    event.get("src"), event.get("dst"),
                )

        # ------------------------------------------------------------------
        # Deletion — just log for now
        # ------------------------------------------------------------------
        elif event_type == "deleted":
            logger.debug("Deleted: %s", event.get("path"))

        event_queue.task_done()

    logger.info("Event processor stopped.")


# ---------------------------------------------------------------------------
# ML periodic scan — runs every 30 seconds alongside event-driven detection
# ---------------------------------------------------------------------------

ML_SCAN_INTERVAL = 30  # seconds between each system-wide ML scan

def ml_scan_loop(classifier: RansomwareClassifier, event_queue: Queue, shutdown_event: threading.Event):
    """
    Periodically collects system features and scores them with the ML model.

    WHY PERIODIC AND NOT EVENT-DRIVEN?
    The ML model scores the *overall system state* — total process count,
    service patterns, handle counts.  These don't change on every file event;
    they reflect what's happening across the whole machine over time.
    Scanning every 30 seconds gives a meaningful signal without hammering psutil.

    This is the second layer of detection:
      Layer 1 (event-driven): file monitor + honey files + entropy
      Layer 2 (periodic):     ML model on live system snapshot
    """
    logger.info("ML scanner started (interval: %ds)", ML_SCAN_INTERVAL)

    if not classifier.is_loaded:
        logger.warning("ML model not loaded — periodic scan disabled.")
        return

    while not shutdown_event.is_set():
        # Wait for the interval, checking shutdown every second
        for _ in range(ML_SCAN_INTERVAL):
            if shutdown_event.is_set():
                break
            time.sleep(1)

        if shutdown_event.is_set():
            break

        features = collect_features()
        if features is None:
            logger.debug("ML scan: feature collection returned None, skipping.")
            continue

        score = classifier.predict(features)
        logger.info("ML scan complete — ransomware probability: %.3f", score)

        if score >= THREAT_THRESHOLD:
            logger.warning("🤖 ML THREAT DETECTED — score=%.3f (threshold=%.2f)", score, THREAT_THRESHOLD)
            event_queue.put({
                "type": "threat",
                "threat_type": "ml_detection",
                "severity": "high" if score < 0.85 else "critical",
                "details": f"ML model score {score:.3f} — system behaviour matches ransomware profile",
                "timestamp": time.time(),
            })

    logger.info("ML scanner stopped.")


# ---------------------------------------------------------------------------
# Main — startup, run, graceful shutdown
# ---------------------------------------------------------------------------

def main():
    logger.info("=" * 60)
    logger.info("  CyberShield v2 — Ransomware Detection Agent")
    logger.info("=" * 60)

    event_queue: Queue = Queue()
    shutdown_event = threading.Event()
    response_engine = ResponseEngine()

    # ------------------------------------------------------------------
    # Step 1: Plant honey files
    # ------------------------------------------------------------------
    honey = HoneyWatcher(event_queue=event_queue)
    honey.plant()
    honey.start()

    # ------------------------------------------------------------------
    # Step 2: Start the file system monitor
    # ------------------------------------------------------------------
    watch_paths = get_watch_paths()
    logger.info("Monitoring paths: %s", watch_paths)

    file_monitor = FileMonitor(watch_paths=watch_paths, event_queue=event_queue)
    file_monitor.start()

    # ------------------------------------------------------------------
    # Step 3: Start the event processing thread
    # ------------------------------------------------------------------
    processor_thread = threading.Thread(
        target=process_events,
        args=(event_queue, shutdown_event, response_engine),
        daemon=True,
        name="EventProcessor",
    )
    processor_thread.start()

    # ------------------------------------------------------------------
    # Step 4: Load ML model and start periodic scan
    # ------------------------------------------------------------------
    classifier = RansomwareClassifier()
    classifier.load()

    ml_thread = threading.Thread(
        target=ml_scan_loop,
        args=(classifier, event_queue, shutdown_event),
        daemon=True,
        name="MLScanner",
    )
    ml_thread.start()

    logger.info("Agent running. Press Ctrl+C to stop.")

    # ------------------------------------------------------------------
    # Graceful shutdown on Ctrl+C or SIGTERM
    # ------------------------------------------------------------------
    def handle_shutdown(sig, frame):
        logger.info("Shutdown signal received — stopping agent...")
        shutdown_event.set()

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    # Keep the main thread alive until shutdown is requested
    while not shutdown_event.is_set():
        time.sleep(0.5)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    file_monitor.stop()
    honey.stop()
    # Leave honey files on disk — removing them on shutdown would let
    # ransomware that ran before shutdown go undetected next boot.
    # honey.remove()  — uncomment only for testing

    processor_thread.join(timeout=5)
    ml_thread.join(timeout=5)
    logger.info("Agent shut down cleanly.")


if __name__ == "__main__":
    main()
