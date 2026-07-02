"""
File System Monitor
-------------------
Watches the file system in real time using the watchdog library.

WHAT IT DOES:
- Listens for every file creation, modification, deletion, and rename on the system.
- Keeps a short-term rolling window of events to spot *mass* activity (the hallmark of ransomware).
- Emits structured events to a shared queue so the main agent can act on them.

WHY THIS MATTERS:
Ransomware MUST touch the file system — it reads a file, encrypts it, and writes it back
(sometimes with a new extension like .locked or .enc).  No matter how the ransomware is
packaged or obfuscated, this behaviour is unavoidable.  Catching it at the file layer is
the most reliable detection vector we have.
"""

import time
import logging
import threading
from collections import defaultdict, deque
from pathlib import Path
from queue import Queue

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger("cybershield.file_monitor")

# ---------------------------------------------------------------------------
# Tuning constants — tweak these to balance sensitivity vs false positives
# ---------------------------------------------------------------------------

# How many seconds to look back when counting rapid events
WINDOW_SECONDS = 5

# How many file writes in WINDOW_SECONDS before we flag "mass write activity"
MASS_WRITE_THRESHOLD = 20

# How many different extensions renamed to in WINDOW_SECONDS before we flag
EXTENSION_CHANGE_THRESHOLD = 5

# File extensions commonly used by ransomware to rename encrypted files.
# This list is not exhaustive — we also catch unknown extensions via volume.
KNOWN_RANSOM_EXTENSIONS = {
    ".locked", ".enc", ".encrypted", ".crypto", ".crypt",
    ".crypted", ".rnsmwr", ".pays", ".zepto", ".locky",
    ".cerber", ".wallet", ".wcry", ".wncry", ".wncryt",
    ".onion", ".fun", ".btc", ".darkness", ".r5a",
}

# Directories to ignore — scanning these produces noise with no security value
IGNORED_DIRS = {
    "AppData\\Local\\Temp",
    "AppData\\Local\\Microsoft\\Windows\\INetCache",
    "$Recycle.Bin",
    "Windows\\Temp",
    "ProgramData\\Microsoft",
}


# ---------------------------------------------------------------------------
# The event handler — watchdog calls methods on this for every FS event
# ---------------------------------------------------------------------------

class RansomwareEventHandler(FileSystemEventHandler):
    """
    Subclasses watchdog's FileSystemEventHandler.

    Think of watchdog as a security guard standing at every door in a building.
    Every time a door opens (file event), the guard calls the matching method
    here.  We decide whether to raise an alarm.
    """

    def __init__(self, event_queue: Queue):
        super().__init__()
        self.event_queue = event_queue

        # Rolling timestamp log — for each event type, store a deque of times.
        # A deque is a double-ended list; we pop old entries off the left end.
        self._write_times: deque = deque()
        self._rename_extensions: deque = deque()   # stores (timestamp, new_ext)

        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Watchdog callback — called for every new file or directory created
    # ------------------------------------------------------------------
    def on_created(self, event):
        if event.is_directory or self._should_ignore(event.src_path):
            return
        self._record_write(event.src_path, "created")

    # ------------------------------------------------------------------
    # Watchdog callback — called every time a file's content changes
    # ------------------------------------------------------------------
    def on_modified(self, event):
        if event.is_directory or self._should_ignore(event.src_path):
            return
        self._record_write(event.src_path, "modified")

    # ------------------------------------------------------------------
    # Watchdog callback — called when a file is renamed or moved
    # ------------------------------------------------------------------
    def on_moved(self, event):
        if event.is_directory or self._should_ignore(event.src_path):
            return

        src = Path(event.src_path)
        dst = Path(event.dest_path)
        new_ext = dst.suffix.lower()

        self._push_event({
            "type": "rename",
            "src": str(src),
            "dst": str(dst),
            "new_extension": new_ext,
            "suspicious_extension": new_ext in KNOWN_RANSOM_EXTENSIONS,
        })

        with self._lock:
            now = time.time()
            self._rename_extensions.append((now, new_ext))
            self._prune_window(self._rename_extensions)
            self._check_mass_rename()

    # ------------------------------------------------------------------
    # Watchdog callback — called when a file is deleted
    # ------------------------------------------------------------------
    def on_deleted(self, event):
        if event.is_directory or self._should_ignore(event.src_path):
            return
        self._push_event({"type": "deleted", "path": event.src_path})

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record_write(self, path: str, event_type: str):
        self._push_event({"type": event_type, "path": path})

        with self._lock:
            now = time.time()
            self._write_times.append(now)
            self._prune_window(self._write_times)
            self._check_mass_write(path)

    def _prune_window(self, dq: deque):
        """Remove entries older than WINDOW_SECONDS from the left of the deque."""
        cutoff = time.time() - WINDOW_SECONDS
        while dq and dq[0] < cutoff:
            dq.popleft()
        # _rename_extensions stores tuples — handle that too
        while dq and isinstance(dq[0], tuple) and dq[0][0] < cutoff:
            dq.popleft()

    def _check_mass_write(self, triggering_path: str):
        """Fires a threat event if write rate crosses the threshold."""
        count = len(self._write_times)
        if count >= MASS_WRITE_THRESHOLD:
            logger.warning(
                "Mass write activity: %d writes in %ds (triggered by %s)",
                count, WINDOW_SECONDS, triggering_path,
            )
            self._push_event({
                "type": "threat",
                "threat_type": "mass_write",
                "details": f"{count} file writes in {WINDOW_SECONDS}s",
                "triggering_path": triggering_path,
                "severity": "high",
            })
            # Clear to avoid re-firing on every subsequent write
            self._write_times.clear()

    def _check_mass_rename(self):
        """Fires a threat event if we see many extension changes quickly."""
        # Count distinct *new* extensions in the window
        unique_exts = {ext for _, ext in self._rename_extensions}
        known_ransom = unique_exts & KNOWN_RANSOM_EXTENSIONS

        if known_ransom:
            logger.warning("Known ransomware extension detected: %s", known_ransom)
            self._push_event({
                "type": "threat",
                "threat_type": "ransom_extension",
                "details": f"Files renamed to: {known_ransom}",
                "severity": "critical",
            })
            self._rename_extensions.clear()
        elif len(unique_exts) >= EXTENSION_CHANGE_THRESHOLD:
            logger.warning("Mass extension change: %d unique extensions in %ds", len(unique_exts), WINDOW_SECONDS)
            self._push_event({
                "type": "threat",
                "threat_type": "mass_extension_change",
                "details": f"{len(unique_exts)} different extensions in {WINDOW_SECONDS}s",
                "severity": "high",
            })
            self._rename_extensions.clear()

    def _push_event(self, event: dict):
        event["timestamp"] = time.time()
        self.event_queue.put(event)

    @staticmethod
    def _should_ignore(path: str) -> bool:
        for ignored in IGNORED_DIRS:
            if ignored.lower() in path.lower():
                return True
        return False


# ---------------------------------------------------------------------------
# FileMonitor — the public interface the main agent uses
# ---------------------------------------------------------------------------

class FileMonitor:
    """
    Manages the watchdog Observer and exposes a simple start/stop interface.

    Usage:
        q = Queue()
        monitor = FileMonitor(watch_paths=["C:\\Users"], event_queue=q)
        monitor.start()
        # main agent reads from q...
        monitor.stop()
    """

    def __init__(self, watch_paths: list[str], event_queue: Queue):
        self.watch_paths = watch_paths
        self.event_queue = event_queue
        self._observer = Observer()
        self._handler = RansomwareEventHandler(event_queue)

    def start(self):
        for path in self.watch_paths:
            if not Path(path).exists():
                logger.warning("Watch path does not exist, skipping: %s", path)
                continue
            # recursive=True means we watch ALL subdirectories too
            self._observer.schedule(self._handler, path, recursive=True)
            logger.info("Watching: %s", path)

        self._observer.start()
        logger.info("File monitor started.")

    def stop(self):
        self._observer.stop()
        self._observer.join()
        logger.info("File monitor stopped.")
