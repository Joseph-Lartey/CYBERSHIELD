"""
Honey File Watcher
------------------
Plants decoy "honey files" in key directories and raises an immediate critical
alert if anything touches them.

WHAT IS A HONEY FILE?
A honey file (or canary file) is a file that:
  1. Looks like a real, valuable document (e.g. "passwords.txt", "backup.docx")
  2. Has NO legitimate reason to ever be read or modified
  3. Is monitored continuously

If anything touches it — reads it, modifies it, renames it, deletes it —
something is wrong.  Ransomware almost always processes files alphabetically
or by directory, so placing these files with names that sort early (e.g.
starting with "!!" or "AAA") means ransomware hits our trip-wire very early,
before it has encrypted anything important.

WHY THIS IS POWERFUL:
Unlike entropy analysis (which requires reading file contents) or rate
monitoring (which requires seeing many events), honey files give a
*near-zero false-positive* signal.  A legitimate program has no reason to
touch a file named "!!CYBERSHIELD_CANARY_DO_NOT_TOUCH.txt".
"""

import os
import time
import logging
import threading
from pathlib import Path
from queue import Queue

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger("cybershield.honey")

# Content written into honey files — looks like a real document to ransomware
HONEY_CONTENT = (
    "CONFIDENTIAL - Internal Use Only\n"
    "================================\n"
    "This file contains sensitive company data.\n"
    "Do not distribute outside the organisation.\n"
    "\n"
    "Q4 Revenue: $4,821,000\n"
    "Payroll accounts: See attached.\n"
    "Database credentials: admin / Tr0ub4dor&3\n"
)

# Honey file names — "!!" prefix sorts before everything else alphabetically,
# so ransomware that processes files in order hits these first.
HONEY_FILENAMES = [
    "!!AAAA_cybershield_canary.txt",
    "!!AAA_important_backup.docx",
    "!!AA_confidential_passwords.txt",
]

# Directories to plant honey files in.
# %USERPROFILE% is the Windows home folder (e.g. C:\Users\Joseph).
# We resolve these at runtime so they work on any machine.
HONEY_DIRECTORIES_TEMPLATES = [
    "{userprofile}",
    "{userprofile}\\Documents",
    "{userprofile}\\Desktop",
    "{userprofile}\\Downloads",
]


class HoneyFileEventHandler(FileSystemEventHandler):
    """
    Watchdog handler that watches ONLY the honey file paths.
    Any event on these files is immediately a critical threat.
    """

    def __init__(self, honey_files: set[str], event_queue: Queue):
        super().__init__()
        self.honey_files = {p.lower() for p in honey_files}
        self.event_queue = event_queue

    def _is_honey(self, path: str) -> bool:
        return path.lower() in self.honey_files

    def on_modified(self, event):
        if not event.is_directory and self._is_honey(event.src_path):
            self._alert("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory and self._is_honey(event.src_path):
            self._alert("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory and self._is_honey(event.src_path):
            self._alert("renamed/moved", event.src_path)

    def on_created(self, event):
        # If a honey file reappears under a different name in the same dir,
        # something suspicious may be restoring or replacing decoys.
        pass

    def _alert(self, action: str, path: str):
        logger.critical("HONEY FILE TOUCHED — action=%s path=%s", action, path)
        self.event_queue.put({
            "type": "threat",
            "threat_type": "honey_file_triggered",
            "details": f"Honey file {action}: {path}",
            "severity": "critical",
            "timestamp": time.time(),
        })


class HoneyWatcher:
    """
    Plants honey files and monitors them.

    Usage:
        q = Queue()
        watcher = HoneyWatcher(event_queue=q)
        watcher.plant()   # write decoy files to disk
        watcher.start()   # begin watching them
        # ...
        watcher.stop()
        watcher.remove()  # clean up decoy files on shutdown (optional)
    """

    def __init__(self, event_queue: Queue):
        self.event_queue = event_queue
        self._honey_paths: list[str] = []
        self._observer = Observer()

    def _resolve_directories(self) -> list[str]:
        userprofile = os.environ.get("USERPROFILE", os.path.expanduser("~"))
        resolved = []
        for template in HONEY_DIRECTORIES_TEMPLATES:
            path = template.format(userprofile=userprofile)
            if Path(path).exists():
                resolved.append(path)
        return resolved

    def plant(self):
        """Write honey files to disk.  Called once at startup."""
        directories = self._resolve_directories()

        for directory in directories:
            for filename in HONEY_FILENAMES:
                full_path = os.path.join(directory, filename)
                try:
                    with open(full_path, "w", encoding="utf-8") as f:
                        f.write(HONEY_CONTENT)
                    self._honey_paths.append(full_path)
                    logger.info("Honey file planted: %s", full_path)
                except OSError as e:
                    logger.warning("Could not plant honey file at %s: %s", full_path, e)

        logger.info("Total honey files planted: %d", len(self._honey_paths))

    def start(self):
        """Start watching honey files.  Call plant() first."""
        if not self._honey_paths:
            logger.warning("No honey files to watch — did you call plant()?")
            return

        honey_set = set(self._honey_paths)
        handler = HoneyFileEventHandler(honey_set, self.event_queue)

        # Watch each unique directory that contains a honey file
        watched_dirs = {str(Path(p).parent) for p in self._honey_paths}
        for directory in watched_dirs:
            self._observer.schedule(handler, directory, recursive=False)

        self._observer.start()
        logger.info("Honey file watcher started. Watching %d directories.", len(watched_dirs))

    def stop(self):
        self._observer.stop()
        self._observer.join()
        logger.info("Honey file watcher stopped.")

    def remove(self):
        """Delete honey files from disk (called on clean shutdown)."""
        for path in self._honey_paths:
            try:
                os.remove(path)
                logger.info("Honey file removed: %s", path)
            except OSError:
                pass
        self._honey_paths.clear()

    @property
    def planted_paths(self) -> list[str]:
        return list(self._honey_paths)
