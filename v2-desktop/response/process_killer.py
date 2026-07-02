"""
Process Killer
--------------
Identifies and terminates the process responsible for ransomware activity.

THE HARD PROBLEM:
When the file monitor fires a "mass_write" threat, we know files are being
encrypted — but we don't automatically know *which process* is doing it.
The OS doesn't tell us that in the file event.

HOW WE FIND THE CULPRIT:
We use two strategies together:

  Strategy 1 — Open file handles
    Ask the OS which process currently has the suspicious file open.
    psutil.Process.open_files() returns every file a process has a handle to.
    If process X has the triggering file open, it's almost certainly the culprit.
    Limitation: only works while the file is still open (ransomware may have
    already closed it after writing).

  Strategy 2 — I/O write rate scoring
    Every process on the system has an I/O counter that tracks how many bytes
    it has written to disk.  We sample these counters twice (0.5s apart) and
    calculate a write rate (bytes per second) for each process.
    The process with the highest write rate that is NOT on our safe-list is
    our best suspect.

WHY SUSPEND BEFORE KILL?
We first call process.suspend() which pauses the process without destroying it.
This immediately stops the encryption.  We then verify it was the right process
before calling process.kill().  This matters because a wrong kill on a legitimate
process (e.g. an antivirus doing a scan) would cause damage.
In Phase 3 when ML confidence scoring is in place we can automate the kill.
For now, Phase 2 suspends and logs, and the kill is confirmed.
"""

import os
import sys
import time
import logging
import psutil
from typing import Optional

logger = logging.getLogger("cybershield.process_killer")

# ---------------------------------------------------------------------------
# Processes we will NEVER touch regardless of their behaviour.
# Killing these would crash the system or cause serious damage.
# ---------------------------------------------------------------------------
PROCESS_SAFELIST = {
    # Windows core
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe",
    "taskmgr.exe", "msiexec.exe", "conhost.exe", "fontdrvhost.exe",
    # Security tools — never kill your own defences
    "msmpeng.exe",      # Windows Defender
    "msseces.exe",      # Microsoft Security Essentials
    "avgnt.exe",        # Avast/AVG
    "mbam.exe",         # Malwarebytes
    # Our own agent
    "python.exe", "python3.exe", "pythonw.exe",
    # Common developer tools — reduce false positives during development
    "code.exe", "devenv.exe",
}

# How long (seconds) to sample I/O counters
IO_SAMPLE_INTERVAL = 0.5

# Minimum write rate (bytes/sec) before we consider a process suspicious.
# 1 MB/s is a reasonable floor — idle processes write almost nothing.
MIN_SUSPICIOUS_WRITE_RATE = 1_048_576  # 1 MB/s


def _is_safelisted(name: str) -> bool:
    return name.lower() in PROCESS_SAFELIST


def find_culprit_by_open_files(suspicious_path: str) -> Optional[psutil.Process]:
    """
    Scans all running processes for one that has suspicious_path open.

    This is O(n) across all processes — can be slow on machines with many
    processes, but it's the most accurate method when the file is still open.
    """
    target = suspicious_path.lower()

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if _is_safelisted(proc.info["name"]):
                continue

            open_files = proc.open_files()
            for f in open_files:
                if f.path.lower() == target:
                    logger.info(
                        "Culprit found via open files: %s (PID %d)",
                        proc.info["name"], proc.pid,
                    )
                    return proc

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return None


def find_culprit_by_io_rate() -> Optional[psutil.Process]:
    """
    Samples every process's disk write rate and returns the one writing fastest.

    Steps:
      1. Snapshot all processes' write_bytes counter at time T
      2. Wait IO_SAMPLE_INTERVAL seconds
      3. Snapshot again at time T + 0.5s
      4. write_rate = (bytes_T2 - bytes_T1) / elapsed
      5. Return the non-safelisted process with the highest write rate
    """

    # --- Snapshot 1 ---
    snapshot1 = {}
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if _is_safelisted(proc.info["name"]):
                continue
            counters = proc.io_counters()
            snapshot1[proc.pid] = (proc, counters.write_bytes)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    time.sleep(IO_SAMPLE_INTERVAL)

    # --- Snapshot 2 + rate calculation ---
    best_proc = None
    best_rate = 0.0

    for pid, (proc, bytes_before) in snapshot1.items():
        try:
            counters = proc.io_counters()
            bytes_after = counters.write_bytes
            rate = (bytes_after - bytes_before) / IO_SAMPLE_INTERVAL

            if rate > best_rate:
                best_rate = rate
                best_proc = proc

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if best_proc and best_rate >= MIN_SUSPICIOUS_WRITE_RATE:
        logger.info(
            "Culprit found via I/O rate: %s (PID %d) — %.1f MB/s",
            best_proc.name(), best_proc.pid, best_rate / 1_048_576,
        )
        return best_proc

    return None


def suspend_process(proc: psutil.Process) -> bool:
    """
    Pauses a process without killing it.

    suspend() sends SIGSTOP on Unix and NtSuspendProcess on Windows.
    The process is frozen in memory — it cannot write any more files,
    but it still exists and can be resumed or inspected.

    Returns True on success.
    """
    try:
        proc.suspend()
        logger.warning(
            "SUSPENDED process: %s (PID %d)",
            proc.name(), proc.pid,
        )
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        logger.error("Could not suspend PID %d: %s", proc.pid, e)
        return False


def kill_process(proc: psutil.Process) -> bool:
    """
    Terminates a process immediately (no recovery).

    Use after suspend() has stopped the encryption and you've confirmed
    this is the right process.

    Returns True on success.
    """
    try:
        name = proc.name()
        pid = proc.pid
        proc.kill()
        logger.warning("KILLED process: %s (PID %d)", name, pid)
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        logger.error("Could not kill PID %d: %s", proc.pid, e)
        return False


def respond_to_threat(triggering_path: str = "") -> dict:
    """
    Main entry point called by the response engine.

    Tries to find and suspend the culprit process.
    Returns a result dict describing what happened.
    """
    result = {
        "action": "none",
        "process_name": None,
        "pid": None,
        "success": False,
    }

    # Strategy 1: check open file handles first (faster, more accurate)
    proc = None
    if triggering_path:
        proc = find_culprit_by_open_files(triggering_path)

    # Strategy 2: fall back to I/O rate if open-file check found nothing
    if proc is None:
        logger.info("Open-file scan found nothing — falling back to I/O rate scan")
        proc = find_culprit_by_io_rate()

    if proc is None:
        logger.warning("Could not identify culprit process — no action taken")
        return result

    result["process_name"] = proc.name()
    result["pid"] = proc.pid

    if suspend_process(proc):
        result["action"] = "suspended"
        result["success"] = True

    return result
