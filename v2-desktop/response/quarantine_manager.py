"""
Quarantine Manager
------------------
Moves suspicious files to a safe, isolated quarantine directory.

WHY QUARANTINE INSTEAD OF DELETE?
Deleting a file is irreversible.  If we get a false positive — i.e. we flag a
legitimate file as ransomware — the user has permanently lost it.
Quarantine moves the file to a locked-away folder where:
  - It cannot execute (we rename it so the OS won't run it)
  - It cannot encrypt other files (it's isolated)
  - It CAN be restored if we were wrong

This is exactly what commercial antivirus software does.

THE QUARANTINE MANIFEST:
Every quarantine action is recorded in a JSON manifest file inside the
quarantine directory.  This gives us a complete audit trail:
  - What was quarantined
  - When
  - Why (which threat triggered it)
  - Where it originally lived (so we can restore it)
"""

import os
import json
import time
import shutil
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("cybershield.quarantine")

# The quarantine directory sits next to the v2-desktop folder.
# We resolve it relative to THIS file's location so it works anywhere.
QUARANTINE_DIR = Path(__file__).parent.parent / "quarantine"
MANIFEST_FILE = QUARANTINE_DIR / "manifest.json"

# We rename quarantined files with this extension so the OS won't execute them.
# Even if someone navigates to the quarantine folder, they can't accidentally
# double-click and run a quarantined .exe.
QUARANTINE_EXTENSION = ".cybershield_quarantine"


def _ensure_quarantine_dir():
    """Create the quarantine directory if it doesn't exist."""
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)


def _load_manifest() -> list:
    """Load the existing manifest, or return empty list if none exists."""
    if not MANIFEST_FILE.exists():
        return []
    try:
        with open(MANIFEST_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _save_manifest(entries: list):
    """Write the manifest back to disk."""
    with open(MANIFEST_FILE, "w") as f:
        json.dump(entries, f, indent=2)


def quarantine_file(file_path: str, reason: str = "") -> dict:
    """
    Moves a file into the quarantine directory and records it in the manifest.

    Returns a result dict:
        {
            "success": bool,
            "original_path": str,
            "quarantine_path": str,   # where it now lives
            "reason": str,
            "timestamp": str,
        }
    """
    _ensure_quarantine_dir()

    result = {
        "success": False,
        "original_path": file_path,
        "quarantine_path": None,
        "reason": reason,
        "timestamp": datetime.now().isoformat(),
    }

    src = Path(file_path)

    if not src.exists():
        logger.warning("Cannot quarantine — file not found: %s", file_path)
        return result

    # Build a unique destination name.
    # We use a timestamp prefix to avoid collisions if the same filename
    # is quarantined multiple times.
    timestamp_prefix = str(int(time.time()))
    dest_name = f"{timestamp_prefix}_{src.name}{QUARANTINE_EXTENSION}"
    dest = QUARANTINE_DIR / dest_name

    try:
        shutil.move(str(src), str(dest))
        result["success"] = True
        result["quarantine_path"] = str(dest)

        logger.warning(
            "QUARANTINED: %s → %s (reason: %s)",
            file_path, dest, reason,
        )

        # Record in manifest
        manifest = _load_manifest()
        manifest.append(result)
        _save_manifest(manifest)

    except PermissionError:
        logger.error("Permission denied quarantining: %s", file_path)
    except OSError as e:
        logger.error("Could not quarantine %s: %s", file_path, e)

    return result


def restore_file(quarantine_path: str) -> dict:
    """
    Restores a quarantined file to its original location.

    Used when we confirm a false positive — the file was wrongly flagged.
    Looks up the original path from the manifest.

    Returns a result dict with success status.
    """
    manifest = _load_manifest()

    # Find the manifest entry for this quarantine path
    entry = next(
        (e for e in manifest if e.get("quarantine_path") == quarantine_path),
        None,
    )

    if not entry:
        logger.error("No manifest entry found for: %s", quarantine_path)
        return {"success": False, "error": "Not in manifest"}

    original = entry["original_path"]
    src = Path(quarantine_path)

    if not src.exists():
        logger.error("Quarantine file not found: %s", quarantine_path)
        return {"success": False, "error": "Quarantine file missing"}

    try:
        # Recreate parent directories if they were deleted
        Path(original).parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), original)

        # Remove from manifest
        manifest = [e for e in manifest if e.get("quarantine_path") != quarantine_path]
        _save_manifest(manifest)

        logger.info("RESTORED: %s → %s", quarantine_path, original)
        return {"success": True, "restored_to": original}

    except OSError as e:
        logger.error("Could not restore %s: %s", quarantine_path, e)
        return {"success": False, "error": str(e)}


def list_quarantined() -> list:
    """Returns all currently quarantined files from the manifest."""
    return _load_manifest()
