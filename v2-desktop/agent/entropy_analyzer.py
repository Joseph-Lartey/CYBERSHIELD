"""
Entropy Analyser
----------------
Calculates the Shannon entropy of a file to detect whether its contents
have been encrypted.

WHAT IS ENTROPY?
Entropy measures how "random" or "unpredictable" data is.  It is measured in
bits per byte, on a scale of 0.0 to 8.0.

  Low entropy  (0.0 – 3.0):  highly repetitive data — plain text, source code
  Medium entropy (3.0 – 6.5): normal binary files — executables, PDFs, docs
  High entropy (7.2 – 8.0):   compressed OR encrypted data

WHY DOES THIS DETECT RANSOMWARE?
When ransomware encrypts a file, the output is mathematically indistinguishable
from random noise — that is the definition of good encryption.  So a Word
document that had entropy 4.2 yesterday suddenly reading as 7.9 today is a
strong signal that something encrypted it.

NOTE: Compressed files (zip, jpg, mp3) also have high entropy.  That is why
we do not use entropy alone — we combine it with file extension checks and
the rate of change from the file monitor.
"""

import math
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger("cybershield.entropy")

# Files larger than this are sampled rather than fully read — for performance.
# 1 MB is enough to get a statistically accurate entropy reading.
MAX_SAMPLE_BYTES = 1_048_576  # 1 MB

# Entropy threshold above which we consider a file suspicious.
# 7.2 catches most encrypted files while avoiding most compressed formats.
ENTROPY_THRESHOLD = 7.2

# File types that legitimately have high entropy — we skip these to avoid
# false positives.  An mp3 being "encrypted" is already compressed.
NATURALLY_HIGH_ENTROPY_EXTENSIONS = {
    ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".jpg", ".jpeg", ".png", ".gif", ".webp",
    ".mp3", ".mp4", ".aac", ".flac", ".ogg", ".avi", ".mkv",
    ".pdf",  # PDFs can vary, but high base entropy is common
}


def calculate_entropy(data: bytes) -> float:
    """
    Calculates Shannon entropy of a byte string.

    Shannon entropy formula:
        H = -SUM( p(x) * log2(p(x)) )  for each unique byte value x

    In plain English:
    - Count how often each of the 256 possible byte values (0-255) appears.
    - Express each count as a probability (count / total_bytes).
    - Multiply each probability by its own log base-2.
    - Sum them all up and negate.

    A file where every byte is the same has entropy 0.0 (totally predictable).
    A file where all 256 byte values appear equally often has entropy 8.0
    (perfectly random — like encrypted data).
    """
    if not data:
        return 0.0

    # Count frequency of each byte value (0-255)
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1

    total = len(data)
    entropy = 0.0

    for count in freq:
        if count == 0:
            continue
        probability = count / total
        # log2(probability) is always negative for 0 < p < 1,
        # so we negate at the end to get a positive entropy value
        entropy -= probability * math.log2(probability)

    return entropy


def analyse_file(file_path: str) -> Optional[dict]:
    """
    Reads a file (or a sample of it) and returns an analysis dict.

    Returns None if the file cannot be read (locked, deleted, permissions).

    Return structure:
        {
            "path": str,
            "entropy": float,          # 0.0 – 8.0
            "suspicious": bool,        # True if entropy > threshold
            "file_size": int,          # bytes
            "sampled": bool,           # True if we only read part of the file
            "extension": str,
            "skipped": bool,           # True if extension is naturally high-entropy
        }
    """
    path = Path(file_path)

    if not path.exists() or not path.is_file():
        return None

    ext = path.suffix.lower()

    # Skip naturally high-entropy file types to avoid false positives
    if ext in NATURALLY_HIGH_ENTROPY_EXTENSIONS:
        return {
            "path": file_path,
            "entropy": None,
            "suspicious": False,
            "file_size": path.stat().st_size,
            "sampled": False,
            "extension": ext,
            "skipped": True,
        }

    try:
        file_size = path.stat().st_size

        if file_size == 0:
            return None

        with open(path, "rb") as f:
            # For large files, read only the first MAX_SAMPLE_BYTES.
            # Entropy is consistent across a file if it's uniformly encrypted,
            # so a 1 MB sample is representative.
            data = f.read(MAX_SAMPLE_BYTES)
            sampled = file_size > MAX_SAMPLE_BYTES

        entropy = calculate_entropy(data)
        suspicious = entropy >= ENTROPY_THRESHOLD

        if suspicious:
            logger.warning(
                "High entropy file detected: %s (entropy=%.3f, size=%d bytes)",
                file_path, entropy, file_size,
            )

        return {
            "path": file_path,
            "entropy": round(entropy, 4),
            "suspicious": suspicious,
            "file_size": file_size,
            "sampled": sampled,
            "extension": ext,
            "skipped": False,
        }

    except PermissionError:
        logger.debug("Permission denied reading: %s", file_path)
        return None
    except OSError as e:
        logger.debug("Could not read %s: %s", file_path, e)
        return None


def analyse_directory_sample(directory: str, max_files: int = 50) -> list[dict]:
    """
    Scans a sample of files in a directory and returns those with high entropy.

    Used during startup to establish a baseline — not called on every event,
    that would be too slow.  The file monitor calls analyse_file() on
    individual files as they change.
    """
    results = []
    count = 0

    for root, _, files in os.walk(directory):
        for filename in files:
            if count >= max_files:
                return results
            full_path = os.path.join(root, filename)
            result = analyse_file(full_path)
            if result and result.get("suspicious"):
                results.append(result)
            count += 1

    return results
