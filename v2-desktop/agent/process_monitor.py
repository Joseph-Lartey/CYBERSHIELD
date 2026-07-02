"""
Process Monitor
---------------
Collects live system features using psutil and maps them to the
feature names the ML model was trained on.

WHAT WE CAN COLLECT (from psutil):
  pslist.*    — process counts, threads, parent PIDs
  handles.*   — open files, network ports, total handles (Windows)
  svcscan.*   — Windows services breakdown (Windows only)

WHAT WE CANNOT COLLECT (requires Volatility / deep Windows APIs):
  dlllist.*   — DLL lists per process        → zeroed
  ldrmodules.*— hidden DLL cross-checks      → zeroed
  malfind.*   — memory injection detection   → zeroed
  psxview.*   — cross-view process analysis  → zeroed
  callbacks.* — kernel callbacks             → zeroed
  modules.*   — loaded kernel modules        → zeroed

These zeros reduce ML confidence slightly, which is why
classifier.py uses a higher threshold (0.65 instead of 0.5).
"""

import sys
import logging
import psutil
from typing import Optional

logger = logging.getLogger("cybershield.process_monitor")


def _safe_iter_processes():
    """Returns a list of process info dicts, skipping inaccessible ones."""
    procs = []
    for p in psutil.process_iter(['pid', 'ppid', 'num_threads', 'status']):
        try:
            procs.append(p.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procs


def _count_open_files() -> int:
    """Total open file handles across all processes."""
    total = 0
    for p in psutil.process_iter():
        try:
            total += len(p.open_files())
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return total


def _count_net_connections() -> int:
    """Total active network connections system-wide."""
    try:
        return len(psutil.net_connections())
    except (psutil.AccessDenied, AttributeError):
        return 0


def _get_handle_count_per_proc(procs: list) -> float:
    """
    Average number of handles per process.
    On Windows: uses num_handles() which counts all kernel object handles.
    On other OSes: uses num_fds() (file descriptors) as a proxy.
    """
    counts = []
    for info in procs:
        try:
            p = psutil.Process(info['pid'])
            if sys.platform == "win32":
                counts.append(p.num_handles())
            else:
                counts.append(p.num_fds())
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            continue
    return sum(counts) / len(counts) if counts else 0.0


def _get_services_info() -> dict:
    """
    Returns Windows service counts broken down by type.
    Returns zeros on non-Windows platforms.
    """
    info = {
        "nservices": 0,
        "kernel_drivers": 0,
        "fs_drivers": 0,
        "process_services": 0,
        "shared_process_services": 0,
        "interactive_process_services": 0,
        "nactive": 0,
    }

    if sys.platform != "win32":
        return info

    try:
        for svc in psutil.win_service_iter():
            try:
                s = svc.as_dict()
                info["nservices"] += 1

                stype = s.get("start_type", "")
                btype = s.get("binpath", "")

                if "kernel" in stype.lower() or ".sys" in btype.lower():
                    info["kernel_drivers"] += 1
                elif "file" in stype.lower():
                    info["fs_drivers"] += 1
                elif s.get("username") == "LocalSystem":
                    info["process_services"] += 1

                if s.get("status") == "running":
                    info["nactive"] += 1

            except Exception:
                continue
    except AttributeError:
        pass

    return info


def collect_features() -> Optional[dict]:
    """
    Collects all available system features and returns a dict
    ready to pass directly into RansomwareClassifier.predict().

    Returns None if psutil fails (e.g. no permissions).
    """
    try:
        procs = _safe_iter_processes()

        if not procs:
            return None

        nproc       = len(procs)
        ppids       = {p['ppid'] for p in procs if p.get('ppid')}
        threads     = [p['num_threads'] for p in procs if p.get('num_threads')]
        avg_threads = sum(threads) / len(threads) if threads else 0.0
        avg_handlers = _get_handle_count_per_proc(procs)

        nfile  = _count_open_files()
        nport  = _count_net_connections()
        nhandles = nfile + nport   # best approximation without Volatility
        avg_handles_per_proc = nhandles / nproc if nproc else 0.0
        nthread = sum(threads)

        svc = _get_services_info()

        features = {
            # pslist
            "pslist.nproc":           float(nproc),
            "pslist.nppid":           float(len(ppids)),
            "pslist.avg_threads":     avg_threads,
            "pslist.nprocs64bit":     0.0,   # needs Windows API
            "pslist.avg_handlers":    avg_handlers,

            # dlllist — unavailable without Volatility
            "dlllist.ndlls":              0.0,
            "dlllist.avg_dlls_per_proc":  0.0,

            # handles — partial
            "handles.nhandles":           float(nhandles),
            "handles.avg_handles_per_proc": avg_handles_per_proc,
            "handles.nport":              float(nport),
            "handles.nfile":              float(nfile),
            "handles.nevent":             0.0,
            "handles.ndesktop":           0.0,
            "handles.nkey":               0.0,
            "handles.nthread":            float(nthread),
            "handles.ndirectory":         0.0,
            "handles.nsemaphore":         0.0,
            "handles.ntimer":             0.0,
            "handles.nsection":           0.0,
            "handles.nmutant":            0.0,

            # ldrmodules — unavailable
            "ldrmodules.not_in_load":         0.0,
            "ldrmodules.not_in_init":         0.0,
            "ldrmodules.not_in_mem":          0.0,
            "ldrmodules.not_in_load_avg":     0.0,
            "ldrmodules.not_in_init_avg":     0.0,
            "ldrmodules.not_in_mem_avg":      0.0,

            # malfind — unavailable
            "malfind.ninjections":       0.0,
            "malfind.commitCharge":      0.0,
            "malfind.protection":        0.0,
            "malfind.uniqueInjections":  0.0,

            # psxview — unavailable
            "psxview.not_in_pslist":                    0.0,
            "psxview.not_in_eprocess_pool":             0.0,
            "psxview.not_in_ethread_pool":              0.0,
            "psxview.not_in_pspcid_list":               0.0,
            "psxview.not_in_csrss_handles":             0.0,
            "psxview.not_in_session":                   0.0,
            "psxview.not_in_deskthrd":                  0.0,
            "psxview.not_in_pslist_false_avg":          0.0,
            "psxview.not_in_eprocess_pool_false_avg":   0.0,
            "psxview.not_in_ethread_pool_false_avg":    0.0,
            "psxview.not_in_pspcid_list_false_avg":     0.0,
            "psxview.not_in_csrss_handles_false_avg":   0.0,
            "psxview.not_in_session_false_avg":         0.0,
            "psxview.not_in_deskthrd_false_avg":        0.0,

            # modules
            "modules.nmodules": 0.0,

            # svcscan — Windows only, zeros on other platforms
            "svcscan.nservices":                  float(svc["nservices"]),
            "svcscan.kernel_drivers":             float(svc["kernel_drivers"]),
            "svcscan.fs_drivers":                 float(svc["fs_drivers"]),
            "svcscan.process_services":           float(svc["process_services"]),
            "svcscan.shared_process_services":    float(svc["shared_process_services"]),
            "svcscan.interactive_process_services": float(svc["interactive_process_services"]),
            "svcscan.nactive":                    float(svc["nactive"]),

            # callbacks — unavailable
            "callbacks.ncallbacks":   0.0,
            "callbacks.nanonymous":   0.0,
            "callbacks.ngeneric":     0.0,
        }

        logger.debug(
            "Features collected: procs=%d threads=%.1f handles=%d files=%d ports=%d",
            nproc, avg_threads, nhandles, nfile, nport,
        )

        return features

    except Exception as e:
        logger.error("Feature collection failed: %s", e)
        return None
