"""
Notifier
--------
Sends a desktop notification to the user when a threat is detected or blocked.

WHAT THIS DOES:
Shows a toast notification (the popups you see in the bottom-right corner on
Windows) with:
  - A title describing the severity
  - A message explaining what happened and what was done about it

HOW IT WORKS ACROSS PLATFORMS:
We try three notification methods in order:

  1. plyer  — cross-platform notification library (Windows, Mac, Linux).
              Best option — works cleanly on all platforms.

  2. win10toast — Windows-only, more native-looking toast notifications.
                  Falls back to this if plyer is not installed.

  3. Console fallback — if neither library is available, we print a highly
                        visible banner to the terminal.  Always works.

WHY THREE METHODS?
Because this is a security tool.  If a dependency fails to install, we cannot
afford to silently skip alerting the user.  The fallback ensures the user
always gets informed, even in a degraded environment.
"""

import logging
import sys

logger = logging.getLogger("cybershield.notifier")

# App name shown in the notification
APP_NAME = "CyberShield"

# Severity → notification title mapping
SEVERITY_TITLES = {
    "critical": "🚨 CRITICAL THREAT BLOCKED",
    "high":     "⚠️  High Threat Detected",
    "medium":   "ℹ️  Medium Threat Detected",
    "low":      "Low Threat Detected",
}

# ANSI colour codes for the console fallback
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_RESET  = "\033[0m"
_BOLD   = "\033[1m"


def _notify_plyer(title: str, message: str):
    from plyer import notification
    notification.notify(
        title=title,
        message=message,
        app_name=APP_NAME,
        timeout=8,
    )


def _notify_win10toast(title: str, message: str):
    from win10toast import ToastNotifier
    toaster = ToastNotifier()
    toaster.show_toast(title, message, duration=8, threaded=True)


def _notify_console(title: str, message: str, severity: str):
    colour = _RED if severity in ("critical", "high") else _YELLOW
    border = "=" * 60
    print(f"\n{colour}{_BOLD}{border}")
    print(f"  {title}")
    print(f"  {message}")
    print(f"{border}{_RESET}\n")


def send(severity: str, message: str):
    """
    Send a desktop notification to the user.

    Parameters:
        severity — "critical", "high", "medium", or "low"
        message  — human-readable description of what happened
    """
    title = SEVERITY_TITLES.get(severity.lower(), "CyberShield Alert")

    # Try plyer first (cross-platform)
    try:
        _notify_plyer(title, message)
        logger.info("Notification sent via plyer: %s", title)
        return
    except ImportError:
        pass
    except Exception as e:
        logger.debug("plyer notification failed: %s", e)

    # Try win10toast (Windows native)
    if sys.platform == "win32":
        try:
            _notify_win10toast(title, message)
            logger.info("Notification sent via win10toast: %s", title)
            return
        except ImportError:
            pass
        except Exception as e:
            logger.debug("win10toast notification failed: %s", e)

    # Always-works console fallback
    _notify_console(title, message, severity)
    logger.info("Notification sent via console fallback: %s", title)


def notify_threat_detected(threat_type: str, severity: str, details: str):
    """Convenience wrapper for threat detection alerts."""
    message = f"Threat: {threat_type}\n{details}"
    send(severity, message)


def notify_threat_blocked(process_name: str, severity: str, action: str):
    """Convenience wrapper for response action alerts."""
    action_str = "suspended" if action == "suspended" else "terminated"
    message = f"Process '{process_name}' has been {action_str}.\nEncryption stopped."
    send(severity, message)


def notify_file_quarantined(original_path: str):
    """Convenience wrapper for quarantine alerts."""
    filename = original_path.split("\\")[-1].split("/")[-1]
    message = f"'{filename}' moved to quarantine.\nOriginal: {original_path}"
    send("high", message)
