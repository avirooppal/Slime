"""Multi-channel notification dispatcher supporting log, desktop, and audit sinks."""

import logging
import os
import subprocess
import sys
from abc import ABC, abstractmethod
from typing import Any

from selfheal.notifications.contracts import NotificationEvent, NotificationLevel
from selfheal.storage.store import Store

logger = logging.getLogger("selfheal.notifications")


class BaseNotifier(ABC):
    """Abstract base class for notification channels."""

    @abstractmethod
    def send(self, event: NotificationEvent) -> bool:
        """Send notification. Returns True if successfully delivered."""


class LogNotifier(BaseNotifier):
    """Logs notifications to standard application logger and SQLite audit log."""

    def __init__(self, store: Store | None = None) -> None:
        self.store = store

    def send(self, event: NotificationEvent) -> bool:
        """Record notification in logger and durable audit log."""
        log_msg = f"[{event.level.value.upper()}] {event.title}: {event.message}"
        if event.level == NotificationLevel.CRITICAL:
            logger.critical(log_msg)
        elif event.level == NotificationLevel.WARNING:
            logger.warning(log_msg)
        else:
            logger.info(log_msg)

        if self.store is not None:
            try:
                self.store.audit("notification", event.event_type, f"{event.title}: {event.message}")
            except Exception as ex:  # noqa: BLE001
                logger.warning(f"Failed to record notification audit: {ex}")
        return True


class DesktopNotifier(BaseNotifier):
    """Cross-platform desktop notification sender with non-blocking graceful fallback."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def send(self, event: NotificationEvent) -> bool:
        """Dispatch desktop toast / popup depending on host OS."""
        if not self.enabled:
            return False

        try:
            if sys.platform == "win32":
                return self._send_windows(event)
            elif sys.platform == "darwin":
                return self._send_macos(event)
            else:
                return self._send_linux(event)
        except Exception as ex:  # noqa: BLE001
            # Never interrupt runtime on desktop notification failure
            logger.debug(f"Desktop notification skipped: {ex}")
            return False

    def _send_windows(self, event: NotificationEvent) -> bool:
        """Windows PowerShell toast or console notification."""
        # Sanitize text for powershell
        safe_title = event.title.replace('"', '""').replace("'", "''")
        safe_msg = event.message.replace('"', '""').replace("'", "''")
        ps_cmd = (
            f"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; "
            f"$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
            f"$textNodes = $template.GetElementsByTagName('text'); "
            f"$textNodes.Item(0).AppendChild($template.CreateTextNode('{safe_title}')) > $null; "
            f"$textNodes.Item(1).AppendChild($template.CreateTextNode('{safe_msg}')) > $null; "
            f"$toast = [Windows.UI.Notifications.ToastNotification]::new($template); "
            f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Slime SelfHeal').Show($toast);"
        )
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                timeout=3,
                check=False,
            )
            return res.returncode == 0
        except Exception:  # noqa: BLE001
            return False

    def _send_macos(self, event: NotificationEvent) -> bool:
        """macOS AppleScript notification."""
        safe_title = event.title.replace('"', '\\"')
        safe_msg = event.message.replace('"', '\\"')
        cmd = f'display notification "{safe_msg}" with title "Slime SelfHeal" subtitle "{safe_title}"'
        try:
            res = subprocess.run(["osascript", "-e", cmd], capture_output=True, timeout=3, check=False)
            return res.returncode == 0
        except Exception:  # noqa: BLE001
            return False

    def _send_linux(self, event: NotificationEvent) -> bool:
        """Linux notify-send."""
        try:
            res = subprocess.run(
                ["notify-send", f"Slime: {event.title}", event.message],
                capture_output=True,
                timeout=3,
                check=False,
            )
            return res.returncode == 0
        except Exception:  # noqa: BLE001
            return False


class NotificationEngine:
    """Central notification dispatcher for incident lifecycle events."""

    def __init__(self, store: Store | None = None, enable_desktop: bool = True) -> None:
        self.notifiers: list[BaseNotifier] = [
            LogNotifier(store),
            DesktopNotifier(enabled=enable_desktop and not bool(os.environ.get("SLIME_HEADLESS"))),
        ]

    def add_notifier(self, notifier: BaseNotifier) -> None:
        """Register an additional notification channel."""
        self.notifiers.append(notifier)

    def notify(
        self,
        event_type: str,
        title: str,
        message: str,
        level: NotificationLevel = NotificationLevel.INFO,
        metadata: dict[str, Any] | None = None,
    ) -> NotificationEvent:
        """Dispatch a notification event to all registered channels safely."""
        event = NotificationEvent(
            event_type=event_type,
            title=title,
            message=message,
            level=level,
            metadata=metadata or {},
        )
        for notifier in self.notifiers:
            try:
                notifier.send(event)
            except Exception as ex:  # noqa: BLE001
                logger.warning(f"Notifier {notifier.__class__.__name__} failed: {ex}")
        return event
