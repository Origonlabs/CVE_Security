"""
Notification manager for repo-scan.
"""

from typing import Any, Dict, List, Optional

from .base import BaseNotifier
from .slack import SlackNotifier
from .email import EmailNotifier
from ..core.models import ScanResult


class NotificationManager:
    """
    Manages multiple notification providers and sends notifications
    based on scan results and configuration.
    """
    
    def __init__(self) -> None:
        """Initialize the notification manager."""
        self._notifiers: Dict[str, BaseNotifier] = {}
        self._enabled_notifiers: List[str] = []
        
        # Register default notifiers
        self.register_notifier(SlackNotifier())
        self.register_notifier(EmailNotifier())
    
    def register_notifier(self, notifier: BaseNotifier) -> None:
        """
        Register a notification provider.
        
        Args:
            notifier: Notification provider to register
        """
        self._notifiers[notifier.name] = notifier
    
    def configure_notifier(self, name: str, config: Dict[str, Any]) -> bool:
        """
        Configure a notification provider.
        
        Args:
            name: Name of the notifier
            config: Configuration dictionary
            
        Returns:
            True if configuration was successful, False otherwise
        """
        notifier = self._notifiers.get(name)
        if notifier:
            notifier.configure(config)
            return True
        return False
    
    def enable_notifier(self, name: str) -> bool:
        """
        Enable a notification provider.
        
        Args:
            name: Name of the notifier
            
        Returns:
            True if notifier was enabled, False if not found
        """
        notifier = self._notifiers.get(name)
        if notifier:
            notifier.enabled = True
            if name not in self._enabled_notifiers:
                self._enabled_notifiers.append(name)
            return True
        return False
    
    def disable_notifier(self, name: str) -> bool:
        """
        Disable a notification provider.
        
        Args:
            name: Name of the notifier
            
        Returns:
            True if notifier was disabled, False if not found
        """
        notifier = self._notifiers.get(name)
        if notifier:
            notifier.enabled = False
            if name in self._enabled_notifiers:
                self._enabled_notifiers.remove(name)
            return True
        return False
    
    def send_notification(self, scan_result: ScanResult, message: str = "") -> Dict[str, bool]:
        """
        Send notifications for a scan result.
        
        Args:
            scan_result: Scan result to notify about
            message: Custom message to include
            
        Returns:
            Dictionary mapping notifier names to success status
        """
        results = {}
        
        for name in self._enabled_notifiers:
            notifier = self._notifiers.get(name)
            if notifier and notifier.is_configured():
                try:
                    if notifier.should_notify(scan_result):
                        success = notifier.send_notification(scan_result, message)
                        results[name] = success
                    else:
                        results[name] = True  # Skipped, not an error
                except Exception as e:
                    print(f"Error sending notification via {name}: {e}")
                    results[name] = False
            else:
                results[name] = False
        
        return results
    
    def send_daily_summary(self, scan_results: List[ScanResult]) -> Dict[str, bool]:
        """
        Send daily summary notifications.
        
        Args:
            scan_results: List of scan results from the day
            
        Returns:
            Dictionary mapping notifier names to success status
        """
        results = {}
        
        for name in self._enabled_notifiers:
            notifier = self._notifiers.get(name)
            if notifier and notifier.is_configured():
                try:
                    # Only send daily summary if we have scan results
                    if scan_results:
                        success = notifier.send_daily_summary(scan_results)
                        results[name] = success
                    else:
                        results[name] = True  # No results to summarize
                except Exception as e:
                    print(f"Error sending daily summary via {name}: {e}")
                    results[name] = False
            else:
                results[name] = False
        
        return results
    
    def get_notifier_status(self) -> Dict[str, Dict[str, Any]]:
        """
        Get status of all registered notifiers.
        
        Returns:
            Dictionary with notifier status information
        """
        status = {}
        
        for name, notifier in self._notifiers.items():
            status[name] = {
                "enabled": notifier.enabled,
                "configured": notifier.is_configured(),
                "available": notifier.is_available() if hasattr(notifier, 'is_available') else True,
            }
        
        return status
    
    def list_notifiers(self) -> List[str]:
        """
        Get list of registered notifier names.
        
        Returns:
            List of notifier names
        """
        return list(self._notifiers.keys())
    
    def get_enabled_notifiers(self) -> List[str]:
        """
        Get list of enabled notifier names.
        
        Returns:
            List of enabled notifier names
        """
        return self._enabled_notifiers.copy()
    
    def configure_from_dict(self, config: Dict[str, Any]) -> None:
        """
        Configure all notifiers from a configuration dictionary.
        
        Args:
            config: Configuration dictionary with notifier configs
        """
        # Configure Slack
        if "slack" in config:
            slack_config = config["slack"]
            if slack_config.get("enabled", False):
                self.configure_notifier("slack", slack_config)
                self.enable_notifier("slack")
            else:
                self.disable_notifier("slack")
        
        # Configure Email
        if "email" in config:
            email_config = config["email"]
            if email_config.get("enabled", False):
                self.configure_notifier("email", email_config)
                self.enable_notifier("email")
            else:
                self.disable_notifier("email")
    
    def test_notification(self, notifier_name: str) -> bool:
        """
        Test a notification provider with a sample message.
        
        Args:
            notifier_name: Name of the notifier to test
            
        Returns:
            True if test was successful, False otherwise
        """
        notifier = self._notifiers.get(notifier_name)
        if not notifier or not notifier.is_configured():
            return False
        
        # Create a test scan result
        from ..core.models import Repository, TechStack, ScanConfig
        
        test_repo = Repository(
            path="/test/repository",
            tech_stack=TechStack()
        )
        
        test_config = ScanConfig(repository=test_repo)
        
        test_result = ScanResult(
            scan_id="test-scan-001",
            repository=test_repo,
            config=test_config,
            findings=[],
            risk_score=0.0,
            risk_level="LOW",
            scan_duration=1.0,
            success=True
        )
        
        try:
            return notifier.send_notification(test_result, "This is a test notification from repo-scan.")
        except Exception as e:
            print(f"Test notification failed for {notifier_name}: {e}")
            return False
