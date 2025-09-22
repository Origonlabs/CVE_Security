"""
Plugin system for repo-scan.
"""

from .loader import PluginLoader, load_plugins
from .base import BasePlugin

__all__ = ["PluginLoader", "load_plugins", "BasePlugin"]
