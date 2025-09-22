"""
Plugin loader for repo-scan.
"""

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from .base import BasePlugin


class PluginLoader:
    """
    Plugin loader that discovers and loads plugins from various sources.
    """
    
    def __init__(self) -> None:
        """Initialize the plugin loader."""
        self._plugins: Dict[str, BasePlugin] = {}
        self._plugin_classes: Dict[str, Type[BasePlugin]] = {}
        self._plugin_dirs: List[Path] = []
    
    def add_plugin_directory(self, plugin_dir: Path) -> None:
        """
        Add a directory to search for plugins.
        
        Args:
            plugin_dir: Directory path to search for plugins
        """
        if plugin_dir.exists() and plugin_dir.is_dir():
            self._plugin_dirs.append(plugin_dir)
    
    def load_plugins_from_directory(self, plugin_dir: Path) -> List[BasePlugin]:
        """
        Load all plugins from a directory.
        
        Args:
            plugin_dir: Directory to load plugins from
            
        Returns:
            List of loaded plugin instances
        """
        plugins = []
        
        if not plugin_dir.exists() or not plugin_dir.is_dir():
            return plugins
        
        # Load Python files as plugins
        for py_file in plugin_dir.glob("*.py"):
            if py_file.name.startswith("__"):
                continue
            
            try:
                plugin = self._load_plugin_from_file(py_file)
                if plugin:
                    plugins.append(plugin)
            except Exception as e:
                print(f"Error loading plugin from {py_file}: {e}")
                continue
        
        return plugins
    
    def _load_plugin_from_file(self, plugin_file: Path) -> Optional[BasePlugin]:
        """
        Load a plugin from a Python file.
        
        Args:
            plugin_file: Path to the plugin file
            
        Returns:
            Plugin instance or None if loading failed
        """
        try:
            # Create module spec
            spec = importlib.util.spec_from_file_location(
                plugin_file.stem, plugin_file
            )
            
            if not spec or not spec.loader:
                return None
            
            # Load the module
            module = importlib.util.module_from_spec(spec)
            sys.modules[plugin_file.stem] = module
            spec.loader.exec_module(module)
            
            # Look for plugin classes
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                
                if (isinstance(attr, type) and 
                    issubclass(attr, BasePlugin) and 
                    attr != BasePlugin):
                    
                    # Create plugin instance
                    plugin_instance = attr()
                    self._plugins[plugin_instance.name] = plugin_instance
                    self._plugin_classes[plugin_instance.name] = attr
                    
                    return plugin_instance
            
            return None
            
        except Exception as e:
            print(f"Error loading plugin from {plugin_file}: {e}")
            return None
    
    def load_plugin_from_module(self, module_name: str) -> Optional[BasePlugin]:
        """
        Load a plugin from a Python module.
        
        Args:
            module_name: Name of the module to load
            
        Returns:
            Plugin instance or None if loading failed
        """
        try:
            module = importlib.import_module(module_name)
            
            # Look for plugin classes
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                
                if (isinstance(attr, type) and 
                    issubclass(attr, BasePlugin) and 
                    attr != BasePlugin):
                    
                    # Create plugin instance
                    plugin_instance = attr()
                    self._plugins[plugin_instance.name] = plugin_instance
                    self._plugin_classes[plugin_instance.name] = attr
                    
                    return plugin_instance
            
            return None
            
        except Exception as e:
            print(f"Error loading plugin from module {module_name}: {e}")
            return None
    
    def register_plugin(self, plugin_class: Type[BasePlugin]) -> BasePlugin:
        """
        Register a plugin class.
        
        Args:
            plugin_class: Plugin class to register
            
        Returns:
            Plugin instance
        """
        plugin_instance = plugin_class()
        self._plugins[plugin_instance.name] = plugin_instance
        self._plugin_classes[plugin_instance.name] = plugin_class
        
        return plugin_instance
    
    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """
        Get a plugin by name.
        
        Args:
            name: Plugin name
            
        Returns:
            Plugin instance or None if not found
        """
        return self._plugins.get(name)
    
    def list_plugins(self) -> List[str]:
        """
        Get list of loaded plugin names.
        
        Returns:
            List of plugin names
        """
        return list(self._plugins.keys())
    
    def get_plugin_metadata(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata for a plugin.
        
        Args:
            name: Plugin name
            
        Returns:
            Plugin metadata or None if not found
        """
        plugin = self._plugins.get(name)
        if plugin:
            return plugin.get_metadata()
        return None
    
    def enable_plugin(self, name: str) -> bool:
        """
        Enable a plugin.
        
        Args:
            name: Plugin name
            
        Returns:
            True if plugin was enabled, False if not found
        """
        plugin = self._plugins.get(name)
        if plugin:
            plugin.enabled = True
            return True
        return False
    
    def disable_plugin(self, name: str) -> bool:
        """
        Disable a plugin.
        
        Args:
            name: Plugin name
            
        Returns:
            True if plugin was disabled, False if not found
        """
        plugin = self._plugins.get(name)
        if plugin:
            plugin.enabled = False
            return True
        return False
    
    def configure_plugin(self, name: str, config: Dict[str, Any]) -> bool:
        """
        Configure a plugin.
        
        Args:
            name: Plugin name
            config: Configuration dictionary
            
        Returns:
            True if plugin was configured successfully, False otherwise
        """
        plugin = self._plugins.get(name)
        if plugin:
            try:
                if plugin.validate_config(config):
                    plugin.initialize(config)
                    plugin.config = config
                    return True
            except Exception as e:
                print(f"Error configuring plugin {name}: {e}")
        return False
    
    def discover_plugins(self) -> List[BasePlugin]:
        """
        Discover and load all available plugins.
        
        Returns:
            List of discovered plugin instances
        """
        discovered_plugins = []
        
        # Load from registered directories
        for plugin_dir in self._plugin_dirs:
            plugins = self.load_plugins_from_directory(plugin_dir)
            discovered_plugins.extend(plugins)
        
        # Load from entry points (if available)
        try:
            import importlib.metadata
            entry_points = importlib.metadata.entry_points()
            
            if hasattr(entry_points, 'select'):
                # Python 3.10+
                plugin_entry_points = entry_points.select(group='repo_scan.plugins')
            else:
                # Python < 3.10
                plugin_entry_points = entry_points.get('repo_scan.plugins', [])
            
            for entry_point in plugin_entry_points:
                try:
                    plugin_class = entry_point.load()
                    plugin_instance = self.register_plugin(plugin_class)
                    discovered_plugins.append(plugin_instance)
                except Exception as e:
                    print(f"Error loading plugin from entry point {entry_point.name}: {e}")
                    
        except ImportError:
            # importlib.metadata not available
            pass
        
        return discovered_plugins
    
    def cleanup_all(self) -> None:
        """Cleanup all loaded plugins."""
        for plugin in self._plugins.values():
            try:
                plugin.cleanup()
            except Exception as e:
                print(f"Error cleaning up plugin {plugin.name}: {e}")


# Global plugin loader instance
_plugin_loader: Optional[PluginLoader] = None


def get_plugin_loader() -> PluginLoader:
    """Get the global plugin loader instance."""
    global _plugin_loader
    if _plugin_loader is None:
        _plugin_loader = PluginLoader()
    return _plugin_loader


def load_plugins(plugins_dir: str) -> List[BasePlugin]:
    """
    Load plugins from a directory (convenience function).
    
    Args:
        plugins_dir: Directory to load plugins from
        
    Returns:
        List of loaded plugin instances
    """
    loader = get_plugin_loader()
    plugin_path = Path(plugins_dir)
    return loader.load_plugins_from_directory(plugin_path)
