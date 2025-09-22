"""
Registry for managing security detectors.
"""

import importlib
import pkgutil
from typing import Any, Dict, List, Optional, Type

from .base import BaseDetector


class DetectorRegistry:
    """
    Registry for managing and discovering security detectors.
    """
    
    def __init__(self) -> None:
        """Initialize the detector registry."""
        self._detectors: Dict[str, Type[BaseDetector]] = {}
        self._instances: Dict[str, BaseDetector] = {}
        self._auto_discover()
    
    def register_detector(self, detector_class: Type[BaseDetector]) -> None:
        """
        Register a detector class.
        
        Args:
            detector_class: Detector class to register
        """
        # Create a temporary instance to get the name
        temp_instance = detector_class()
        detector_name = temp_instance.name
        
        self._detectors[detector_name] = detector_class
    
    def unregister_detector(self, detector_name: str) -> None:
        """
        Unregister a detector.
        
        Args:
            detector_name: Name of the detector to unregister
        """
        if detector_name in self._detectors:
            del self._detectors[detector_name]
        
        if detector_name in self._instances:
            del self._instances[detector_name]
    
    def get_detector(self, detector_name: str) -> Optional[BaseDetector]:
        """
        Get a detector instance by name.
        
        Args:
            detector_name: Name of the detector
            
        Returns:
            Detector instance or None if not found
        """
        if detector_name not in self._instances:
            if detector_name in self._detectors:
                detector_class = self._detectors[detector_name]
                self._instances[detector_name] = detector_class()
            else:
                return None
        
        return self._instances[detector_name]
    
    def list_detectors(self) -> List[str]:
        """
        Get list of registered detector names.
        
        Returns:
            List of detector names
        """
        return list(self._detectors.keys())
    
    def list_detector_objects(self) -> List[BaseDetector]:
        """
        Get list of detector instances.
        
        Returns:
            List of detector instances
        """
        return [self.get_detector(name) for name in self.list_detectors()]
    
    def get_detectors_by_type(self, finding_type: str) -> List[BaseDetector]:
        """
        Get detectors filtered by finding type.
        
        Args:
            finding_type: Type of findings to filter by
            
        Returns:
            List of matching detector instances
        """
        matching_detectors = []
        
        for detector in self.list_detector_objects():
            if detector and detector.scanner_type.value == finding_type:
                matching_detectors.append(detector)
        
        return matching_detectors
    
    def get_available_detectors(self) -> List[BaseDetector]:
        """
        Get list of available detector instances.
        
        Returns:
            List of available detector instances
        """
        available_detectors = []
        
        for detector in self.list_detector_objects():
            if detector and detector.is_available():
                available_detectors.append(detector)
        
        return available_detectors
    
    def get_detector_info(self, detector_name: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a detector.
        
        Args:
            detector_name: Name of the detector
            
        Returns:
            Dictionary with detector information or None if not found
        """
        detector = self.get_detector(detector_name)
        if not detector:
            return None
        
        return {
            "name": detector.name,
            "scanner_type": detector.scanner_type.value,
            "description": detector.description,
            "available": detector.is_available(),
            "version": detector.get_version(),
            "required_dependencies": detector.get_required_dependencies(),
            "optional_dependencies": detector.get_optional_dependencies(),
            "supported_extensions": detector.get_supported_file_extensions(),
            "help_text": detector.get_help_text(),
        }
    
    def validate_all_detectors(self) -> Dict[str, List[str]]:
        """
        Validate all registered detectors.
        
        Returns:
            Dictionary with validation results
        """
        results = {
            "valid": [],
            "invalid": [],
            "unavailable": [],
        }
        
        for detector_name in self.list_detectors():
            detector = self.get_detector(detector_name)
            if not detector:
                results["invalid"].append(f"{detector_name}: Could not instantiate")
                continue
            
            if not detector.is_available():
                results["unavailable"].append(detector_name)
                continue
            
            try:
                detector.validate_configuration()
                results["valid"].append(detector_name)
            except Exception as e:
                results["invalid"].append(f"{detector_name}: {e}")
        
        return results
    
    def _auto_discover(self) -> None:
        """Automatically discover and register detectors."""
        # Import built-in detectors
        try:
            from . import semgrep, gitleaks, trivy, bandit, checkov
        except ImportError:
            # Some detectors might not be available
            pass
        
        # Discover detectors in the detectors package
        try:
            import repo_scan.detectors
            
            for importer, modname, ispkg in pkgutil.iter_modules(
                repo_scan.detectors.__path__, 
                repo_scan.detectors.__name__ + "."
            ):
                if not ispkg and modname != "repo_scan.detectors.base":
                    try:
                        module = importlib.import_module(modname)
                        self._discover_detectors_in_module(module)
                    except ImportError:
                        # Skip modules that can't be imported
                        continue
        except Exception:
            # If auto-discovery fails, continue with manually registered detectors
            pass
    
    def _discover_detectors_in_module(self, module: Any) -> None:
        """
        Discover detector classes in a module.
        
        Args:
            module: Module to search for detector classes
        """
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseDetector)
                and attr != BaseDetector
            ):
                self.register_detector(attr)


# Global registry instance
_registry: Optional[DetectorRegistry] = None


def get_registry() -> DetectorRegistry:
    """Get the global detector registry instance."""
    global _registry
    if _registry is None:
        _registry = DetectorRegistry()
    return _registry


def register_detector(detector_class: Type[BaseDetector]) -> None:
    """
    Register a detector class with the global registry.
    
    Args:
        detector_class: Detector class to register
    """
    registry = get_registry()
    registry.register_detector(detector_class)
