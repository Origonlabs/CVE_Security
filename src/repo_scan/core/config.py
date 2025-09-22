"""
Configuration management for repo-scan.
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, validator
from dotenv import load_dotenv

from .exceptions import ConfigError


class ScannerConfig(BaseModel):
    """Configuration for individual scanners."""
    
    enabled: bool = True
    timeout: int = 300  # seconds
    memory_limit: str = "1g"
    cpu_limit: str = "1.0"
    custom_rules: Optional[str] = None
    exclude_patterns: List[str] = Field(default_factory=list)
    include_patterns: List[str] = Field(default_factory=list)


class NotificationConfig(BaseModel):
    """Configuration for notifications."""
    
    slack_webhook: Optional[str] = None
    slack_channel: Optional[str] = None
    email_smtp_server: Optional[str] = None
    email_smtp_port: int = 587
    email_username: Optional[str] = None
    email_password: Optional[str] = None
    email_from: Optional[str] = None
    email_to: List[str] = Field(default_factory=list)


class DatabaseConfig(BaseModel):
    """Database configuration."""
    
    url: str = "sqlite:///repo_scan.db"
    echo: bool = False
    pool_size: int = 5
    max_overflow: int = 10


class APIConfig(BaseModel):
    """API server configuration."""
    
    host: str = "127.0.0.1"
    port: int = 8000
    workers: int = 1
    reload: bool = False
    auth_enabled: bool = False
    jwt_secret: Optional[str] = None
    oidc_provider: Optional[str] = None
    oidc_client_id: Optional[str] = None
    oidc_client_secret: Optional[str] = None


class Config(BaseModel):
    """Main configuration class for repo-scan."""
    
    # General settings
    debug: bool = False
    verbose: bool = False
    workspace_dir: str = "/var/tmp/repo-scan"
    max_workers: int = 4
    scan_timeout: int = 3600  # 1 hour
    
    # Scanner configurations
    scanners: Dict[str, ScannerConfig] = Field(default_factory=dict)
    
    # Notification settings
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)
    
    # Database settings
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    
    # API settings
    api: APIConfig = Field(default_factory=APIConfig)
    
    # Security settings
    verify_gpg_signatures: bool = True
    allowed_git_protocols: List[str] = Field(default_factory=lambda: ["https", "ssh"])
    
    # Scoring settings
    risk_scoring: Dict[str, Any] = Field(default_factory=lambda: {
        "severity_weights": {
            "LOW": 10,
            "MEDIUM": 40,
            "HIGH": 75,
            "CRITICAL": 100
        },
        "multipliers": {
            "history_exposure": 1.25,
            "private_key": 2.0,
            "api_token": 1.8,
            "published_exploit": 1.5,
            "production_branch": 1.3
        },
        "max_findings_for_score": 20
    })
    
    @validator('workspace_dir')
    def validate_workspace_dir(cls, v: str) -> str:
        """Validate workspace directory path."""
        path = Path(v)
        if not path.exists():
            try:
                path.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                raise ConfigError(f"Cannot create workspace directory {v}: {e}")
        return str(path.absolute())
    
    @classmethod
    def load_from_file(cls, config_path: Union[str, Path]) -> "Config":
        """Load configuration from YAML file."""
        config_path = Path(config_path)
        
        if not config_path.exists():
            raise ConfigError(f"Configuration file not found: {config_path}")
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            return cls(**config_data)
        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML in configuration file: {e}")
        except Exception as e:
            raise ConfigError(f"Error loading configuration: {e}")
    
    @classmethod
    def load_from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        load_dotenv()
        
        config_data = {}
        
        # General settings
        if os.getenv("REPO_SCAN_DEBUG"):
            config_data["debug"] = os.getenv("REPO_SCAN_DEBUG").lower() in ("true", "1", "yes")
        
        if os.getenv("REPO_SCAN_VERBOSE"):
            config_data["verbose"] = os.getenv("REPO_SCAN_VERBOSE").lower() in ("true", "1", "yes")
        
        if os.getenv("REPO_SCAN_WORKSPACE"):
            config_data["workspace_dir"] = os.getenv("REPO_SCAN_WORKSPACE")
        
        if os.getenv("REPO_SCAN_MAX_WORKERS"):
            config_data["max_workers"] = int(os.getenv("REPO_SCAN_MAX_WORKERS"))
        
        # Database settings
        if os.getenv("DATABASE_URL"):
            config_data["database"] = {"url": os.getenv("DATABASE_URL")}
        
        # API settings
        if os.getenv("API_HOST"):
            config_data["api"] = {"host": os.getenv("API_HOST")}
        
        if os.getenv("API_PORT"):
            config_data["api"] = {"port": int(os.getenv("API_PORT"))}
        
        # Notification settings
        if os.getenv("SLACK_WEBHOOK"):
            config_data["notifications"] = {"slack_webhook": os.getenv("SLACK_WEBHOOK")}
        
        return cls(**config_data)
    
    def save_to_file(self, config_path: Union[str, Path]) -> None:
        """Save configuration to YAML file."""
        config_path = Path(config_path)
        
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.dict(), f, default_flow_style=False, indent=2)
        except Exception as e:
            raise ConfigError(f"Error saving configuration: {e}")
    
    def get_scanner_config(self, scanner_name: str) -> ScannerConfig:
        """Get configuration for a specific scanner."""
        return self.scanners.get(scanner_name, ScannerConfig())
    
    def is_scanner_enabled(self, scanner_name: str) -> bool:
        """Check if a scanner is enabled."""
        return self.get_scanner_config(scanner_name).enabled


# Global configuration instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = Config.load_from_env()
    return _config


def set_config(config: Config) -> None:
    """Set the global configuration instance."""
    global _config
    _config = config
