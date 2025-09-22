"""
Utility functions for repo-scan.
"""

import hashlib
import secrets
import string
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import git
from git import Repo, InvalidGitRepositoryError


def generate_scan_id() -> str:
    """Generate a unique scan ID."""
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    random_suffix = ''.join(secrets.choices(string.ascii_lowercase + string.digits, k=6))
    return f"scan_{timestamp}_{random_suffix}"


def generate_finding_id(scanner: str, title: str, file_path: Optional[str] = None) -> str:
    """Generate a unique finding ID."""
    content = f"{scanner}:{title}:{file_path or ''}"
    hash_obj = hashlib.sha256(content.encode())
    return f"finding_{hash_obj.hexdigest()[:12]}"


def is_git_repository(path: Union[str, Path]) -> bool:
    """Check if a path is a valid Git repository."""
    try:
        Repo(path)
        return True
    except (InvalidGitRepositoryError, git.GitError):
        return False


def get_repository_info(repo_path: Union[str, Path]) -> Dict[str, Any]:
    """Extract information from a Git repository."""
    try:
        repo = Repo(repo_path)
        
        # Get current branch
        try:
            branch = repo.active_branch.name
        except (TypeError, AttributeError):
            # Detached HEAD or no active branch
            branch = repo.head.reference.name if repo.head.reference else "detached"
        
        # Get commit hash
        commit_hash = repo.head.commit.hexsha
        
        # Get repository URL
        try:
            origin = repo.remotes.origin
            url = origin.url
        except AttributeError:
            url = None
        
        # Get last modified date
        last_modified = datetime.fromtimestamp(repo.head.commit.committed_date)
        
        # Get repository size (approximate)
        size_bytes = sum(f.stat().st_size for f in Path(repo_path).rglob('*') if f.is_file())
        
        # Get file count
        file_count = len([f for f in Path(repo_path).rglob('*') if f.is_file()])
        
        return {
            "path": str(Path(repo_path).resolve()),
            "url": url,
            "branch": branch,
            "commit_hash": commit_hash,
            "last_modified": last_modified,
            "size_bytes": size_bytes,
            "file_count": file_count,
            "is_git": True
        }
        
    except Exception:
        # Not a Git repository or error accessing it
        path = Path(repo_path)
        return {
            "path": str(path.resolve()),
            "url": None,
            "branch": None,
            "commit_hash": None,
            "last_modified": None,
            "size_bytes": sum(f.stat().st_size for f in path.rglob('*') if f.is_file()) if path.exists() else 0,
            "file_count": len([f for f in path.rglob('*') if f.is_file()]) if path.exists() else 0,
            "is_git": False
        }


def detect_tech_stack(repo_path: Union[str, Path]) -> Dict[str, List[str]]:
    """Detect technology stack from repository files."""
    path = Path(repo_path)
    tech_stack = {
        "languages": [],
        "frameworks": [],
        "package_managers": [],
        "containers": [],
        "infrastructure": []
    }
    
    if not path.exists():
        return tech_stack
    
    # Language detection based on file extensions and patterns
    language_files = {
        "Python": ["*.py", "requirements.txt", "setup.py", "pyproject.toml"],
        "JavaScript": ["*.js", "*.jsx", "*.ts", "*.tsx", "package.json"],
        "Java": ["*.java", "*.jar", "pom.xml", "build.gradle"],
        "Go": ["*.go", "go.mod", "go.sum"],
        "Rust": ["*.rs", "Cargo.toml", "Cargo.lock"],
        "C/C++": ["*.c", "*.cpp", "*.h", "*.hpp", "CMakeLists.txt", "Makefile"],
        "C#": ["*.cs", "*.csproj", "*.sln"],
        "PHP": ["*.php", "composer.json"],
        "Ruby": ["*.rb", "Gemfile", "Rakefile"],
        "Shell": ["*.sh", "*.bash", "*.zsh"],
        "PowerShell": ["*.ps1", "*.psm1"],
        "HTML": ["*.html", "*.htm"],
        "CSS": ["*.css", "*.scss", "*.sass"],
        "SQL": ["*.sql", "*.db", "*.sqlite"],
        "YAML": ["*.yml", "*.yaml"],
        "JSON": ["*.json"],
        "XML": ["*.xml"],
        "Markdown": ["*.md", "*.rst"]
    }
    
    for language, patterns in language_files.items():
        for pattern in patterns:
            if list(path.rglob(pattern)):
                if language not in tech_stack["languages"]:
                    tech_stack["languages"].append(language)
                break
    
    # Framework detection
    framework_indicators = {
        "Django": ["django", "manage.py"],
        "Flask": ["flask", "app.py"],
        "FastAPI": ["fastapi", "uvicorn"],
        "React": ["react", "jsx"],
        "Vue.js": ["vue", "nuxt"],
        "Angular": ["angular", "@angular"],
        "Spring": ["spring", "springframework"],
        "Express": ["express"],
        "Laravel": ["laravel"],
        "Rails": ["rails", "gemfile"],
        "ASP.NET": ["aspnet", "microsoft"],
        "TensorFlow": ["tensorflow"],
        "PyTorch": ["torch", "pytorch"]
    }
    
    for framework, indicators in framework_indicators.items():
        for indicator in indicators:
            if any(indicator.lower() in str(f).lower() for f in path.rglob("*")):
                if framework not in tech_stack["frameworks"]:
                    tech_stack["frameworks"].append(framework)
                break
    
    # Package manager detection
    package_managers = {
        "npm": ["package.json", "package-lock.json"],
        "yarn": ["yarn.lock"],
        "pip": ["requirements.txt", "setup.py", "pyproject.toml"],
        "poetry": ["pyproject.toml"],
        "maven": ["pom.xml"],
        "gradle": ["build.gradle", "gradlew"],
        "cargo": ["Cargo.toml"],
        "composer": ["composer.json"],
        "gem": ["Gemfile"],
        "nuget": ["*.csproj", "packages.config"]
    }
    
    for pm, files in package_managers.items():
        for file_pattern in files:
            if list(path.rglob(file_pattern)):
                if pm not in tech_stack["package_managers"]:
                    tech_stack["package_managers"].append(pm)
                break
    
    # Container detection
    container_files = {
        "Docker": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
        "Podman": ["Containerfile"],
        "Kubernetes": ["*.yaml", "*.yml"]  # Check for k8s manifests
    }
    
    for container_type, files in container_files.items():
        for file_pattern in files:
            if list(path.rglob(file_pattern)):
                if container_type not in tech_stack["containers"]:
                    tech_stack["containers"].append(container_type)
                break
    
    # Infrastructure detection
    infra_files = {
        "Terraform": ["*.tf", "*.tfvars"],
        "Ansible": ["playbook.yml", "inventory"],
        "CloudFormation": ["*.template", "*.yaml"],
        "Helm": ["Chart.yaml", "values.yaml"],
        "Pulumi": ["Pulumi.yaml", "Pulumi.*.yaml"]
    }
    
    for infra_type, files in infra_files.items():
        for file_pattern in files:
            if list(path.rglob(file_pattern)):
                if infra_type not in tech_stack["infrastructure"]:
                    tech_stack["infrastructure"].append(infra_type)
                break
    
    return tech_stack


def normalize_path(path: Union[str, Path]) -> str:
    """Normalize a path to a consistent format."""
    return str(Path(path).resolve())


def is_url(string: str) -> bool:
    """Check if a string is a valid URL."""
    try:
        result = urlparse(string)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def sanitize_filename(filename: str) -> str:
    """Sanitize a filename for safe filesystem usage."""
    # Remove or replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Remove leading/trailing whitespace and dots
    filename = filename.strip(' .')
    
    # Ensure it's not empty
    if not filename:
        filename = "unnamed"
    
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename


def format_bytes(bytes_value: int) -> str:
    """Format bytes into human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable format."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def merge_dicts(*dicts: Dict[str, Any]) -> Dict[str, Any]:
    """Merge multiple dictionaries, with later ones taking precedence."""
    result = {}
    for d in dicts:
        result.update(d)
    return result


def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """Split a list into chunks of specified size."""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def retry_on_exception(
    max_retries: int = 3,
    delay: float = 1.0,
    exceptions: tuple = (Exception,)
):
    """Decorator to retry function on exception."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        import time
                        time.sleep(delay * (2 ** attempt))  # Exponential backoff
                    else:
                        raise last_exception
            return None
        return wrapper
    return decorator
