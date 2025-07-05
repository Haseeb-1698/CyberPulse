"""
Vulnerability Remediation System Configuration
==============================================

This module contains all configuration settings, paths, and constants used throughout
the vulnerability remediation system. It centralizes all hardcoded values to make
the system easier to maintain and configure.

Author: Vulnerability Remediation System Team
Last Updated: 2025-07-05
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional

# Add at the top after imports
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv is optional, but recommended for local development

# ─── BASE DIRECTORY CONFIGURATION ─────────────────────────────────────────────
# Base directory is the root of the project where all other paths are relative to
BASE_DIR = Path(__file__).parent.parent.absolute()

# ─── APPLICATION PATHS ───────────────────────────────────────────────────────
# Core application directories and files
PATHS = {
    # Upload directory for XML scan reports from OpenVAS
    'UPLOAD_FOLDER': BASE_DIR / 'uploads',
    
    # Output files for processed data
    'JSON_OUTPUT': BASE_DIR / 'test_vulnerabilities.json',
    'DASHBOARD_DATA': BASE_DIR / 'dashboard_data.json',
    'SCAN_HISTORY': BASE_DIR / 'scan_history.json',
    'JOBS_PERSISTENCE': BASE_DIR / 'jobs_persistence.json',
    
    # Results and reports directory
    'RESULTS_FOLDER': BASE_DIR / 'integrated_results',
    'SCANS_FOLDER': BASE_DIR / 'scans',
    
    # Web application directories
    'TEMPLATES_FOLDER': BASE_DIR / 'templates',
    'STATIC_FOLDER': BASE_DIR / 'static',
    
    # Configuration files
    'CONFIG_FILE': BASE_DIR / 'config.json',
    'REQUIREMENTS_FILE': BASE_DIR / 'requirements.txt',
}

# ─── CACHE DIRECTORIES ───────────────────────────────────────────────────────
# Cache directories for storing API responses and processed data
CACHE_DIRS = {
    # CVE data cache - stores vulnerability details from various APIs
    'CVE_CACHE': BASE_DIR / 'cve_cache',
    
    # Exploit database cache - stores exploit information
    'EXPLOIT_CACHE': BASE_DIR / 'exploit_cache',
    
    # Remediation cache - stores generated remediation data
    'REMEDIATION_CACHE': BASE_DIR / 'remediation_cache',
    
    # MITRE ATT&CK framework cache - stores threat intelligence data
    'MITRE_CACHE': BASE_DIR / 'mitre_cache',
    
    # Shodan API cache - stores network intelligence data
    'SHODAN_CACHE': BASE_DIR / 'shodan_cache',
    
    # Vulners API cache - stores vulnerability intelligence data
    'VULNERS_CACHE': BASE_DIR / 'vulners_cache',
}

# ─── DATA DIRECTORIES ───────────────────────────────────────────────────────
# Directories for storing various data files
DATA_DIRS = {
    # Exploit database files
    'EXPLOIT_DB': BASE_DIR / 'exploitdb',
    
    # Machine learning models
    'MODELS': BASE_DIR / 'models',
    
    # Remediation feedback data
    'REMEDIATION_FEEDBACK': BASE_DIR / 'remediation_feedback',
    
    # Static data for web interface
    'STATIC_DATA': BASE_DIR / 'static' / 'data',
}

# ─── FILE PATTERNS ──────────────────────────────────────────────────────────
# File patterns and extensions used throughout the system
FILE_PATTERNS = {
    # Allowed file extensions for upload
    'ALLOWED_EXTENSIONS': {'xml'},
    
    # Default file names
    'DEFAULT_FILES': {
        'EXPLOIT_DB_CSV': 'files_exploits.csv',
        'SEVERITY_MODEL': 'severity_model.pkl',
        'VULNERABILITY_CLASSIFIER': 'vulnerability_classifier.pkl',
        'INTEGRATED_CSV': 'test_vulnerabilities_integrated.csv',
        'INTEGRATED_REPORT': 'test_vulnerabilities_report.html',
        'VULNERABILITIES_DATA': 'vulnerabilities_data.json',
        'VULNERABILITIES_CSV': 'vulnerabilities.csv',
    }
}

# ─── API CONFIGURATION ──────────────────────────────────────────────────────
# API keys and endpoints for external services
API_CONFIG = {
    # Vulners API configuration
    'VULNERS': {
        'BASE_URL': 'https://vulners.com/api/v3',
        'API_KEY': os.getenv('VULNERS_API_KEY', ''),
        'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'RATE_LIMIT': 100,  # requests per minute
        'TIMEOUT': 30,  # seconds
    },
    
    # NVD API configuration
    'NVD': {
        'BASE_URL': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
        'API_KEY': os.getenv('NVD_API_KEY', ''),
        'RATE_LIMIT': 1000,  # requests per hour
        'TIMEOUT': 30,  # seconds
        'HEADERS': {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    },
    
    # Shodan API configuration
    'SHODAN': {
        'BASE_URL': 'https://api.shodan.io',
        'API_KEY': os.getenv('SHODAN_API_KEY', ''),
        'RATE_LIMIT': 100,  # requests per minute
        'TIMEOUT': 30,  # seconds
    },
    
    # MITRE ATT&CK API configuration
    'MITRE': {
        'BASE_URL': 'https://attack.mitre.org/api',
        'ENTERPRISE_URL': 'https://attack.mitre.org/enterprise.json',
        'TIMEOUT': 30,  # seconds
    },
    
    # Ollama API configuration
    'OLLAMA': {
        'BASE_URL': os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434'),
        'DEFAULT_MODEL': os.getenv('OLLAMA_MODEL', 'mistral'),
        'TIMEOUT': int(os.getenv('OLLAMA_TIMEOUT', 60)),  # seconds
        'TEMPERATURE': float(os.getenv('OLLAMA_TEMPERATURE', 0.3)),
        'CONTEXT_SIZE': int(os.getenv('OLLAMA_CONTEXT_SIZE', 8192)),
    },
}

# ─── APPLICATION SETTINGS ───────────────────────────────────────────────────
# Core application settings and behavior
APP_SETTINGS = {
    # Flask application settings
    'FLASK': {
        'SECRET_KEY': os.getenv('FLASK_SECRET_KEY', 'replace-me-with-a-secure-key'),
        'DEBUG': os.getenv('FLASK_DEBUG', 'False').lower() == 'true',
        'HOST': os.getenv('FLASK_HOST', '127.0.0.1'),
        'PORT': int(os.getenv('FLASK_PORT', 5000)),
        'THREADED': True,
    },
    
    # Job processing settings
    'JOBS': {
        'MAX_CONCURRENT_JOBS': 3,
        'JOB_TIMEOUT': 3600,  # seconds (1 hour)
        'CLEANUP_INTERVAL': 86400,  # seconds (24 hours)
    },
    
    # File processing settings
    'PROCESSING': {
        'MAX_FILE_SIZE': 50 * 1024 * 1024,  # 50MB
        'CHUNK_SIZE': 8192,  # bytes
        'ENCODING': 'utf-8',
    },
    
    # Logging settings
    'LOGGING': {
        'LEVEL': os.getenv('LOG_LEVEL', 'INFO'),
        'FORMAT': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'FILE': BASE_DIR / 'logs' / 'app.log',
        'MAX_SIZE': 10 * 1024 * 1024,  # 10MB
        'BACKUP_COUNT': 5,
    },
}

# ─── SCANNING CONFIGURATION ─────────────────────────────────────────────────
# Settings for vulnerability scanning
SCAN_CONFIG = {
    # Default scan settings
    'DEFAULT': {
        'SCAN_MODE': 'quick',  # quick, full, custom
        'TIMEOUT': 300,  # seconds
        'MAX_HOSTS': 100,
        'CONCURRENT_SCANS': 2,
    },
    
    # Scan types and their configurations
    'TYPES': {
        'quick': {
            'description': 'Quick scan for common vulnerabilities',
            'duration': '5-15 minutes',
            'coverage': 'Basic vulnerability assessment',
        },
        'full': {
            'description': 'Comprehensive vulnerability scan',
            'duration': '30-60 minutes',
            'coverage': 'Complete vulnerability assessment',
        },
        'custom': {
            'description': 'Custom scan with specific parameters',
            'duration': 'Variable',
            'coverage': 'User-defined scope',
        },
    },
}

# ─── REMEDIATION CONFIGURATION ──────────────────────────────────────────────
# Settings for remediation generation and processing
REMEDIATION_CONFIG = {
    # Remediation generation settings
    'GENERATION': {
        'MAX_REMEDIATIONS_PER_CVE': 5,
        'MIN_CONFIDENCE_SCORE': 0.7,
        'INCLUDE_EXPLOITS': True,
        'INCLUDE_THREAT_INTEL': True,
    },
    
    # Quality assessment settings
    'QUALITY': {
        'ENABLE_FEEDBACK_LOOP': True,
        'MIN_FEEDBACK_SCORE': 0.6,
        'AUTO_IMPROVE': True,
    },
    
    # Cache settings
    'CACHE': {
        'ENABLE_CACHING': True,
        'CACHE_DURATION': 86400,  # seconds (24 hours)
        'MAX_CACHE_SIZE': 100 * 1024 * 1024,  # 100MB
    },
}

# ─── SECURITY SETTINGS ──────────────────────────────────────────────────────
# Security-related configuration
SECURITY_CONFIG = {
    # CORS settings
    'CORS': {
        'ENABLED': True,
        'ORIGINS': ['http://127.0.0.1:5000', 'http://localhost:5000'],
        'METHODS': ['GET', 'POST', 'PUT', 'DELETE'],
        'HEADERS': ['Content-Type', 'Authorization'],
    },
    
    # File upload security
    'UPLOAD': {
        'ALLOWED_EXTENSIONS': FILE_PATTERNS['ALLOWED_EXTENSIONS'],
        'MAX_FILE_SIZE': APP_SETTINGS['PROCESSING']['MAX_FILE_SIZE'],
        'SCAN_UPLOADS': True,
    },
    
    # API security
    'API': {
        'RATE_LIMITING': True,
        'AUTHENTICATION': False,  # Set to True if implementing auth
        'API_KEY_REQUIRED': False,
    },
}

# ─── HELPER FUNCTIONS ───────────────────────────────────────────────────────

def ensure_directories() -> None:
    """
    Create all necessary directories if they don't exist.
    
    This function ensures that all required directories for the application
    are created during startup. It's called automatically when the config
    is imported.
    """
    directories = []
    
    # Add all paths from PATHS (only directories, not files)
    for key, path in PATHS.items():
        if key not in ['JSON_OUTPUT', 'DASHBOARD_DATA', 'SCAN_HISTORY', 'JOBS_PERSISTENCE', 'CONFIG_FILE', 'REQUIREMENTS_FILE']:
            directories.append(path)
    
    # Add all cache directories
    directories.extend(CACHE_DIRS.values())
    
    # Add all data directories
    directories.extend(DATA_DIRS.values())
    
    # Add logs directory
    directories.append(APP_SETTINGS['LOGGING']['FILE'].parent)
    
    # Create directories
    for directory in directories:
        if isinstance(directory, Path):
            directory.mkdir(parents=True, exist_ok=True)
        elif isinstance(directory, str):
            Path(directory).mkdir(parents=True, exist_ok=True)

def get_path(path_key: str) -> Path:
    """
    Get a path by its key from the configuration.
    
    Args:
        path_key: The key of the path to retrieve
        
    Returns:
        Path object for the requested path
        
    Raises:
        KeyError: If the path key doesn't exist
    """
    if path_key == 'BASE_DIR':
        return BASE_DIR
    elif path_key in PATHS:
        return PATHS[path_key]
    elif path_key in CACHE_DIRS:
        return CACHE_DIRS[path_key]
    elif path_key in DATA_DIRS:
        return DATA_DIRS[path_key]
    else:
        raise KeyError(f"Path key '{path_key}' not found in configuration")

def get_cache_path(cache_type: str, filename: str) -> Path:
    """
    Get a cache file path for a specific cache type and filename.
    
    Args:
        cache_type: Type of cache (e.g., 'CVE_CACHE', 'EXPLOIT_CACHE')
        filename: Name of the cache file
        
    Returns:
        Full path to the cache file
        
    Raises:
        KeyError: If the cache type doesn't exist
    """
    if cache_type not in CACHE_DIRS:
        raise KeyError(f"Cache type '{cache_type}' not found in configuration")
    
    return CACHE_DIRS[cache_type] / filename

def get_data_path(data_type: str, filename: str) -> Path:
    """
    Get a data file path for a specific data type and filename.
    
    Args:
        data_type: Type of data directory (e.g., 'EXPLOIT_DB', 'MODELS')
        filename: Name of the data file
        
    Returns:
        Full path to the data file
        
    Raises:
        KeyError: If the data type doesn't exist
    """
    if data_type not in DATA_DIRS:
        raise KeyError(f"Data type '{data_type}' not found in configuration")
    
    return DATA_DIRS[data_type] / filename

def get_api_config(api_name: str) -> Dict[str, Any]:
    """
    Get API configuration for a specific API.
    
    Args:
        api_name: Name of the API (e.g., 'VULNERS', 'NVD', 'SHODAN')
        
    Returns:
        Dictionary containing API configuration
        
    Raises:
        KeyError: If the API name doesn't exist
    """
    if api_name not in API_CONFIG:
        raise KeyError(f"API '{api_name}' not found in configuration")
    
    return API_CONFIG[api_name]

def get_app_setting(category: str, key: str) -> Any:
    """
    Get an application setting by category and key.
    
    Args:
        category: Setting category (e.g., 'FLASK', 'JOBS', 'PROCESSING')
        key: Setting key within the category
        
    Returns:
        The setting value
        
    Raises:
        KeyError: If the category or key doesn't exist
    """
    if category not in APP_SETTINGS:
        raise KeyError(f"Setting category '{category}' not found in configuration")
    
    if key not in APP_SETTINGS[category]:
        raise KeyError(f"Setting key '{key}' not found in category '{category}'")
    
    return APP_SETTINGS[category][key]

# ─── INITIALIZATION ─────────────────────────────────────────────────────────
# Ensure all directories exist when this module is imported
ensure_directories()

# ─── CONFIGURATION VALIDATION ───────────────────────────────────────────────
def validate_configuration() -> Dict[str, Any]:
    """
    Validate the configuration and return any issues found.
    
    Returns:
        Dictionary containing validation results and any issues
    """
    issues = []
    warnings = []
    
    # Check if required API keys are set
    for api_name, config in API_CONFIG.items():
        if 'API_KEY' in config and not config['API_KEY']:
            warnings.append(f"API key for {api_name} is not set")
    
    # Check if required directories are writable
    for dir_name, dir_path in {**PATHS, **CACHE_DIRS, **DATA_DIRS}.items():
        if isinstance(dir_path, Path) and not dir_path.exists():
            issues.append(f"Directory {dir_name} does not exist: {dir_path}")
        elif isinstance(dir_path, Path) and not os.access(dir_path, os.W_OK):
            issues.append(f"Directory {dir_name} is not writable: {dir_path}")
    
    # Check if required files exist
    required_files = [
        (PATHS['REQUIREMENTS_FILE'], 'requirements.txt'),
        (DATA_DIRS['EXPLOIT_DB'] / FILE_PATTERNS['DEFAULT_FILES']['EXPLOIT_DB_CSV'], 'exploit database CSV'),
    ]
    
    for file_path, description in required_files:
        if not file_path.exists():
            warnings.append(f"Required file {description} not found: {file_path}")
    
    return {
        'valid': len(issues) == 0,
        'issues': issues,
        'warnings': warnings,
        'summary': f"Configuration validation: {len(issues)} issues, {len(warnings)} warnings"
    }

# ─── EXPORT CONFIGURATION ───────────────────────────────────────────────────
# Export all configuration for easy access
__all__ = [
    'BASE_DIR',
    'PATHS',
    'CACHE_DIRS',
    'DATA_DIRS',
    'FILE_PATTERNS',
    'API_CONFIG',
    'APP_SETTINGS',
    'SCAN_CONFIG',
    'REMEDIATION_CONFIG',
    'SECURITY_CONFIG',
    'get_path',
    'get_cache_path',
    'get_data_path',
    'get_api_config',
    'get_app_setting',
    'validate_configuration',
    'ensure_directories',
] 