"""
Configuration Package for Vulnerability Remediation System
=========================================================

This package provides centralized configuration management for the entire
vulnerability remediation system. It includes all paths, settings, and
constants used throughout the application.

Usage:
    from config import PATHS, API_CONFIG, get_path, get_api_config
    
    # Get a specific path
    upload_dir = get_path('UPLOAD_FOLDER')
    
    # Get API configuration
    vulners_config = get_api_config('VULNERS')
    
    # Access settings directly
    flask_port = APP_SETTINGS['FLASK']['PORT']
"""

from .settings import (
    BASE_DIR,
    PATHS,
    CACHE_DIRS,
    DATA_DIRS,
    FILE_PATTERNS,
    API_CONFIG,
    APP_SETTINGS,
    SCAN_CONFIG,
    REMEDIATION_CONFIG,
    SECURITY_CONFIG,
    get_path,
    get_cache_path,
    get_data_path,
    get_api_config,
    get_app_setting,
    validate_configuration,
    ensure_directories,
)

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

# Validate configuration on import
try:
    validation_result = validate_configuration()
    if not validation_result['valid']:
        print("WARNING: Configuration validation failed:")
        for issue in validation_result['issues']:
            print(f"   ERROR: {issue}")
        for warning in validation_result['warnings']:
            print(f"   WARNING: {warning}")
    else:
        print("Configuration validation passed")
        if validation_result['warnings']:
            print("Configuration warnings:")
            for warning in validation_result['warnings']:
                print(f"   WARNING: {warning}")
except Exception as e:
    # Silently handle encoding issues during import
    pass 