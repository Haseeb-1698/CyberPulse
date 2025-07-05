#!/usr/bin/env python3
"""
Configuration Migration Script
==============================

This script helps migrate from the old hardcoded configuration system to the new
centralized configuration system. It will:

1. Detect old hardcoded paths in Python files
2. Suggest replacements using the new configuration system
3. Create a migration report
4. Optionally perform automatic migration

Usage:
    python config/migrate_config.py [--auto] [--dry-run] [--file <filename>]

Author: Vulnerability Remediation System Team
Last Updated: 2025-07-05
"""

import os
import re
import json
import argparse
from pathlib import Path
from typing import List, Dict, Tuple, Set
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ConfigMigrationHelper:
    """Helper class for migrating configuration from hardcoded to centralized system."""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.migration_report = {
            'files_processed': 0,
            'hardcoded_paths_found': 0,
            'suggestions_made': 0,
            'migrations_performed': 0,
            'errors': [],
            'warnings': [],
            'details': []
        }
        
        # Common hardcoded path patterns to look for
        self.path_patterns = [
            # os.path.join patterns
            r'os\.path\.join\([^)]+\)',
            # Direct path assignments
            r'[A-Z_]+_FOLDER\s*=\s*os\.path\.join\([^)]+\)',
            r'[A-Z_]+_PATH\s*=\s*os\.path\.join\([^)]+\)',
            r'[A-Z_]+_FILE\s*=\s*os\.path\.join\([^)]+\)',
            # String literals that look like paths
            r'["\'][^"\']*\.(json|csv|xml|html|py|log)["\']',
            # Directory references
            r'["\'][^"\']*(uploads|results|scans|cache|static|templates|models|logs)["\']',
        ]
        
        # Mapping of old patterns to new configuration keys
        self.path_mappings = {
            # Upload and output directories
            'uploads': 'UPLOAD_FOLDER',
            'Uploads': 'UPLOAD_FOLDER',
            'integrated_results': 'RESULTS_FOLDER',
            'scans': 'SCANS_FOLDER',
            'templates': 'TEMPLATES_FOLDER',
            'static': 'STATIC_FOLDER',
            
            # Cache directories
            'cve_cache': 'CVE_CACHE',
            'exploit_cache': 'EXPLOIT_CACHE',
            'remediation_cache': 'REMEDIATION_CACHE',
            'mitre_cache': 'MITRE_CACHE',
            'shodan_cache': 'SHODAN_CACHE',
            'vulners_cache': 'VULNERS_CACHE',
            
            # Data directories
            'exploitdb': 'EXPLOIT_DB',
            'models': 'MODELS',
            'remediation_feedback': 'REMEDIATION_FEEDBACK',
            'static/data': 'STATIC_DATA',
            
            # Files
            'test_vulnerabilities.json': 'JSON_OUTPUT',
            'dashboard_data.json': 'DASHBOARD_DATA',
            'scan_history.json': 'SCAN_HISTORY',
            'jobs_persistence.json': 'JOBS_PERSISTENCE',
            'config.json': 'CONFIG_FILE',
            'requirements.txt': 'REQUIREMENTS_FILE',
            'test_vulnerabilities_integrated.csv': 'INTEGRATED_CSV',
            'test_vulnerabilities_report.html': 'INTEGRATED_REPORT',
            'vulnerabilities_data.json': 'VULNERABILITIES_DATA',
            'vulnerabilities.csv': 'VULNERABILITIES_CSV',
            'files_exploits.csv': 'EXPLOIT_DB_CSV',
            'severity_model.pkl': 'SEVERITY_MODEL',
            'vulnerability_classifier.pkl': 'VULNERABILITY_CLASSIFIER',
        }
        
        # Files to exclude from migration
        self.exclude_files = {
            'config/settings.py',
            'config/__init__.py',
            'config/migrate_config.py',
            'README.md',
            'requirements.txt',
            '.gitignore',
            '__pycache__',
            '.git',
            '.vscode',
            '.idea',
        }
        
        # Files to include (if specified)
        self.include_files = set()
    
    def should_process_file(self, file_path: Path) -> bool:
        """Determine if a file should be processed for migration."""
        # Skip excluded files
        if file_path.name in self.exclude_files:
            return False
        
        # Skip directories
        if file_path.is_dir():
            return False
        
        # Skip non-Python files unless specifically included
        if file_path.suffix not in ['.py', '.pyw'] and str(file_path) not in self.include_files:
            return False
        
        # Skip if specific files are specified and this file is not in the list
        if self.include_files and str(file_path) not in self.include_files:
            return False
        
        return True
    
    def find_hardcoded_paths(self, file_path: Path) -> List[Dict]:
        """Find hardcoded paths in a file."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                for pattern in self.path_patterns:
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        finding = {
                            'file': str(file_path),
                            'line': line_num,
                            'line_content': line.strip(),
                            'match': match.group(),
                            'start': match.start(),
                            'end': match.end(),
                            'suggestion': self.generate_suggestion(match.group(), line),
                            'migrated': False
                        }
                        findings.append(finding)
            
        except Exception as e:
            self.migration_report['errors'].append(f"Error processing {file_path}: {e}")
        
        return findings
    
    def generate_suggestion(self, match: str, line: str) -> str:
        """Generate a suggestion for replacing a hardcoded path."""
        # Handle os.path.join patterns
        if 'os.path.join' in match:
            return self.suggest_path_join_replacement(match, line)
        
        # Handle direct path assignments
        if any(keyword in line for keyword in ['_FOLDER', '_PATH', '_FILE']):
            return self.suggest_direct_assignment_replacement(line)
        
        # Handle string literals
        if match.startswith('"') or match.startswith("'"):
            return self.suggest_string_literal_replacement(match, line)
        
        return f"# TODO: Replace '{match}' with appropriate configuration function"
    
    def suggest_path_join_replacement(self, match: str, line: str) -> str:
        """Suggest replacement for os.path.join patterns."""
        # Extract the arguments from os.path.join
        args_match = re.search(r'os\.path\.join\(([^)]+)\)', match)
        if not args_match:
            return f"# TODO: Replace '{match}' with get_path() or get_cache_path()"
        
        args_str = args_match.group(1)
        args = [arg.strip().strip('"\'') for arg in args_str.split(',')]
        
        # Try to map to a known path
        for arg in args:
            if arg in self.path_mappings:
                config_key = self.path_mappings[arg]
                if config_key in ['CVE_CACHE', 'EXPLOIT_CACHE', 'REMEDIATION_CACHE', 'MITRE_CACHE', 'SHODAN_CACHE', 'VULNERS_CACHE']:
                    return f"get_cache_path('{config_key}', filename)"
                elif config_key in ['EXPLOIT_DB', 'MODELS', 'REMEDIATION_FEEDBACK', 'STATIC_DATA']:
                    return f"get_data_path('{config_key}', filename)"
                else:
                    return f"get_path('{config_key}')"
        
        # If no direct mapping, suggest a generic replacement
        return f"# TODO: Replace '{match}' with get_path() or appropriate configuration function"
    
    def suggest_direct_assignment_replacement(self, line: str) -> str:
        """Suggest replacement for direct path assignments."""
        # Look for variable assignments
        var_match = re.search(r'([A-Z_]+)\s*=\s*os\.path\.join\([^)]+\)', line)
        if var_match:
            var_name = var_match.group(1)
            # Try to map the variable name to a configuration key
            for key, value in self.path_mappings.items():
                if key.upper() in var_name or var_name in key.upper():
                    return f"{var_name} = get_path('{value}')"
        
        return f"# TODO: Replace direct assignment with get_path() or appropriate configuration function"
    
    def suggest_string_literal_replacement(self, match: str, line: str) -> str:
        """Suggest replacement for string literal paths."""
        path_str = match.strip('"\'')
        
        # Check if it's a file in a known directory
        for key, value in self.path_mappings.items():
            if key in path_str:
                if value in ['CVE_CACHE', 'EXPLOIT_CACHE', 'REMEDIATION_CACHE', 'MITRE_CACHE', 'SHODAN_CACHE', 'VULNERS_CACHE']:
                    filename = os.path.basename(path_str)
                    return f"get_cache_path('{value}', '{filename}')"
                elif value in ['EXPLOIT_DB', 'MODELS', 'REMEDIATION_FEEDBACK', 'STATIC_DATA']:
                    filename = os.path.basename(path_str)
                    return f"get_data_path('{value}', '{filename}')"
                else:
                    return f"get_path('{value}')"
        
        return f"# TODO: Replace '{match}' with appropriate configuration function"
    
    def migrate_file(self, file_path: Path, findings: List[Dict], dry_run: bool = True) -> bool:
        """Migrate a file by replacing hardcoded paths."""
        if not findings:
            return True
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Sort findings by line number in reverse order to avoid offset issues
            findings.sort(key=lambda x: x['line'], reverse=True)
            
            # Apply migrations
            for finding in findings:
                if finding['suggestion'].startswith('# TODO:'):
                    continue  # Skip suggestions that need manual review
                
                line_num = finding['line'] - 1  # Convert to 0-based index
                if line_num < len(lines):
                    old_line = lines[line_num]
                    new_line = old_line[:finding['start']] + finding['suggestion'] + old_line[finding['end']:]
                    lines[line_num] = new_line
                    finding['migrated'] = True
            
            # Write back to file if not dry run
            if not dry_run:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(lines))
                logger.info(f"Migrated {file_path}")
            else:
                logger.info(f"Would migrate {file_path} (dry run)")
            
            return True
            
        except Exception as e:
            self.migration_report['errors'].append(f"Error migrating {file_path}: {e}")
            return False
    
    def process_directory(self, dry_run: bool = True) -> Dict:
        """Process all files in the directory for migration."""
        logger.info(f"Starting configuration migration in {self.base_dir}")
        
        # Find all Python files
        python_files = []
        for file_path in self.base_dir.rglob('*'):
            if self.should_process_file(file_path):
                python_files.append(file_path)
        
        logger.info(f"Found {len(python_files)} files to process")
        
        # Process each file
        for file_path in python_files:
            logger.info(f"Processing {file_path}")
            self.migration_report['files_processed'] += 1
            
            # Find hardcoded paths
            findings = self.find_hardcoded_paths(file_path)
            self.migration_report['hardcoded_paths_found'] += len(findings)
            
            if findings:
                self.migration_report['details'].append({
                    'file': str(file_path),
                    'findings': findings
                })
                
                # Migrate the file
                if self.migrate_file(file_path, findings, dry_run):
                    migrated_count = sum(1 for f in findings if f['migrated'])
                    self.migration_report['migrations_performed'] += migrated_count
                    self.migration_report['suggestions_made'] += len(findings)
        
        return self.migration_report
    
    def generate_report(self, output_file: str = None) -> str:
        """Generate a migration report."""
        report_lines = [
            "Configuration Migration Report",
            "============================",
            "",
            f"Files processed: {self.migration_report['files_processed']}",
            f"Hardcoded paths found: {self.migration_report['hardcoded_paths_found']}",
            f"Suggestions made: {self.migration_report['suggestions_made']}",
            f"Migrations performed: {self.migration_report['migrations_performed']}",
            "",
        ]
        
        if self.migration_report['errors']:
            report_lines.extend([
                "Errors:",
                "-------"
            ])
            for error in self.migration_report['errors']:
                report_lines.append(f"  - {error}")
            report_lines.append("")
        
        if self.migration_report['warnings']:
            report_lines.extend([
                "Warnings:",
                "---------"
            ])
            for warning in self.migration_report['warnings']:
                report_lines.append(f"  - {warning}")
            report_lines.append("")
        
        if self.migration_report['details']:
            report_lines.extend([
                "Detailed Findings:",
                "-----------------"
            ])
            for detail in self.migration_report['details']:
                report_lines.extend([
                    f"File: {detail['file']}",
                    f"  Findings: {len(detail['findings'])}"
                ])
                for finding in detail['findings']:
                    report_lines.extend([
                        f"    Line {finding['line']}: {finding['match']}",
                        f"    Suggestion: {finding['suggestion']}",
                        f"    Migrated: {finding['migrated']}",
                        ""
                    ])
        
        report = '\n'.join(report_lines)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"Migration report saved to {output_file}")
        
        return report

def main():
    """Main function for the migration script."""
    parser = argparse.ArgumentParser(description='Migrate hardcoded configuration to centralized system')
    parser.add_argument('--auto', action='store_true', help='Perform automatic migration')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be migrated without making changes')
    parser.add_argument('--file', type=str, help='Process only specific files (comma-separated)')
    parser.add_argument('--output', type=str, help='Output file for migration report')
    parser.add_argument('--base-dir', type=str, default='.', help='Base directory to process')
    
    args = parser.parse_args()
    
    base_dir = Path(args.base_dir).resolve()
    if not base_dir.exists():
        logger.error(f"Base directory does not exist: {base_dir}")
        return 1
    
    # Initialize migration helper
    helper = ConfigMigrationHelper(base_dir)
    
    # Set include files if specified
    if args.file:
        helper.include_files = set(args.file.split(','))
    
    # Determine if this is a dry run
    dry_run = args.dry_run or not args.auto
    
    # Process the directory
    report = helper.process_directory(dry_run=dry_run)
    
    # Generate and display report
    report_text = helper.generate_report(args.output)
    print(report_text)
    
    # Summary
    if dry_run:
        print("\n" + "="*50)
        print("DRY RUN COMPLETED")
        print("To perform actual migration, run with --auto flag")
        print("="*50)
    else:
        print("\n" + "="*50)
        print("MIGRATION COMPLETED")
        print(f"Migrated {report['migrations_performed']} hardcoded paths")
        print("="*50)
    
    return 0

if __name__ == '__main__':
    exit(main()) 