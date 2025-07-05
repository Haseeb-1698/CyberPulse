"""
Prerequisite Checker for Enhanced Remediation System

This script checks for all required directories, files, and dependencies
needed to run the enhanced_remediation_system_fixed.py script. It now
includes XML to JSON conversion for OpenVAS reports.
"""

import os
import sys
import json
import pickle
import importlib
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

# Set your working directory here - change this to match your setup
WORK_DIR = "C:/Users/cb26h/Desktop/pipeline/pipeline"  # Updated to match the actual working directory

# Required directories
REQUIRED_DIRS = [
    "remediation_cache",
    "cve_cache",
    "remediation_feedback",
    "integrated_results",
    "models",
    "exploitdb"
]

# Required files
# Updated to handle both XML and JSON test data files
REQUIRED_FILES = [
    {
        "path": os.path.join("models", "severity_model.pkl"),
        "description": "Severity prediction model",
        "critical": True,
        "create_function": "create_dummy_model",
        "prompt": "Severity prediction model is missing. Would you like to create a dummy model for testing?"
    },
    {
        "path": os.path.join("exploitdb", "files_exploits.csv"),
        "description": "ExploitDB CSV file",
        "critical": False,  # Not critical as the system can create a sample one
        "create_function": "create_sample_exploitdb",
        "prompt": "ExploitDB CSV file is missing. Would you like to create a sample file for testing?"
    },
    {
        "path": "process_download_openvas.py",
        "description": "OpenVAS processing module",
        "critical": True,
        "create_function": "create_openvas_module",
        "prompt": "OpenVAS processing module is missing. Would you like to create a minimal implementation?"
    },
    {
        "path": "test_vulnerabilities.json",
        "xml_path": "test_vulnerabilities.xml",  # Optional XML input
        "description": "Test vulnerability data (JSON or XML)",
        "critical": False,
        "create_function": "create_test_data",
        "prompt": "Test vulnerability data is missing. Would you like to create sample data for testing?"
    }
]

# Path to requirements.txt file
REQUIREMENTS_FILE = os.path.join(WORK_DIR, "requirements.txt")

def ask_yes_no(question, default="yes"):
    """Ask a yes/no question and return the answer"""
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError(f"Invalid default answer: '{default}'")
    
    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

def create_requirements_file():
    """Create a requirements.txt file if it doesn't exist"""
    if os.path.exists(REQUIREMENTS_FILE):
        print(f"✅ requirements.txt already exists at {REQUIREMENTS_FILE}")
        return True
    
    # Ask the user if they want to create the file
    if not ask_yes_no("requirements.txt file is missing. Would you like to create one?"):
        print("ℹ️ Skipping creation of requirements.txt")
        return False
    
    try:
        with open(REQUIREMENTS_FILE, 'w') as f:
            f.write("""# Requirements for Enhanced Remediation System
pandas>=1.0.0
numpy>=1.18.0
requests>=2.25.0
scikit-learn>=0.24.0
nltk>=3.5
sentence-transformers>=2.0.0
scipy>=1.6.0
""")
        print(f"✅ Created requirements.txt at {REQUIREMENTS_FILE}")
        return True
    except Exception as e:
        print(f"❌ Failed to create requirements.txt: {e}")
        return False

def convert_openvas_xml_to_json(xml_path, json_path):
    """Convert OpenVAS XML report to the JSON format expected by the system"""
    try:
        # Parse the XML file
        tree = ET.parse(xml_path)
        root = tree.getroot()

        # Initialize the JSON structure
        json_data = {
            "report": {
                "results": {
                    "result": []
                }
            }
        }

        # Find all result elements
        results = root.findall(".//result")
        if not results:
            print("⚠️ No vulnerability results found in XML file")
            return False

        for result in results:
            # Extract CVE IDs from refs
            cve_ids = []
            refs = result.find(".//refs")
            if refs is not None:
                for ref in refs.findall(".//ref[@type='cve']"):
                    cve_id = ref.get('id')
                    if cve_id:
                        cve_ids.append(cve_id)

            # Extract data from each result
            result_data = {
                "cve": cve_ids[0] if cve_ids else "",  # Use first CVE ID if available
                "severity": result.findtext("severity", default="0.0"),
                "threat": result.findtext("threat", default="Unknown"),
                "description": result.findtext("description", default=""),
                "port": result.findtext("port", default="Unknown"),
                "nvt": {
                    "name": "",
                    "description": "",
                    "solution": {
                        "text": ""
                    }
                }
            }

            # Extract NVT details
            nvt = result.find("nvt")
            if nvt is not None:
                result_data["nvt"]["name"] = nvt.findtext("name", default="Unknown")
                result_data["nvt"]["description"] = nvt.findtext("description", default="")
                solution = nvt.find("solution")
                if solution is not None:
                    result_data["nvt"]["solution"]["text"] = solution.findtext("text", default="")

            # Add all CVE IDs to the result
            if len(cve_ids) > 1:
                result_data["additional_cves"] = cve_ids[1:]

            json_data["report"]["results"]["result"].append(result_data)

        # Write to JSON file
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2)

        print(f"✅ Converted XML file {xml_path} to JSON at {json_path}")
        print(f"   Found {len(json_data['report']['results']['result'])} vulnerabilities")
        return True
    except Exception as e:
        print(f"❌ Failed to convert XML to JSON: {e}")
        return False

def check_python_version():
    """Check if Python version is at least 3.6"""
    print("\n--- Checking Python Version ---")
    major, minor = sys.version_info[:2]
    if major < 3 or (major == 3 and minor < 6):
        print("❌ ERROR: Python 3.6 or higher is required")
        print(f"   Current version: {major}.{minor}")
        return False
    else:
        print(f"✅ Python version {major}.{minor} is compatible")
        return True

def check_directories():
    """Check and create required directories"""
    print("\n--- Checking Required Directories ---")
    missing_dirs = []
    
    for directory in REQUIRED_DIRS:
        dir_path = os.path.join(WORK_DIR, directory)
        if not os.path.exists(dir_path):
            missing_dirs.append(directory)
            print(f"⚠️ Directory missing: {directory}")
        else:
            print(f"✅ Directory exists: {directory}")
    
    if missing_dirs:
        print(f"\nℹ️ {len(missing_dirs)} directories are missing")
        create_dirs = ask_yes_no("Would you like to create the missing directories?")
        if create_dirs:
            for directory in missing_dirs:
                dir_path = os.path.join(WORK_DIR, directory)
                try:
                    os.makedirs(dir_path)
                    print(f"✅ Created directory: {directory}")
                except Exception as e:
                    print(f"❌ Failed to create directory {directory}: {e}")
                    return False
        else:
            print("ℹ️ Skipping directory creation")
            print("⚠️ Note: The system may fail without the required directories")
    else:
        print("ℹ️ All required directories already exist")
    
    return True

def check_files():
    """Check required files, including XML to JSON conversion"""
    print("\n--- Checking Required Files ---")
    missing_files = []
    
    for file_info in REQUIRED_FILES:
        file_path = os.path.join(WORK_DIR, file_info["path"])
        # Check for XML file if specified
        xml_path = file_info.get("xml_path")
        if xml_path:
            xml_full_path = os.path.join(WORK_DIR, xml_path)
            # If JSON doesn't exist but XML does, offer to convert
            if not os.path.exists(file_path) and os.path.exists(xml_full_path):
                print(f"⚠️ JSON file missing: {file_info['path']} - {file_info['description']}")
                print(f"ℹ️ Found corresponding XML file: {xml_path}")
                if ask_yes_no(f"Would you like to convert {xml_path} to JSON?"):
                    convert_openvas_xml_to_json(xml_full_path, file_path)
                else:
                    print("ℹ️ Skipping XML to JSON conversion")
            elif os.path.exists(file_path):
                print(f"✅ File exists: {file_info['path']}")
                continue
            elif os.path.exists(xml_full_path):
                print(f"⚠️ JSON file missing: {file_info['path']} - {file_info['description']}")
                print(f"ℹ️ Found corresponding XML file: {xml_path}")
                if ask_yes_no(f"Would you like to convert {xml_path} to JSON?"):
                    convert_openvas_xml_to_json(xml_full_path, file_path)
                else:
                    print("ℹ️ Skipping XML to JSON conversion")
                    missing_files.append(file_info)
            else:
                print(f"❌ Missing: {file_info['path']} - {file_info['description']}")
                print(f"ℹ️ Also missing XML alternative: {xml_path}")
                missing_files.append(file_info)
        else:
            # Handle non-XML/JSON files as before
            if not os.path.exists(file_path):
                missing_files.append(file_info)
                print(f"❌ Missing: {file_info['path']} - {file_info['description']}")
            else:
                print(f"✅ File exists: {file_info['path']}")
    
    if missing_files:
        print(f"\nℹ️ Missing {len(missing_files)} required files")
        handle_missing_files(missing_files)
    else:
        print("\nℹ️ All required files are present")
    
    return len([f for f in missing_files if f["critical"] and not os.path.exists(os.path.join(WORK_DIR, f["path"]))]) == 0

def handle_missing_files(missing_files):
    """Handle missing files - ask user before creating"""
    critical_missing = [f for f in missing_files if f["critical"]]
    non_critical_missing = [f for f in missing_files if not f["critical"]]
    
    if critical_missing:
        print("\n⚠️ CRITICAL FILES MISSING:")
        for file_info in critical_missing:
            handle_missing_file(file_info)
    
    if non_critical_missing:
        print("\nℹ️ OPTIONAL FILES MISSING:")
        for file_info in non_critical_missing:
            handle_missing_file(file_info)

def handle_missing_file(file_info):
    """Handle a single missing file - ask user before creating"""
    file_path = os.path.join(WORK_DIR, file_info["path"])
    
    if "create_function" in file_info and "prompt" in file_info:
        print(f"\n- {file_info['path']} ({file_info['description']})")
        if ask_yes_no(file_info["prompt"]):
            # Call the appropriate function to create the file
            func_name = file_info["create_function"]
            if func_name == "create_sample_exploitdb":
                create_sample_exploitdb(file_path)
            elif func_name == "create_test_data":
                create_test_data(file_path)
            elif func_name == "create_dummy_model":
                create_dummy_model(file_path)
            elif func_name == "create_openvas_module":
                create_openvas_module(file_path)
        else:
            print(f"ℹ️ Skipped creation of {file_info['path']}")
            if file_info["critical"]:
                print(f"⚠️ This file is critical and must be provided manually to run the system")
    else:
        print(f"- {file_info['path']} ({file_info['description']})")
        print(f"  ⚠️ This file is required but cannot be automatically created")

def create_sample_exploitdb(output_path):
    """Create a sample ExploitDB CSV file"""
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    try:
        # Sample exploit data
        sample_exploits = [
            {
                'id': '40839',
                'file': '40839.py',
                'description': 'Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - Remote Code Execution (CVE-2017-5638)',
                'date': '2017-03-14',
                'author': 'research',
                'type': 'webapps',
                'platform': 'multiple',
                'port': '80'
            },
            {
                'id': '42324',
                'file': '42324.py',
                'description': 'EternalBlue SMB Remote Code Execution (MS17-010) (CVE-2017-0144)',
                'date': '2017-05-07',
                'author': 'research',
                'type': 'remote',
                'platform': 'windows',
                'port': '445'
            },
            {
                'id': '46153',
                'file': '46153.py',
                'description': 'Apache Log4j 2.0-beta9 to 2.12.1, 2.13.0 to 2.15.0 - JNDI Injection (CVE-2021-44228)',
                'date': '2021-12-10',
                'author': 'research',
                'type': 'remote',
                'platform': 'multiple',
                'port': '0'
            },
            {
                'id': '47655',
                'file': '47655.py',
                'description': 'Spring Core and Spring Cloud Function SpEL Injection (CVE-2022-22965)',
                'date': '2022-03-30',
                'author': 'research',
                'type': 'webapps',
                'platform': 'java',
                'port': '8080'
            },
            {
                'id': '46362',
                'file': '46362.py',
                'description': 'Citrix ADC and Gateway - Remote Code Execution (CVE-2019-19781)',
                'date': '2019-12-28',
                'author': 'research',
                'type': 'remote',
                'platform': 'multiple',
                'port': '443'
            },
            {
                'id': '45380',
                'file': '45380.py',
                'description': 'BlueKeep - Microsoft Windows Remote Desktop RCE (CVE-2019-0708)',
                'date': '2019-05-15',
                'author': 'research',
                'type': 'remote',
                'platform': 'windows',
                'port': '3389'
            }
        ]
        
        # Write the sample data to a CSV file
        import csv
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['id', 'file', 'description', 'date', 'author', 'type', 'platform', 'port']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for exploit in sample_exploits:
                writer.writerow(exploit)
        
        print(f"✅ Created sample ExploitDB file with {len(sample_exploits)} entries at {output_path}")
        return True
    except Exception as e:
        print(f"❌ Failed to create sample ExploitDB file: {e}")
        return False

def create_test_data(output_path):
    """Create a sample vulnerability dataset for testing"""
    try:
        sample_data = {
            "report": {
                "results": {
                    "result": [
                        {
                            "cve": "CVE-2021-44228",
                            "severity": "10.0",
                            "threat": "Critical",
                            "description": "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                            "nvt": {
                                "name": "Log4Shell",
                                "description": "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                                "solution": {
                                    "text": ""
                                }
                            },
                            "port": "general/tcp"
                        },
                        {
                            "cve": "CVE-2022-22965",
                            "severity": "8.2",
                            "threat": "High",
                            "description": "Spring Framework RCE vulnerability. A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding.",
                            "nvt": {
                                "name": "Spring4Shell",
                                "description": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding.",
                                "solution": {
                                    "text": ""
                                }
                            },
                            "port": "8080/tcp"
                        },
                        {
                            "cve": "CVE-2019-0708",
                            "severity": "9.8",
                            "threat": "Critical",
                            "description": "BlueKeep Remote Desktop vulnerability. A remote code execution vulnerability exists in Remote Desktop Services when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests.",
                            "nvt": {
                                "name": "BlueKeep",
                                "description": "A remote code execution vulnerability exists in Remote Desktop Services when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests.",
                                "solution": {
                                    "text": "Apply the appropriate patches."
                                }
                            },
                            "port": "3389/tcp"
                        }
                    ]
                }
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(sample_data, f, indent=2)
        
        print(f"✅ Created sample test data with 3 vulnerabilities at {output_path}")
        return True
    except Exception as e:
        print(f"❌ Failed to create test data: {e}")
        return False

def create_dummy_model(output_path):
    """Create a dummy severity prediction model for testing"""
    try:
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Create a simple random forest model
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        
        # Train on dummy data
        X = np.array([
            [7.5, 3.0, 4.5, 1, 2.0, 100],  # High severity
            [5.5, 2.2, 3.3, 0, 0.0, 0],    # Medium severity
            [3.5, 1.4, 2.1, 0, 0.0, 0]     # Low severity
        ])
        y = np.array(['High', 'Medium', 'Low'])
        
        model.fit(X, y)
        
        # Save the model
        with open(output_path, 'wb') as f:
            pickle.dump(model, f)
        
        print(f"✅ Created dummy severity model at {output_path}")
        return True
    except Exception as e:
        print(f"❌ Failed to create dummy model: {e}")
        return False

def check_openvas_module():
    """Check if the process_download_openvas.py module is valid"""
    print("\n--- Checking OpenVAS Processing Module ---")
    module_path = os.path.join(WORK_DIR, "process_download_openvas.py")
    
    if not os.path.exists(module_path):
        print("❌ process_download_openvas.py is missing")
        # Creation of this file is handled by check_files() function
        return False
    
    # Check if module has required functions
    required_functions = [
        "extract_openvas_data",
        "preprocess_openvas_data",
        "predict_severity"
    ]
    
    try:
        # Add WORK_DIR to Python path temporarily
        sys.path.insert(0, WORK_DIR)
        
        # Try to import the module
        spec = importlib.util.spec_from_file_location("process_download_openvas", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        missing_functions = []
        for func in required_functions:
            if not hasattr(module, func):
                missing_functions.append(func)
        
        if missing_functions:
            print(f"❌ Missing required functions in process_download_openvas.py: {', '.join(missing_functions)}")
            return False
        else:
            print("✅ process_download_openvas.py is valid and contains all required functions")
            return True
    except Exception as e:
        print(f"❌ Error validating process_download_openvas.py: {e}")
        return False
    finally:
        # Remove WORK_DIR from Python path
        if WORK_DIR in sys.path:
            sys.path.remove(WORK_DIR)

def create_openvas_module(output_path):
    """Create a minimal process_download_openvas.py module"""
    try:
        with open(output_path, 'w') as f:
            f.write('''import json
import pandas as pd
import numpy as np
import pickle
import os
import re

def extract_openvas_data(json_file):
    """
    Extract vulnerability data from OpenVAS JSON output.
    
    Args:
        json_file: Path to OpenVAS JSON file
        
    Returns:
        List of vulnerability dictionaries
    """
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        results = []
        
        # Extract results from different possible structures
        if 'report' in data and 'results' in data['report']:
            results = data['report']['results'].get('result', [])
            if isinstance(results, dict):
                results = [results]
        elif 'results' in data:
            results = data['results'].get('result', [])
            if isinstance(results, dict):
                results = [results]
        
        return results
    except Exception as e:
        print(f"Error extracting OpenVAS data: {e}")
        return []

def preprocess_openvas_data(vulnerabilities, exploit_db_path=None):
    """
    Preprocess vulnerability data for the model.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        exploit_db_path: Path to ExploitDB CSV
        
    Returns:
        DataFrame with preprocessed data
    """
    if not vulnerabilities:
        return pd.DataFrame()
    
    # Convert to DataFrame
    data = []
    for vuln in vulnerabilities:
        item = {
            'name': vuln.get('name', vuln.get('nvt', {}).get('name', 'Unknown')),
            'description': vuln.get('description', vuln.get('nvt', {}).get('description', '')),
            'cve_id': vuln.get('cve', ''),
            'cvss_v3_score': float(vuln.get('severity', 0)),
            'original_threat': vuln.get('threat', 'Unknown'),
            'port': vuln.get('port', 'Unknown'),
            'cvss_v3_exploitability': 0.0,  # Default value
            'cvss_v3_impact': 0.0,  # Default value
            'has_known_exploit': False,  # Default value
            'exploit_maturity_score': 0.0,  # Default value
            'exploit_age_days': 0  # Default value
        }
        data.append(item)
    
    df = pd.DataFrame(data)
    
    # Add exploitability and impact based on CVSS
    df['cvss_v3_exploitability'] = df['cvss_v3_score'] * 0.4  # Simplified calculation
    df['cvss_v3_impact'] = df['cvss_v3_score'] * 0.6  # Simplified calculation
    
    # Extract cve_id pattern if exists but wasn't correctly extracted
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    for idx, row in df.iterrows():
        if not row['cve_id']:
            desc = str(row['description'])
            cve_matches = re.findall(cve_pattern, desc, re.IGNORECASE)
            if cve_matches:
                df.at[idx, 'cve_id'] = cve_matches[0].upper()
    
    # Add default features if exploit_db integration not available
    df['has_known_exploit'] = False
    df['exploit_maturity_score'] = 0.0
    df['exploit_age_days'] = 0
    
    return df

def predict_severity(df, model_path):
    """
    Predict severity using the trained model.
    
    Args:
        df: DataFrame with preprocessed vulnerability data
        model_path: Path to the trained model pickle file
        
    Returns:
        DataFrame with predicted severity
    """
    if df.empty:
        return df
    
    try:
        # Load the model
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        
        # Prepare features
        feature_cols = [
            'cvss_v3_score', 'cvss_v3_exploitability', 'cvss_v3_impact',
            'has_known_exploit', 'exploit_maturity_score', 'exploit_age_days'
        ]
        
        # Ensure all feature columns exist
        for col in feature_cols:
            if col not in df.columns:
                df[col] = 0.0
        
        # Make predictions
        X = df[feature_cols]
        
        # Get prediction probabilities
        proba = model.predict_proba(X)
        predictions = model.predict(X)
        
        # Add predictions to DataFrame
        df['predicted_severity'] = predictions
        df['prediction_confidence'] = proba.max(axis=1)
        
        return df
    except Exception as e:
        print(f"Error predicting severity: {e}")
        # Fallback to CVSS-based severity
        df['predicted_severity'] = df['cvss_v3_score'].apply(
            lambda x: 'High' if x >= 7.0 else 'Medium' if x >= 4.0 else 'Low'
        )
        df['prediction_confidence'] = 0.7  # Default confidence
        return df

def fallback_cvss_based_severity(df):
    """Fill missing severity predictions based on CVSS score."""
    mask = df['predicted_severity'].isnull()
    df.loc[mask, 'predicted_severity'] = df.loc[mask, 'cvss_v3_score'].apply(
        lambda x: 'High' if x >= 7.0 else 'Medium' if x >= 4.0 else 'Low'
    )
    return df

def enhanced_calibration(df):
    """Enhance severity predictions based on exploit information."""
    # If there's a known exploit, increase severity
    exploit_mask = df['has_known_exploit'] == True
    med_mask = (df['predicted_severity'] == 'Medium') & exploit_mask
    df.loc[med_mask, 'predicted_severity'] = 'High'
    
    # High CVSS with high exploitability should be High severity
    high_cvss_mask = (df['cvss_v3_score'] >= 9.0) & (df['cvss_v3_exploitability'] >= 3.0)
    df.loc[high_cvss_mask, 'predicted_severity'] = 'High'
    
    return df
''')
        print(f"✅ Created minimal process_download_openvas.py module at {output_path}")
        return True
    except Exception as e:
        print(f"❌ Failed to create process_download_openvas.py: {e}")
        return False

def check_packages_from_requirements():
    """Check if required Python packages from requirements.txt are installed"""
    print("\n--- Checking Required Python Packages from requirements.txt ---")
    
    # Check if requirements.txt exists
    if not os.path.exists(REQUIREMENTS_FILE):
        print("⚠️ requirements.txt not found")
        create_requirements_file()
        
    if not os.path.exists(REQUIREMENTS_FILE):
        print("⚠️ Checking default package list instead")
        return check_default_packages()
    
    # Parse requirements.txt
    try:
        with open(REQUIREMENTS_FILE, 'r') as f:
            requirements = []
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Handle version specifications
                    package = line.split('==')[0].split('>=')[0].split('<=')[0].strip()
                    if package:
                        requirements.append(package)
        
        if not requirements:
            print("⚠️ No packages found in requirements.txt")
            return check_default_packages()
            
        print(f"Found {len(requirements)} packages in requirements.txt")
        
        # Check each package
        missing_packages = []
        for package in requirements:
            try:
                importlib.import_module(package)
                print(f"✅ Package installed: {package}")
            except ImportError:
                missing_packages.append(package)
                print(f"❌ Package missing: {package}")
        
        if missing_packages:
            print(f"\nℹ️ {len(missing_packages)} required packages are missing")
            if ask_yes_no("Would you like to install missing packages?"):
                install_missing_packages(missing_packages)
            else:
                print("\nTo manually install missing packages, run:")
                print(f"pip install {' '.join(missing_packages)}")
        else:
            print("\nℹ️ All required packages are installed")
        
        return len(missing_packages) == 0
    
    except Exception as e:
        print(f"❌ Error parsing requirements.txt: {e}")
        return check_default_packages()

def check_default_packages():
    """Check if default required Python packages are installed"""
    default_packages = [
        "pandas",
        "numpy",
        "requests",
        "scikit-learn",
        "nltk",
        "sentence-transformers",
        "scipy"
    ]
    
    missing_packages = []
    
    for package in default_packages:
        try:
            importlib.import_module(package)
            print(f"✅ Package installed: {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ Package missing: {package}")
    
    if missing_packages:
        print(f"\nℹ️ {len(missing_packages)} required packages are missing")
        if ask_yes_no("Would you like to install missing packages?"):
            install_missing_packages(missing_packages)
        else:
            print("\nTo manually install missing packages, run:")
            print(f"pip install {' '.join(missing_packages)}")
    else:
        print("\nℹ️ All required packages are installed")
    
    return len(missing_packages) == 0

def install_missing_packages(packages):
    """Attempt to install missing packages"""
    if not packages:
        return True
    
    print("\nAttempting to install missing packages...")
    success = True
    
    for package in packages:
        try:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"✅ Successfully installed {package}")
        except Exception as e:
            print(f"❌ Error installing {package}: {e}")
            success = False
    
    if not success:
        print("\nSome packages could not be installed automatically.")
        print("To manually install missing packages, run:")
        print(f"pip install {' '.join(packages)}")
    
    return success

def check_nltk_data():
    """Check if required NLTK data is downloaded"""
    print("\n--- Checking NLTK Data ---")
    try:
        import nltk
        nltk_data_needed = ['punkt']
        missing_data = []
        
        for data in nltk_data_needed:
            try:
                nltk.data.find(f'tokenizers/{data}')
                print(f"✅ NLTK data exists: {data}")
            except LookupError:
                missing_data.append(data)
                print(f"❌ NLTK data missing: {data}")
        
        if missing_data:
            print("\nℹ️ NLTK data components are missing")
            if ask_yes_no("Would you like to download missing NLTK data?"):
                print("\nDownloading missing NLTK data...")
                for data in missing_data:
                    nltk.download(data)
                    print(f"✅ Downloaded NLTK data: {data}")
            else:
                print("ℹ️ Skipping NLTK data download")
                print("⚠️ Some functionality may be limited without NLTK data")
        
        return True
    except Exception as e:
        print(f"❌ Error checking NLTK data: {e}")
        return False

def main():
    """Main function to check all prerequisites"""
    print("=" * 60)
    print("Enhanced Remediation System - Prerequisite Checker")
    print("=" * 60)
    print(f"Working directory: {WORK_DIR}")
    
    # Ensure WORK_DIR exists
    if not os.path.exists(WORK_DIR):
        print(f"❌ ERROR: Working directory {WORK_DIR} does not exist")
        print("   Please modify WORK_DIR in this script to match your setup")
        return False
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Check requirements.txt and create if missing
    create_requirements_file()
    
    # Check required packages from requirements.txt
    packages_ok = check_packages_from_requirements()
    
    # Check directories
    dirs_ok = check_directories()
    
    # Check files (including XML to JSON conversion)
    files_ok = check_files()
    
    # Check OpenVAS module
    openvas_ok = check_openvas_module()
    
    # Check NLTK data
    nltk_ok = check_nltk_data()
    
    # Summary
    print("\n" + "=" * 60)
    print("Prerequisite Check Summary")
    print("=" * 60)
    print(f"Python version: {'✅' if check_python_version() else '❌'}")
    print(f"Required packages: {'✅' if packages_ok else '⚠️'}")
    print(f"Required directories: {'✅' if dirs_ok else '⚠️'}")
    print(f"Required files: {'✅' if files_ok else '⚠️'}")
    print(f"OpenVAS module: {'✅' if openvas_ok else '⚠️'}")
    print(f"NLTK data: {'✅' if nltk_ok else '⚠️'}")
    
    all_ok = packages_ok and dirs_ok and files_ok and openvas_ok and nltk_ok
    
    if all_ok:
        print("\n✅ All prerequisites are met! You're ready to run the Enhanced Remediation System.")
        print("   Run: python enhanced_remediation_system_fixed.py")
    else:
        print("\n⚠️ Some prerequisites are missing or incomplete.")
        print("   Please address the issues marked with ⚠️ or ❌ above before running the system.")
    
    return all_ok

if __name__ == "__main__":
    main()