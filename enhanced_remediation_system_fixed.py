import pandas as pd
import numpy as np
import json
import os
import re
import requests
import pickle
import time
from datetime import datetime
from sentence_transformers import SentenceTransformer, util
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from scipy.spatial.distance import cosine
import logging
from process_download_openvas import extract_openvas_data, preprocess_openvas_data, predict_severity

# Setup logging
logging.basicConfig(
    filename='remediation_system.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

WORK_DIR = "C:/Users/cb26h/Desktop/pipeline/pipeline"
DEFAULT_EXPLOIT_DB_PATH = os.path.join(WORK_DIR, "exploitdb", "files_exploits.csv")

class ExploitDBIntegration:
    def __init__(self, exploit_db_path=None, cache_dir=os.path.join(WORK_DIR, "remediation_cache"), config=None):
        self.config = config or {}
        self.exploit_db_path = exploit_db_path or DEFAULT_EXPLOIT_DB_PATH
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self._download_latest_exploitdb()
        self.exploit_db = self._load_exploit_db()
        self.cve_exploit_map = self._build_cve_exploit_map()

    def _download_latest_exploitdb(self):
        """Download only the latest ExploitDB files_exploits.csv from GitLab."""
        try:
            # Check if we already have a recent download
            if os.path.exists(self.exploit_db_path):
                file_age = time.time() - os.path.getmtime(self.exploit_db_path)
                if file_age < 86400:  # Less than 24 hours old
                    print("Using existing ExploitDB dataset (less than 24 hours old)")
                    return

            # Create exploitdb directory if it doesn't exist
            exploitdb_dir = os.path.dirname(self.exploit_db_path)
            os.makedirs(exploitdb_dir, exist_ok=True)

            # Download files_exploits.csv
            files_exploits_url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
            files_exploits_path = os.path.join(exploitdb_dir, "files_exploits.csv")
            
            print("Downloading latest ExploitDB CSV dataset...")
            response = self.session.get(files_exploits_url, stream=True)
            response.raise_for_status()
            
            with open(files_exploits_path, 'wb') as f:
                for data in response.iter_content(1024):
                    f.write(data)
            
            print(f"Successfully downloaded ExploitDB CSV to {files_exploits_path}")
        except Exception as e:
            logging.error(f"Error downloading ExploitDB CSV: {e}")
            print(f"Error downloading ExploitDB CSV: {e}")
            # Fall back to sample data if download fails
            self._create_sample_exploitdb()

    def _load_exploit_db(self):
        """Load the ExploitDB dataset from CSV."""
        try:
            if not os.path.exists(self.exploit_db_path):
                logging.warning(f"ExploitDB CSV not found at {self.exploit_db_path}. Creating sample.")
                self._create_sample_exploitdb()
            
            db = pd.read_csv(self.exploit_db_path, encoding='utf-8')
            logging.info(f"Loaded {len(db)} exploits from ExploitDB")
            return db
        except Exception as e:
            logging.error(f"Error loading ExploitDB: {e}")
            return pd.DataFrame()

    def _create_sample_exploitdb(self):
        """Create a sample ExploitDB CSV file if the download fails."""
        sample_exploits = [
            {'id': '46153', 'file': 'exploits/multiple/remote/46153.py', 'description': 'Apache Log4j 2.0-beta9 to 2.15.0 - JNDI Injection (CVE-2021-44228)', 'date': '2021-12-10', 'type': 'remote', 'platform': 'multiple', 'port': '0'},
            {'id': '45380', 'file': 'exploits/windows/remote/45380.py', 'description': 'BlueKeep - Microsoft Windows Remote Desktop RCE (CVE-2019-0708)', 'date': '2019-05-15', 'type': 'remote', 'platform': 'windows', 'port': '3389'}
        ]
        
        import csv
        with open(self.exploit_db_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['id', 'file', 'description', 'date', 'type', 'platform', 'port']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for exploit in sample_exploits:
                writer.writerow(exploit)
        
        logging.info(f"Created sample ExploitDB at {self.exploit_db_path}")
        
        # Create sample exploit files
        exploits_dir = os.path.join(os.path.dirname(self.exploit_db_path), "exploits")
        os.makedirs(exploits_dir, exist_ok=True)
        
        for exploit in sample_exploits:
            file_path = os.path.join(exploits_dir, exploit['file'])
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as f:
                f.write(f"# {exploit['description']}\n")
                f.write("# Sample exploit file\n")

    def _build_cve_exploit_map(self):
        """Build a mapping from CVE IDs to exploit details."""
        cve_map = {}
        if self.exploit_db.empty:
            return cve_map
            
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        
        # Check for required columns
        required_cols = ['id', 'description', 'codes']
        missing_cols = [col for col in required_cols if col not in self.exploit_db.columns]
        
        if missing_cols:
            logging.warning(f"ExploitDB CSV missing columns: {missing_cols}")
            return cve_map
        
        # Process each exploit
        cve_count = 0
        total_exploits = len(self.exploit_db)
        print(f"\nProcessing {total_exploits} exploits from ExploitDB...")
        
        for idx, row in self.exploit_db.iterrows():
            # Check both description and codes field
            description = str(row.get('description', ''))
            codes = str(row.get('codes', ''))
            
            # Extract CVEs from description
            desc_cve_ids = re.findall(cve_pattern, description, re.IGNORECASE)
            
            # Extract CVEs from codes field
            codes_cve_ids = []
            if codes and ';' in codes:
                for code in codes.split(';'):
                    if re.match(cve_pattern, code.strip(), re.IGNORECASE):
                        codes_cve_ids.append(code.strip())
            
            # Combined CVE list
            all_cve_ids = list(set(desc_cve_ids + codes_cve_ids))
            
            # Skip if no CVEs found
            if not all_cve_ids:
                continue
                
            cve_count += len(all_cve_ids)
            
            # Exploitation details
            exploit_id = row.get('id', '')
            exploit_type = row.get('type', '')
            exploit_date = row.get('date_published', row.get('date', ''))
            exploit_platform = row.get('platform', '')
            exploit_port = row.get('port', '')
            
            # Add to map for each CVE
            for cve_id in all_cve_ids:
                cve_id = cve_id.upper()
                
                if cve_id not in cve_map:
                    cve_map[cve_id] = []
                
                exploit_details = {
                    'exploit_id': exploit_id,
                    'type': exploit_type,
                    'date': exploit_date,
                    'platform': exploit_platform,
                    'port': exploit_port,
                    'description': description
                }
                cve_map[cve_id].append(exploit_details)
            
            # Show progress
            if (idx + 1) % 1000 == 0 or (idx + 1) == total_exploits:
                print(f"Processed {idx + 1}/{total_exploits} exploits...")
        
        # Print summary statistics
        print(f"\nExploitDB Processing Complete:")
        print(f"Total exploits processed: {total_exploits}")
        print(f"Total CVE mappings created: {cve_count}")
        print(f"Unique CVEs with exploits: {len(cve_map)}")
        
        # Save the mappings to a JSON file
        mappings_file = os.path.join(self.cache_dir, "cve_exploit_mappings.json")
        with open(mappings_file, 'w') as f:
            json.dump(cve_map, f, indent=2)
        print(f"\nCVE to exploit mappings saved to: {mappings_file}")
        
        return cve_map

    def lookup_cve_exploit(self, cve_id):
        """Enhanced CVE exploit lookup using local metadata and Vulners API."""
        if not cve_id or not isinstance(cve_id, str):
            return {'cve_id': cve_id, 'has_exploit': False, 'exploit_count': 0, 'exploits': [], 'exploit_maturity': 'none'}
        
        cve_id = cve_id.upper()
        cache_file = os.path.join(self.cache_dir, f"{cve_id}_exploit.json")
        
        # Check cache first
        if os.path.exists(cache_file):
            cache_age = time.time() - os.path.getmtime(cache_file)
            if cache_age < 86400:  # Cache valid for 24 hours
                try:
                    with open(cache_file, 'r') as f:
                        return json.load(f)
                except Exception as e:
                    logging.error(f"Error reading cache for {cve_id}: {e}")
        
        # Initialize result structure
        result = {
            'cve_id': cve_id,
            'has_exploit': False,
            'exploit_count': 0,
            'exploits': [],
            'exploit_maturity': 'none',
            'sources': []
        }
        
        # Check local ExploitDB metadata first
        local_exploits = self._check_local_exploitdb(cve_id)
        if local_exploits:
            result['has_exploit'] = True
            result['exploit_count'] += len(local_exploits)
            result['exploits'].extend(local_exploits)
            result['sources'].append('exploitdb')
        
        # Try Vulners API
        vulners_result = self._query_vulners_api(cve_id)
        if vulners_result and vulners_result.get('has_exploit'):
            result['has_exploit'] = True
            result['exploit_count'] += vulners_result.get('exploit_count', 0)
            result['exploits'].extend(vulners_result.get('exploits', []))
            result['sources'].append('vulners')
        
        # Calculate exploit maturity
        if result['has_exploit']:
            result['exploit_maturity'] = self._calculate_exploit_maturity(result['exploits'])
        
        # Save to cache
        try:
            with open(cache_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logging.error(f"Error writing cache for {cve_id}: {e}")
        
        return result

    def _check_local_exploitdb(self, cve_id):
        """Check local ExploitDB metadata for exploits."""
        exploits = []
        if self.exploit_db.empty:
            return exploits
        
        # First check the CVE map
        if cve_id in self.cve_exploit_map:
            return self.cve_exploit_map[cve_id]
        
        # Fallback to searching in description and codes
        cve_pattern = re.compile(rf'\b{cve_id}\b', re.IGNORECASE)
        
        # Check both description and codes fields
        matching_exploits = self.exploit_db[
            (self.exploit_db['description'].str.contains(cve_pattern, na=False)) |
            (self.exploit_db['codes'].str.contains(cve_pattern, na=False))
        ]
        
        for _, row in matching_exploits.iterrows():
            exploit = {
                'exploit_id': str(row.get('id', 'unknown')),
                'type': row.get('type', 'unknown'),
                'date': row.get('date_published', row.get('date', datetime.now().strftime('%Y-%m-%d'))),
                'source': 'exploit-db.com',
                'description': row.get('description', '')[:200],
                'platform': row.get('platform', 'unknown'),
                'port': row.get('port', '0')
            }
            exploits.append(exploit)
        
        return exploits

    def _query_vulners_api(self, cve_id):
        """Query Vulners API for exploit information."""
        api_key = self.config.get('vulners_api_key') or os.getenv("VULNERS_API_KEY", "")
        if not api_key:
            logging.warning("No Vulners API key provided.")
            return None
        
        headers = {
            "Content-Type": "application/json",
            "X-Api-Key": api_key
        }
        
        try:
            url = f"https://vulners.com/api/v3/search/id/?id={cve_id}"
            
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            
            if data.get("result") != "OK":
                logging.error(f"Vulners API error for {cve_id}: {data.get('data', {}).get('error', 'Unknown error')}")
                return None
            
            result = {
                'has_exploit': False,
                'exploit_count': 0,
                'exploits': [],
                'source': 'vulners'
            }
            
            if 'data' in data and 'documents' in data['data'] and cve_id in data['data']['documents']:
                cve_data = data['data']['documents'][cve_id]
                exploit_sources = ['exploit', 'exploitdb', 'metasploit', 'packetstorm']
                
                for source in exploit_sources:
                    if source in cve_data:
                        for exp in cve_data[source]:
                            result['exploits'].append({
                                'exploit_id': exp.get('id', 'unknown'),
                                'type': exp.get('type', 'unknown'),
                                'date': exp.get('published', datetime.now().strftime('%Y-%m-%d')),
                                'source': 'vulners.com',
                                'title': exp.get('title', ''),
                                'description': exp.get('description', '')[:200]
                            })
            
                result['has_exploit'] = len(result['exploits']) > 0
                result['exploit_count'] = len(result['exploits'])
            
            return result
        except Exception as e:
            logging.error(f"Vulners API failed for {cve_id}: {e}")
            return None

    def _calculate_exploit_maturity(self, exploits):
        """Calculate exploit maturity based on various factors."""
        if not exploits:
            return 'none'
        
        # Count different types of exploits
        metasploit_count = sum(1 for exp in exploits if 'metasploit' in exp.get('source', '').lower())
        exploitdb_count = sum(1 for exp in exploits if 'exploitdb' in exp.get('source', '').lower())
        total_count = len(exploits)
        
        # Determine maturity based on counts and types
        if metasploit_count > 0 or total_count > 3:
            return 'high'
        elif exploitdb_count > 0 or total_count > 1:
            return 'medium'
        else:
            return 'low'

    def test_exploit_api_integration(self, cve_id="CVE-2019-0708"):
        """Test function to debug Vulners API integration."""
        print(f"\n{'='*50}")
        print(f"Testing Vulners API for {cve_id}")
        print(f"{'='*50}")
        
        # Try Vulners API with the working GET format
        vulners_api_key = self.config.get('vulners_api_key') or os.getenv("VULNERS_API_KEY", "")
        if vulners_api_key:
            try:
                headers = {
                    "Content-Type": "application/json",
                    "X-Api-Key": vulners_api_key
                }
                url = f"https://vulners.com/api/v3/search/id/?id={cve_id}"
                
                response = requests.get(url, headers=headers, timeout=15)
                data = response.json()
                
                if data.get('result') == 'OK' and 'data' in data and 'documents' in data['data']:
                    vuln_data = data['data']['documents'].get(cve_id, {})
                    if vuln_data:
                        # Extract CVSS information
                        cvss_info = vuln_data.get('cvss', {})
                        cvss_score = cvss_info.get('score')
                        cvss_severity = cvss_info.get('severity')
                        cvss_vector = cvss_info.get('vector')
                        
                        # Extract CWE information
                        cwe_info = []
                        cwe_list = vuln_data.get('cwe', [])
                        for cwe in cwe_list:
                            cwe_info.append({
                                'id': cwe.replace('CWE-', ''),
                                'title': self._get_cwe_title(cwe)
                            })
                        
                        # Extract affected products
                        affected_products = vuln_data.get('affected_products', [])
                        
                        # Extract references and categorize them
                        references = vuln_data.get('references', [])
                        vendor_advisories = []
                        patches = []
                        for ref in references:
                            if isinstance(ref, dict):
                                url = ref.get('url', '')
                                tags = ref.get('tags', [])
                                if 'Vendor Advisory' in tags:
                                    vendor_advisories.append({'url': url, 'title': ref.get('title', '')})
                                elif 'Patch' in tags:
                                    patches.append({'url': url, 'title': ref.get('title', '')})
                            else:
                                # Handle string references
                                if 'advisory' in ref.lower():
                                    vendor_advisories.append({'url': ref, 'title': 'Vendor Advisory'})
                                elif 'patch' in ref.lower():
                                    patches.append({'url': ref, 'title': 'Patch'})
                        
                        # Get model's predicted score
                        model_score = self._predict_severity_score(vuln_data.get('description', ''))
                        
                        # Print summary information
                        print("\nVulnerability Details:")
                        print(f"Description: {vuln_data.get('description', 'N/A')}")
                        print(f"Published: {vuln_data.get('published', 'N/A')}")
                        print(f"Last Seen: {vuln_data.get('lastseen', 'N/A')}")
                        
                        print("\nCVSS Information:")
                        print(f"Score: {cvss_score}")
                        print(f"Severity: {cvss_severity}")
                        print(f"Vector: {cvss_vector}")
                        
                        if cwe_info:
                            print("\nCWE Information:")
                            for cwe in cwe_info:
                                print(f"CWE-{cwe['id']}: {cwe['title']}")
                        
                        if affected_products:
                            print("\nAffected Products:")
                            for product in affected_products[:5]:
                                if isinstance(product, dict):
                                    print(f"- {product.get('name', 'N/A')} {product.get('version', 'N/A')}")
                                else:
                                    print(f"- {product}")
                            if len(affected_products) > 5:
                                print(f"... and {len(affected_products) - 5} more products")
                        
                        print("\nRemediation Resources:")
                        if vendor_advisories:
                            print("\nVendor Advisories:")
                            for advisory in vendor_advisories[:3]:
                                print(f"- {advisory['title']}: {advisory['url']}")
                            if len(vendor_advisories) > 3:
                                print(f"... and {len(vendor_advisories) - 3} more advisories")
                        
                        if patches:
                            print("\nAvailable Patches:")
                            for patch in patches[:3]:
                                print(f"- {patch['title']}: {patch['url']}")
                            if len(patches) > 3:
                                print(f"... and {len(patches) - 3} more patches")
                        
                        return {
                            'cve_id': cve_id,
                            'original_cvss_score': cvss_score,
                            'original_severity': cvss_severity,
                            'cvss_vector': cvss_vector,
                            'model_predicted_score': model_score,
                            'cwe_info': cwe_info,
                            'affected_products': affected_products,
                            'vendor_advisories': vendor_advisories,
                            'patches': patches,
                            'description': vuln_data.get('description', ''),
                            'published_date': vuln_data.get('published', ''),
                            'last_seen_date': vuln_data.get('lastseen', '')
                        }
                    else:
                        print(f"No data found for {cve_id}")
                else:
                    print(f"API Error: {data.get('data', {}).get('error', 'Unknown error')}")
            except Exception as e:
                print(f"Vulners API error: {str(e)}")
        print(f"\n{'-'*50}\n")
        return None

    def _get_cwe_title(self, cwe_id):
        """Get CWE title from a predefined mapping."""
        cwe_titles = {
            "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
            "CWE-20": "Improper Input Validation",
            "CWE-200": "Information Exposure",
            "CWE-22": "Path Traversal",
            "CWE-287": "Improper Authentication",
            "CWE-352": "Cross-Site Request Forgery (CSRF)",
            "CWE-434": "Unrestricted Upload of File with Dangerous Type",
            "CWE-306": "Missing Authentication for Critical Function",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-400": "Uncontrolled Resource Consumption",
            "CWE-798": "Use of Hard-coded Credentials",
            "CWE-295": "Improper Certificate Validation",
            "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            "CWE-264": "Permissions, Privileges, and Access Controls",
            "CWE-787": "Out-of-bounds Write"
        }
        return cwe_titles.get(cwe_id, "Unknown CWE")

    def _predict_severity_score(self, description):
        """Predict severity score based on vulnerability description."""
        if not description:
            return None
        # Use a simple heuristic based on keywords in the description
        critical_keywords = ['remote code execution', 'arbitrary code execution', 'root access', 'privilege escalation']
        high_keywords = ['memory corruption', 'buffer overflow', 'denial of service', 'information disclosure']
        medium_keywords = ['cross-site scripting', 'sql injection', 'information exposure']
        
        description_lower = description.lower()
        if any(keyword in description_lower for keyword in critical_keywords):
            return 9.0
        elif any(keyword in description_lower for keyword in high_keywords):
            return 7.5
        elif any(keyword in description_lower for keyword in medium_keywords):
            return 5.0
        return 3.0  # Default to low severity if no keywords match

class CVEDatabaseIntegration:
    def __init__(self, cache_dir=os.path.join(WORK_DIR, "cve_cache"), config=None):
        self.config = config or {}
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)
        self.nvd_api_key = self.config.get('nvd_api_key') or os.getenv("NVD_API_KEY", "")
        self.vul_api_key = self.config.get('vulners_api_key') or os.getenv("VULNERS_API_KEY", "")
        self.cache_validity = 7 * 24 * 60 * 60

    def get_cve_details(self, cve_id):
        if not cve_id or not isinstance(cve_id, str):
            return None
        cve_id = cve_id.upper()
        cache_file = os.path.join(self.cache_dir, f"{cve_id}_details.json")
        if os.path.exists(cache_file) and (time.time() - os.path.getmtime(cache_file)) < self.cache_validity:
            with open(cache_file, 'r') as f:
                return json.load(f)
        result = {
            "cve_id": cve_id, "summary": "", "description": "", "cvss_v3_score": None,
            "cvss_v2_score": None, "cwe_id": "", "references": [], "patches": [],
            "vendor_advisories": [], "affected_products": [], "remediation": "", "sources": []
        }
        nvd_data = self._query_nvd(cve_id)
        if nvd_data:
            self._update_result_with_nvd(result, nvd_data)
            result["sources"].append("nvd")
        circl_data = self._query_circl(cve_id)
        if circl_data:
            self._update_result_with_circl(result, circl_data)
            result["sources"].append("circl")
        if self.vul_api_key:
            vulners_data = self._query_vulners(cve_id)
            if vulners_data:
                self._update_result_with_vulners(result, vulners_data)
                result["sources"].append("vulners")
        if result["sources"]:
            with open(cache_file, 'w') as f:
                json.dump(result, f, indent=2)
            return result
        return None

    def _query_nvd(self, cve_id):
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        api_key = self.config.get('nvd_api_key') or os.getenv("NVD_API_KEY", "")
        headers = {"apiKey": api_key} if api_key else {}
        try:
            response = requests.get(base_url, params={"cveId": cve_id, "resultsPerPage": 10, "startIndex": 0}, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data['vulnerabilities'][0] if 'vulnerabilities' in data and data['vulnerabilities'] else None
        except Exception as e:
            logging.error(f"NVD API failed for {cve_id}: {e}")
            return None

    def _query_circl(self, cve_id):
        base_url = f"https://cve.circl.lu/api/cve/{cve_id}"
        try:
            response = requests.get(base_url, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data if data and 'id' in data else None
        except Exception as e:
            logging.error(f"CIRCL API failed for {cve_id}: {e}")
            return None

    def _query_vulners(self, cve_id):
        url = "https://vulners.com/api/v3/search/id/"
        headers = {"X-Vulners-API-Key": self.vul_api_key, "Content-Type": "application/json"}
        try:
            response = requests.get(url, params={"id": cve_id}, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            return data['data'][cve_id] if data.get("status") == "success" and 'data' in data and cve_id in data['data'] else None
        except Exception as e:
            logging.error(f"Vulners API failed for {cve_id}: {e}")
            return None

    def _update_result_with_nvd(self, result, nvd_data):
        cve_data = nvd_data.get('cve', {})
        if 'descriptions' in cve_data:
            for desc in cve_data['descriptions']:
                if desc.get('lang') == 'en':
                    result['description'] = desc.get('value', '')
                    break
        if 'metrics' in cve_data:
            metrics = cve_data['metrics']
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                result['cvss_v3_score'] = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore')
            if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                result['cvss_v2_score'] = metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore')
        if 'weaknesses' in cve_data and cve_data['weaknesses']:
            for weakness in cve_data['weaknesses']:
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en' and desc.get('value', '').startswith('CWE-'):
                        result['cwe_id'] = desc.get('value')
                        break
        if 'references' in cve_data:
            for ref in cve_data['references']:
                url = ref.get('url', '')
                tags = ref.get('tags', [])
                if url:
                    result['references'].append(url)
                    if 'Patch' in tags:
                        result['patches'].append(url)
                    if 'Vendor Advisory' in tags:
                        result['vendor_advisories'].append(url)
        if 'configurations' in cve_data:
            for config in cve_data['configurations']:
                for node in config.get('nodes', []):
                    for cpe in node.get('cpeMatch', []):
                        cpe_str = cpe.get('criteria', '')
                        parts = cpe_str.split(':')
                        if len(parts) > 4:
                            product_info = {
                                "vendor": parts[3],
                                "product": parts[4],
                                "version": parts[5] if len(parts) > 5 else "*"
                            }
                            if product_info not in result['affected_products']:
                                result['affected_products'].append(product_info)
        self._generate_remediation_from_nvd(result, cve_data)

    def _update_result_with_circl(self, result, circl_data):
        if not result['description'] and 'summary' in circl_data:
            result['description'] = circl_data['summary']
        if 'summary' in circl_data:
            result['summary'] = circl_data['summary']
        if result['cvss_v3_score'] is None and 'cvss3' in circl_data:
            result['cvss_v3_score'] = circl_data['cvss3']
        if result['cvss_v2_score'] is None and 'cvss' in circl_data:
            result['cvss_v2_score'] = circl_data['cvss']
        if not result['cwe_id'] and 'cwe' in circl_data and circl_data['cwe']:
            cwe = circl_data['cwe']
            result['cwe_id'] = f"CWE-{cwe}" if not cwe.startswith('CWE-') else cwe
        if 'references' in circl_data:
            for ref in circl_data['references']:
                if ref not in result['references']:
                    result['references'].append(ref)
        if 'vulnerable_product' in circl_data:
            for cpe in circl_data['vulnerable_product']:
                parts = cpe.split(':')
                if len(parts) > 4:
                    product_info = {
                        "vendor": parts[3],
                        "product": parts[4],
                        "version": parts[5] if len(parts) > 5 else "*"
                    }
                    if product_info not in result['affected_products']:
                        result['affected_products'].append(product_info)

    def _update_result_with_vulners(self, result, vulners_data):
        if not result['description'] and 'description' in vulners_data:
            result['description'] = vulners_data['description']
        exploit_sources = ['exploit', 'exploitdb', 'metasploit', 'packetstorm']
        for source in exploit_sources:
            if source in vulners_data and vulners_data[source]:
                if 'exploit_details' not in result:
                    result['exploit_details'] = []
                for exploit in vulners_data[source]:
                    result['exploit_details'].append({
                        'id': exploit.get('id', 'unknown'),
                        'title': exploit.get('title', ''),
                        'source': source,
                        'link': exploit.get('href', '')
                    })
        if 'bulletins' in vulners_data:
            for bulletin in vulners_data['bulletins']:
                if 'href' in bulletin and bulletin['href'] not in result['vendor_advisories']:
                    result['vendor_advisories'].append(bulletin['href'])

    def _generate_remediation_from_nvd(self, result, cve_data):
        remediation = []
        if result['affected_products']:
            vendors = set(product['vendor'] for product in result['affected_products'])
            products = set(product['product'] for product in result['affected_products'])
            remediation.append(f"Update affected {'products' if len(products) > 1 else 'product'} from {', '.join(vendors)} to the latest version.")
        if result['patches']:
            remediation.append("\nApply available patches:")
            for patch in result['patches'][:3]:
                remediation.append(f"- {patch}")
            if len(result['patches']) > 3:
                remediation.append(f"- Plus {len(result['patches']) - 3} more patches")
        if result['vendor_advisories']:
            remediation.append("\nRefer to vendor advisories for detailed remediation steps:")
            for advisory in result['vendor_advisories'][:3]:
                remediation.append(f"- {advisory}")
            if len(result['vendor_advisories']) > 3:
                remediation.append(f"- Plus {len(result['vendor_advisories']) - 3} more advisories")
        if result['cwe_id']:
            cwe_remediation = self._get_cwe_remediation(result['cwe_id'])
            if cwe_remediation:
                remediation.append(f"\nAdditional security recommendations for {result['cwe_id']}:")
                remediation.append(cwe_remediation)
        result['remediation'] = "\n".join(remediation) if remediation else "Update software to the latest version and apply security patches."

    def _get_cwe_remediation(self, cwe_id):
        cwe_remediation = {
            "CWE-79": "Implement proper output encoding and content security policies to prevent XSS attacks.",
            "CWE-89": "Use parameterized queries or prepared statements to prevent SQL injection.",
            "CWE-119": "Use memory-safe languages or implement bounds checking to prevent buffer overflows.",
            "CWE-20": "Implement proper input validation by using allowlists rather than denylists.",
            "CWE-200": "Review application to ensure sensitive information is not leaked in error messages or logs.",
            "CWE-22": "Validate and sanitize file paths. Use a library that canonicalizes paths.",
            "CWE-287": "Implement proper authentication mechanisms and session management.",
            "CWE-352": "Implement anti-CSRF tokens and same-site cookie attributes.",
            "CWE-434": "Validate file uploads thoroughly, including type, size, and content.",
            "CWE-306": "Ensure proper authorization checks are in place for all sensitive operations.",
            "CWE-502": "Avoid deserialization of untrusted data, or implement integrity checks.",
            "CWE-400": "Implement rate limiting and resource constraints to prevent DoS.",
            "CWE-798": "Remove hardcoded credentials and use secure credential management.",
            "CWE-295": "Properly validate SSL/TLS certificates and implement certificate pinning.",
            "CWE-78": "Avoid using shell commands. If necessary, use proper validation and sanitization."
        }
        return cwe_remediation.get(cwe_id, cwe_remediation.get(cwe_id.replace("CWE-", "CWE-")))

class RemediationQualityFeedbackLoop:
    def __init__(self, data_dir=os.path.join(WORK_DIR, "remediation_feedback")):
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self.feedback_file = os.path.join(self.data_dir, "remediation_feedback.csv")
        self.model_file = os.path.join(self.data_dir, "remediation_quality_model.pkl")
        self.vectorizer_file = os.path.join(self.data_dir, "tfidf_vectorizer.pkl")
        self.stats_file = os.path.join(self.data_dir, "feedback_stats.json")
        self.feedback_data = self._load_feedback_data()
        self.model, self.vectorizer = self._load_or_train_model()
        self.stats = self._load_stats()

    def _load_feedback_data(self):
        if os.path.exists(self.feedback_file):
            try:
                return pd.read_csv(self.feedback_file)
            except Exception as e:
                logging.error(f"Error loading feedback data: {e}")
        return pd.DataFrame(columns=[
            'cve_id', 'vulnerability_description', 'remediation_text', 'recommendation_method',
            'feedback_rating', 'feedback_comments', 'feedback_timestamp', 'implemented', 'effectiveness'
        ])

    def _load_or_train_model(self):
        if os.path.exists(self.model_file) and os.path.exists(self.vectorizer_file):
            try:
                with open(self.model_file, 'rb') as f:
                    model = pickle.load(f)
                with open(self.vectorizer_file, 'rb') as f:
                    vectorizer = pickle.load(f)
                return model, vectorizer
            except Exception as e:
                logging.error(f"Error loading model: {e}")
        vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        if len(self.feedback_data) >= 20:
            self._train_model(model, vectorizer)
        return model, vectorizer

    def _load_stats(self):
        if os.path.exists(self.stats_file):
            try:
                with open(self.stats_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logging.error(f"Error loading stats: {e}")
        return {
            "total_feedback": 0, "positive_feedback": 0, "negative_feedback": 0,
            "method_stats": {}, "last_training": None, "model_performance": {
                "precision": 0, "recall": 0, "f1": 0
            }
        }

    def add_feedback(self, cve_id, vulnerability_description, remediation_text, recommendation_method,
                     feedback_rating, feedback_comments=None, implemented=False, effectiveness=None):
        new_feedback = {
            'cve_id': cve_id, 'vulnerability_description': vulnerability_description,
            'remediation_text': remediation_text, 'recommendation_method': recommendation_method,
            'feedback_rating': feedback_rating, 'feedback_comments': feedback_comments,
            'feedback_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'implemented': implemented, 'effectiveness': effectiveness
        }
        self.feedback_data = pd.concat([self.feedback_data, pd.DataFrame([new_feedback])], ignore_index=True)
        self.feedback_data.to_csv(self.feedback_file, index=False)
        self._update_stats(new_feedback)
        if self.stats["total_feedback"] % 10 == 0 and self.stats["total_feedback"] >= 20:
            self._train_model(self.model, self.vectorizer)
        return True

    def _update_stats(self, new_feedback):
        self.stats["total_feedback"] += 1
        rating = new_feedback["feedback_rating"]
        method = new_feedback["recommendation_method"]
        if rating >= 4:
            self.stats["positive_feedback"] += 1
        elif rating <= 2:
            self.stats["negative_feedback"] += 1
        if method not in self.stats["method_stats"]:
            self.stats["method_stats"][method] = {"count": 0, "ratings": [0, 0, 0, 0, 0], "average": 0}
        method_stats = self.stats["method_stats"][method]
        method_stats["count"] += 1
        method_stats["ratings"][int(rating) - 1] += 1
        total_ratings = sum(i * count for i, count in enumerate(method_stats["ratings"], 1))
        method_stats["average"] = total_ratings / method_stats["count"]
        with open(self.stats_file, 'w') as f:
            json.dump(self.stats, f, indent=2)

    def _train_model(self, model, vectorizer):
        if len(self.feedback_data) < 20:
            logging.warning("Not enough feedback data to train model")
            return False
        X_text = self.feedback_data['vulnerability_description'] + ' ' + self.feedback_data['remediation_text']
        y = (self.feedback_data['feedback_rating'] >= 4).astype(int)
        X_train, X_test, y_train, y_test = train_test_split(X_text, y, test_size=0.2, random_state=42)
        X_train_vec = vectorizer.fit_transform(X_train)
        model.fit(X_train_vec, y_train)
        X_test_vec = vectorizer.transform(X_test)
        y_pred = model.predict(X_test_vec)
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary')
        self.stats["last_training"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.stats["model_performance"] = {
            "precision": float(precision), "recall": float(recall), "f1": float(f1),
            "training_samples": len(X_train)
        }
        with open(self.stats_file, 'w') as f:
            json.dump(self.stats, f, indent=2)
        with open(self.model_file, 'wb') as f:
            pickle.dump(model, f)
        with open(self.vectorizer_file, 'wb') as f:
            pickle.dump(vectorizer, f)
        self.model = model
        self.vectorizer = vectorizer
        logging.info(f"Model trained successfully. F1 score: {f1:.4f}")
        return True

    def predict_remediation_quality(self, vulnerability_description, remediation_text):
        if self.model is None or self.vectorizer is None:
            return {"quality_score": 0.5, "confidence": 0.0, "status": "no_model"}
        try:
            combined_text = f"{vulnerability_description} {remediation_text}"
            X = self.vectorizer.transform([combined_text])
            prediction = self.model.predict(X)[0]
            probability = self.model.predict_proba(X)[0]
            confidence = probability[1] if prediction == 1 else probability[0]
            return {
                "quality_score": float(probability[1]),
                "prediction": "good" if prediction == 1 else "poor",
                "confidence": float(confidence),
                "status": "success"
            }
        except Exception as e:
            logging.error(f"Error predicting remediation quality: {e}")
            return {"quality_score": 0.5, "confidence": 0.0, "status": "error", "message": str(e)}

    def get_method_effectiveness(self):
        return {
            "method_stats": self.stats["method_stats"],
            "overall_positive_rate": self.stats["positive_feedback"] / self.stats["total_feedback"]
                if self.stats["total_feedback"] > 0 else 0
        }

    def get_most_effective_method(self, vulnerability_description):
        method_stats = self.stats["method_stats"]
        if not method_stats or len(self.feedback_data) < 50:
            return sorted(method_stats.items(), key=lambda x: (x[1]["average"], x[1]["count"]), reverse=True)[0][0] if method_stats else "hybrid-similarity"
        return sorted(method_stats.items(), key=lambda x: (x[1]["average"], x[1]["count"]), reverse=True)[0][0]

class EnhancedRemediationSystem:
    def __init__(self, config=None):
        self.config = config or {
            'work_dir': WORK_DIR,
            'cache_dir': os.path.join(WORK_DIR, "remediation_cache"),
            'embedding_model': 'all-mpnet-base-v2',
            'similarity_threshold': 0.70,
            'exploit_db_path': DEFAULT_EXPLOIT_DB_PATH,
            'vulners_api_key': os.getenv('VULNERS_API_KEY', ''),
            'nvd_api_key': os.getenv('NVD_API_KEY', '')
        }
        self.cache_dir = self.config.get('cache_dir')
        os.makedirs(self.cache_dir, exist_ok=True)
        self.similarity_threshold = self.config.get('similarity_threshold')
        self.embedding_cache_file = os.path.join(self.cache_dir, "embeddings_cache.pkl")
        self.embedding_cache = self._load_embedding_cache()
        self.exploit_db = ExploitDBIntegration(self.config.get('exploit_db_path'), self.cache_dir, self.config)
        self.cve_db = CVEDatabaseIntegration(self.cache_dir, self.config)
        self.feedback_loop = RemediationQualityFeedbackLoop(os.path.join(WORK_DIR, "remediation_feedback"))
        self._initialize_enhanced_embedding_model()
        self.remediation_db = self._load_remediation_db()
        self.rule_based_fixes = self._initialize_rule_based_fixes()
        self.cve_exploit_map = self.exploit_db.cve_exploit_map  # Initialize cve_exploit_map

    def _initialize_enhanced_embedding_model(self):
        try:
            model_name = self.config.get('embedding_model', 'all-mpnet-base-v2')
            logging.info(f"Initializing enhanced embedding model: {model_name}")
            self.model = SentenceTransformer(model_name)
            return True
        except Exception as e:
            logging.error(f"Error initializing enhanced model: {e}. Falling back to standard model.")
            self.model = SentenceTransformer('all-MiniLM-L6-v2')
            return False

    def _load_embedding_cache(self):
        if os.path.exists(self.embedding_cache_file):
            with open(self.embedding_cache_file, 'rb') as f:
                return pickle.load(f)
        return {}

    def _save_embedding_cache(self):
        with open(self.embedding_cache_file, 'wb') as f:
            pickle.dump(self.embedding_cache, f)

    def get_cached_embedding(self, text):
        text_key = hash(text)
        if text_key in self.embedding_cache:
            return self.embedding_cache[text_key]
        embedding = self.model.encode(text, show_progress_bar=False)
        self.embedding_cache[text_key] = embedding
        if len(self.embedding_cache) % 50 == 0:
            self._save_embedding_cache()
        return embedding

    def _load_remediation_db(self):
        default_db = {
            "templates": [
                {"type": "sql_injection", "description": "SQL injection vulnerability", "remediation": "Use prepared statements and parameterized queries to prevent SQL injection."},
                {"type": "smb_vulnerability", "description": "SMB protocol vulnerability", "remediation": "Disable SMBv1, enable SMB signing, and apply latest patches."},
                {"type": "rdp_vulnerability", "description": "RDP vulnerability", "remediation": "Enable Network Level Authentication (NLA) and apply latest patches."},
                {"type": "log4j", "description": "Apache Log4j vulnerability", "remediation": "Update Log4j to version 2.17.0 or later."},
                {"type": "xss", "description": "Cross-site scripting vulnerability", "remediation": "Implement proper output encoding and Content Security Policy (CSP)."}
            ]
        }
        descriptions = [template["description"] for template in default_db["templates"]]
        embeddings = self.model.encode(descriptions, show_progress_bar=True)
        for i, template in enumerate(default_db["templates"]):
            template["embedding"] = embeddings[i].tolist()
        return default_db

    def _initialize_rule_based_fixes(self):
        return {
            r'log4j|log4shell': "Update Log4j to 2.17.0 or later, or set log4j2.formatMsgNoLookups to true.",
            r'smb.+(vulnerability|exploit)': "Disable SMBv1, enable SMB signing, and apply latest patches.",
            r'rdp.+(vulnerability|exploit)': "Enable Network Level Authentication (NLA) and apply latest patches.",
            r'bluekeep|cve-2019-0708': "Apply Microsoft patches for CVE-2019-0708 and restrict RDP access.",
            r'eternalblue|cve-2017-0144': "Apply Microsoft patches for CVE-2017-0144 and disable SMBv1."
        }

    def get_remediation_by_similarity(self, description):
        if not description:
            return None
        query_embedding = self.get_cached_embedding(description)
        max_similarity = 0
        best_template = None
        for template in self.remediation_db["templates"]:
            template_embedding = np.array(template["embedding"], dtype=np.float32)
            query_embedding = np.array(query_embedding, dtype=np.float32)
            similarity = util.cos_sim(query_embedding, template_embedding).item()
            if similarity > max_similarity:
                max_similarity = similarity
                best_template = template
        if max_similarity > self.similarity_threshold and best_template:
            return {
                "remediation": best_template["remediation"],
                "similarity": max_similarity,
                "method": "similarity"
            }
        return None

    def get_remediation_by_hybrid_similarity(self, vulnerability_description):
        if not vulnerability_description:
            return None
        query_embedding = self.get_cached_embedding(vulnerability_description)
        if not hasattr(self, 'tfidf_vectorizer'):
            descriptions = [template["description"] for template in self.remediation_db["templates"]]
            self.tfidf_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english', ngram_range=(1, 2))
            self.tfidf_matrix = self.tfidf_vectorizer.fit_transform(descriptions)
        query_tfidf = self.tfidf_vectorizer.transform([vulnerability_description])
        best_template = None
        max_combined_score = 0
        best_semantic = best_keyword = 0
        for i, template in enumerate(self.remediation_db["templates"]):
            template_embedding = np.array(template["embedding"], dtype=np.float32)
            query_embedding = np.array(query_embedding, dtype=np.float32)
            semantic_sim = util.cos_sim(query_embedding, template_embedding).item()
            keyword_sim = 1 - cosine(query_tfidf.toarray()[0], self.tfidf_matrix[i].toarray()[0])
            combined_score = (semantic_sim * 0.7) + (keyword_sim * 0.3)
            if combined_score > max_combined_score:
                max_combined_score = combined_score
                best_template = template
                best_semantic = semantic_sim
                best_keyword = keyword_sim
        if max_combined_score > self.similarity_threshold and best_template:
            return {
                "remediation": best_template["remediation"],
                "similarity": max_combined_score,
                "semantic_similarity": best_semantic,
                "keyword_similarity": best_keyword,
                "template_type": best_template["type"],
                "method": "hybrid-similarity"
            }
        return None

    def get_remediation_by_rules(self, description):
        if not description:
            return None
        desc_lower = description.lower()
        for pattern, recommendation in self.rule_based_fixes.items():
            if re.search(pattern, desc_lower, re.IGNORECASE):
                return {"remediation": recommendation, "method": "rule-based"}
        return None

    def _get_remediation_by_cve(self, cve_id):
        if not cve_id or not isinstance(cve_id, str):
            return None
        cve_id = cve_id.upper()
        cache_file = os.path.join(self.cache_dir, f"{cve_id}_remediation.json")
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                try:
                    return json.load(f)
                except:
                    pass
        for pattern, recommendation in self.rule_based_fixes.items():
            if cve_id.lower() in pattern.lower():
                result = {"remediation": recommendation, "pattern": pattern, "method": "cve-direct-match"}
                with open(cache_file, 'w') as f:
                    json.dump(result, f)
                return result
        nvd_result = self._query_nvd_for_remediation(cve_id)
        if nvd_result:
            with open(cache_file, 'w') as f:
                json.dump(nvd_result, f)
            return nvd_result
        return None

    def _query_nvd_for_remediation(self, cve_id):
        api_key = os.getenv("NVD_API_KEY", "")
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"apiKey": api_key} if api_key else {}
        try:
            response = requests.get(base_url, params={"cveId": cve_id, "resultsPerPage": 10, "startIndex": 0}, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            if 'vulnerabilities' in data and data['vulnerabilities']:
                vuln = data['vulnerabilities'][0]['cve']
                remediation_text = ""
                if 'references' in vuln:
                    vendor_advisories = []
                    patch_links = []
                    for ref in vuln['references']:
                        tags = ref.get('tags', [])
                        url = ref.get('url', '')
                        if 'Vendor Advisory' in tags or 'Patch' in tags:
                            vendor_advisories.append(f"- {url}")
                        elif 'Patch' in tags:
                            patch_links.append(f"- {url}")
                    if vendor_advisories:
                        remediation_text += "Vendor advisories:\n" + "\n".join(vendor_advisories) + "\n\n"
                    if patch_links:
                        remediation_text += "Patch information:\n" + "\n".join(patch_links) + "\n\n"
                if remediation_text:
                    result = {
                        "remediation": f"For {cve_id}, apply the patches and mitigations mentioned in the following resources:\n\n{remediation_text}Always update the affected software to the latest version.",
                        "method": "nvd-api",
                        "source": "nvd"
                    }
                    return result
        except Exception as e:
            logging.error(f"NVD API failed for {cve_id}: {e}")
        return None

    def get_nvd_severity(self, cve_id):
        """Fetch severity from NVD API as a fallback or cross-check."""
        if not cve_id or not isinstance(cve_id, str):
            return None
        cve_id = cve_id.upper()
        cache_file = os.path.join(self.cache_dir, f"{cve_id}_nvd_severity.json")
        if os.path.exists(cache_file) and (time.time() - os.path.getmtime(cache_file)) < self.cve_db.cache_validity:
            with open(cache_file, 'r') as f:
                return json.load(f)
        api_key = self.config.get('nvd_api_key') or os.getenv("NVD_API_KEY", "")
        headers = {"apiKey": api_key} if api_key else {}
        try:
            response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", 
                                  params={"cveId": cve_id, "resultsPerPage": 10, "startIndex": 0}, 
                                  headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            if 'vulnerabilities' in data and data['vulnerabilities']:
                vuln = data['vulnerabilities'][0]['cve']
                if 'metrics' in vuln and 'cvssMetricV31' in vuln['metrics'] and vuln['metrics']['cvssMetricV31']:
                    severity = vuln['metrics']['cvssMetricV31'][0].get('cvssData', {}).get('baseScore')
                    result = {"cve_id": cve_id, "nvd_severity": float(severity) if severity else None}
                    with open(cache_file, 'w') as f:
                        json.dump(result, f, indent=2)
                    return result
        except Exception as e:
            logging.error(f"NVD severity check failed for {cve_id}: {e}")
        return {"cve_id": cve_id, "nvd_severity": None}

    def get_ensemble_recommendation(self, vulnerability_description, cve_id=None):
        results = []
        if cve_id:
            cve_match = self._get_remediation_by_cve(cve_id)
            if cve_match:
                cve_match["confidence"] = 1.0
                results.append(cve_match)
        hybrid_match = self.get_remediation_by_hybrid_similarity(vulnerability_description)
        if hybrid_match:
            hybrid_match["confidence"] = hybrid_match["similarity"]
            results.append(hybrid_match)
        similarity_match = self.get_remediation_by_similarity(vulnerability_description)
        if similarity_match:
            similarity_match["confidence"] = similarity_match["similarity"] * 0.9
            results.append(similarity_match)
        rule_match = self.get_remediation_by_rules(vulnerability_description)
        if rule_match:
            rule_match["confidence"] = 0.8
            results.append(rule_match)
        if not results:
            return {
                "remediation": "Update the affected software to the latest version. Follow vendor-specific security advisories for this vulnerability.",
                "method": "generic",
                "confidence": 0.5
            }
        return max(results, key=lambda x: x["confidence"])

    def _load_threat_intelligence(self):
        """Load the threat intelligence modules (MitreAttackIntegration and ShodanIntegration)."""
        from threat_intelligence import MitreAttackIntegration, ShodanIntegration
        self.mitre_integration = MitreAttackIntegration(cache_dir=os.path.join(self.config.get('work_dir'), "mitre_cache"))
        self.shodan_integration = ShodanIntegration(
            api_key=self.config.get('shodan_api_key') or os.environ.get('SHODAN_API_KEY'),
            cache_dir=os.path.join(self.config.get('work_dir'), "shodan_cache")
        )

    def generate_remediation(self, vulnerability_data):
        description = vulnerability_data.get('description', '')
        cve_id = vulnerability_data.get('cve_id', '')
        cvss_v3_score = vulnerability_data.get('cvss_v3_score', 0)
        threat = vulnerability_data.get('threat', 'Unknown')
        result = self.get_ensemble_recommendation(description, cve_id)
        
        # Load threat intelligence if not already loaded
        if not hasattr(self, 'mitre_integration') or not hasattr(self, 'shodan_integration'):
            self._load_threat_intelligence()
        
        # Integrate MITRE ATT&CK analysis
        if cve_id:
            mitre_analysis = self.mitre_integration.analyze_vulnerability({'cve_id': cve_id, 'description': description})
            if mitre_analysis.get('techniques') or mitre_analysis.get('threat_actors') or mitre_analysis.get('mitigations'):
                result["mitre_analysis"] = mitre_analysis
                mitre_html = self.mitre_integration.generate_threat_intelligence_report({'cve_id': cve_id, 'description': description})
                result["remediation"] += f"\n\nMITRE ATT&CK Analysis:\n{mitre_html}"
        
        # Integrate Shodan exposure data
        if cve_id:
            shodan_report = self.shodan_integration.generate_exposure_report(cve_id)
            result["shodan_report"] = shodan_report
            result["remediation"] += f"\n\nShodan Exposure Report:\n{shodan_report}"
            adjusted_severity, adjustment_reason = self.shodan_integration.calculate_exposure_severity_adjustment(cve_id, threat)
            if adjusted_severity != threat:
                result["remediation"] += f"\n\n⚠️ Severity Adjustment: Based on Shodan data, severity adjusted from {threat} to {adjusted_severity} ({adjustment_reason})."
                threat = adjusted_severity
        
        exploit_info = self.exploit_db.lookup_cve_exploit(cve_id) if cve_id else {}
        result["exploit_info"] = exploit_info
        if exploit_info.get('has_exploit'):
            result["remediation"] += f"\n\n⚠️ Exploit Alert: {exploit_info.get('exploit_count', 0)} known exploit(s) available. Maturity: {exploit_info.get('exploit_maturity', 'none').upper()}."
        
        cve_details = self.cve_db.get_cve_details(cve_id) if cve_id else None
        if cve_details and cve_details['remediation']:
            result["remediation"] += f"\n\nAdditional CVE Details:\n{cve_details['remediation']}"
        
        quality_pred = self.feedback_loop.predict_remediation_quality(description, result["remediation"])
        result["quality_prediction"] = quality_pred
        priority = "High" if cvss_v3_score >= 7 or threat in ['Critical', 'High'] or result.get('exploit_info', {}).get('has_exploit', False) else "Medium" if cvss_v3_score >= 4 else "Low"
        urgency = "Critical" if cvss_v3_score >= 9 or result.get('exploit_info', {}).get('exploit_maturity', 'none') == 'high' else "Important" if cvss_v3_score >= 7 else "Moderate"
        result.update({"priority": priority, "urgency": urgency})
        
        if cve_id:
            nvd_severity_data = self.get_nvd_severity(cve_id)
            nvd_severity = nvd_severity_data.get('nvd_severity')
            if nvd_severity is not None:
                result["nvd_severity_check"] = {
                    "score": nvd_severity,
                    "match": "Yes" if abs(float(cvss_v3_score) - nvd_severity) < 1.0 else "No",
                    "difference": abs(float(cvss_v3_score) - nvd_severity) if nvd_severity else None
                }
                if not cvss_v3_score or abs(float(cvss_v3_score) - nvd_severity) > 2.0:
                    result["remediation"] += f"\n\n⚠️ Severity Mismatch: Model predicted {cvss_v3_score}, NVD reports {nvd_severity}. Consider NVD severity for accuracy."
        
        return result

    def test_exploit_api_integration(self, cve_id="CVE-2019-0708"):
        """Test function to debug Vulners API integration."""
        print(f"\n{'='*50}")
        print(f"Testing Vulners API for {cve_id}")
        print(f"{'='*50}")
        
        # Try Vulners API with the working GET format
        vulners_api_key = self.config.get('vulners_api_key') or os.getenv("VULNERS_API_KEY", "")
        if vulners_api_key:
            try:
                headers = {
                    "Content-Type": "application/json",
                    "X-Api-Key": vulners_api_key
                }
                url = f"https://vulners.com/api/v3/search/id/?id={cve_id}"
                
                response = requests.get(url, headers=headers, timeout=15)
                data = response.json()
                
                if data.get('result') == 'OK' and 'data' in data and 'documents' in data['data']:
                    vuln_data = data['data']['documents'].get(cve_id, {})
                    if vuln_data:
                        # Extract CVSS information
                        cvss_info = vuln_data.get('cvss', {})
                        cvss_score = cvss_info.get('score')
                        cvss_severity = cvss_info.get('severity')
                        cvss_vector = cvss_info.get('vector')
                        
                        # Extract CWE information
                        cwe_info = []
                        cwe_list = vuln_data.get('cwe', [])
                        for cwe in cwe_list:
                            cwe_info.append({
                                'id': cwe.replace('CWE-', ''),
                                'title': self._get_cwe_title(cwe)
                            })
                        
                        # Extract affected products
                        affected_products = vuln_data.get('affected_products', [])
                        
                        # Extract references and categorize them
                        references = vuln_data.get('references', [])
                        vendor_advisories = []
                        patches = []
                        for ref in references:
                            if isinstance(ref, dict):
                                url = ref.get('url', '')
                                tags = ref.get('tags', [])
                                if 'Vendor Advisory' in tags:
                                    vendor_advisories.append({'url': url, 'title': ref.get('title', '')})
                                elif 'Patch' in tags:
                                    patches.append({'url': url, 'title': ref.get('title', '')})
                            else:
                                # Handle string references
                                if 'advisory' in ref.lower():
                                    vendor_advisories.append({'url': ref, 'title': 'Vendor Advisory'})
                                elif 'patch' in ref.lower():
                                    patches.append({'url': ref, 'title': 'Patch'})
                        
                        # Get model's predicted score
                        model_score = self._predict_severity_score(vuln_data.get('description', ''))
                        
                        # Print summary information
                        print("\nVulnerability Details:")
                        print(f"Description: {vuln_data.get('description', 'N/A')}")
                        print(f"Published: {vuln_data.get('published', 'N/A')}")
                        print(f"Last Seen: {vuln_data.get('lastseen', 'N/A')}")
                        
                        print("\nCVSS Information:")
                        print(f"Score: {cvss_score}")
                        print(f"Severity: {cvss_severity}")
                        print(f"Vector: {cvss_vector}")
                        
                        if cwe_info:
                            print("\nCWE Information:")
                            for cwe in cwe_info:
                                print(f"CWE-{cwe['id']}: {cwe['title']}")
                        
                        if affected_products:
                            print("\nAffected Products:")
                            for product in affected_products[:5]:
                                if isinstance(product, dict):
                                    print(f"- {product.get('name', 'N/A')} {product.get('version', 'N/A')}")
                                else:
                                    print(f"- {product}")
                            if len(affected_products) > 5:
                                print(f"... and {len(affected_products) - 5} more products")
                        
                        print("\nRemediation Resources:")
                        if vendor_advisories:
                            print("\nVendor Advisories:")
                            for advisory in vendor_advisories[:3]:
                                print(f"- {advisory['title']}: {advisory['url']}")
                            if len(vendor_advisories) > 3:
                                print(f"... and {len(vendor_advisories) - 3} more advisories")
                        
                        if patches:
                            print("\nAvailable Patches:")
                            for patch in patches[:3]:
                                print(f"- {patch['title']}: {patch['url']}")
                            if len(patches) > 3:
                                print(f"... and {len(patches) - 3} more patches")
                        
                        return {
                            'cve_id': cve_id,
                            'original_cvss_score': cvss_score,
                            'original_severity': cvss_severity,
                            'cvss_vector': cvss_vector,
                            'model_predicted_score': model_score,
                            'cwe_info': cwe_info,
                            'affected_products': affected_products,
                            'vendor_advisories': vendor_advisories,
                            'patches': patches,
                            'description': vuln_data.get('description', ''),
                            'published_date': vuln_data.get('published', ''),
                            'last_seen_date': vuln_data.get('lastseen', '')
                        }
                    else:
                        print(f"No data found for {cve_id}")
                else:
                    print(f"API Error: {data.get('data', {}).get('error', 'Unknown error')}")
            except Exception as e:
                print(f"Vulners API error: {str(e)}")
        print(f"\n{'-'*50}\n")
        return None

    def _get_cwe_title(self, cwe_id):
        """Get CWE title from a predefined mapping."""
        cwe_titles = {
            "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
            "CWE-20": "Improper Input Validation",
            "CWE-200": "Information Exposure",
            "CWE-22": "Path Traversal",
            "CWE-287": "Improper Authentication",
            "CWE-352": "Cross-Site Request Forgery (CSRF)",
            "CWE-434": "Unrestricted Upload of File with Dangerous Type",
            "CWE-306": "Missing Authentication for Critical Function",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-400": "Uncontrolled Resource Consumption",
            "CWE-798": "Use of Hard-coded Credentials",
            "CWE-295": "Improper Certificate Validation",
            "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            "CWE-264": "Permissions, Privileges, and Access Controls",
            "CWE-787": "Out-of-bounds Write"
        }
        return cwe_titles.get(cwe_id, "Unknown CWE")

    def _predict_severity_score(self, description):
        """Predict severity score based on vulnerability description."""
        if not description:
            return None
        # Use a simple heuristic based on keywords in the description
        critical_keywords = ['remote code execution', 'arbitrary code execution', 'root access', 'privilege escalation']
        high_keywords = ['memory corruption', 'buffer overflow', 'denial of service', 'information disclosure']
        medium_keywords = ['cross-site scripting', 'sql injection', 'information exposure']
        
        description_lower = description.lower()
        if any(keyword in description_lower for keyword in critical_keywords):
            return 9.0
        elif any(keyword in description_lower for keyword in high_keywords):
            return 7.5
        elif any(keyword in description_lower for keyword in medium_keywords):
            return 5.0
        return 3.0  # Default to low severity if no keywords match

    def integrated_pipeline(self, json_file, output_dir=os.path.join(WORK_DIR, "integrated_results")):
        os.makedirs(output_dir, exist_ok=True)
        try:
            vulnerabilities = extract_openvas_data(json_file)
            df = preprocess_openvas_data(vulnerabilities, self.config.get('exploit_db_path'), self.config)
            
            # Test API integration for each vulnerability
            print("\nTesting API Integration for each vulnerability:")
            for _, row in df.iterrows():
                if pd.notna(row.get('cve_id')):
                    self.test_exploit_api_integration(row['cve_id'])
            
            df = predict_severity_from_cvss(df)
            df['ai_remediation'] = df.apply(
                lambda row: self.generate_remediation({
                    'description': row['description'],
                    'cve_id': row.get('cve_id', ''),
                    'cvss_v3_score': row['cvss_v3_score'],
                    'threat': row['predicted_severity']
                }), axis=1
            )
            source_name = os.path.splitext(os.path.basename(json_file))[0]
            output_file = os.path.join(output_dir, f"{source_name}_integrated.csv")
            df.to_csv(output_file, index=False)
            self._generate_enhanced_report(df, source_name, output_dir)
            logging.info(f"Pipeline completed. Output saved to {output_file}")
            return df
        except Exception as e:
            logging.error(f"Pipeline failed: {e}")
            raise

    def _generate_enhanced_report(self, df, source_name, output_dir):
        html_content = """
        <html>
        <head>
            <title>Vulnerability Remediation Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .tab {{ display: none; }}
                .tab.active {{ display: block; }}
                .card {{ border: 1px solid #ccc; padding: 15px; margin: 10px; border-radius: 5px; background-color: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .exploit-warning {{ color: red; font-weight: bold; background-color: #fff0f0; padding: 10px; border-radius: 5px; }}
                .severity-critical {{ color: red; font-weight: bold; }}
                .severity-high {{ color: orange; font-weight: bold; }}
                .severity-medium {{ color: #d4a017; font-weight: bold; }}
                .severity-low {{ color: green; font-weight: bold; }}
                .tab-buttons {{ margin-bottom: 20px; }}
                .tab-buttons button {{ padding: 10px 20px; margin-right: 10px; border: none; background-color: #f0f0f0; cursor: pointer; border-radius: 5px; }}
                .tab-buttons button:hover {{ background-color: #e0e0e0; }}
                .cvss-comparison {{ margin: 15px 0; padding: 15px; background-color: #f8f8f8; border-radius: 5px; border-left: 4px solid #4CAF50; }}
                .score-difference {{ font-weight: bold; }}
                .score-match {{ color: green; }}
                .score-mismatch {{ color: red; }}
                .remediation-section {{ margin: 15px 0; padding: 15px; background-color: #f0f8ff; border-radius: 5px; border-left: 4px solid #2196F3; }}
                .cwe-info {{ margin: 15px 0; padding: 15px; background-color: #fff8f0; border-radius: 5px; border-left: 4px solid #FF9800; }}
                .affected-products {{ margin: 15px 0; padding: 15px; background-color: #f0fff0; border-radius: 5px; border-left: 4px solid #4CAF50; }}
                .severity-scores {{ display: flex; gap: 20px; margin: 15px 0; padding: 15px; background-color: #f5f5f5; border-radius: 5px; }}
                .severity-score-box {{ flex: 1; padding: 10px; border-radius: 5px; text-align: center; }}
                .severity-score-box h4 {{ margin: 0 0 10px 0; }}
                .severity-score-value {{ font-size: 24px; font-weight: bold; }}
                .severity-score-label {{ font-size: 14px; color: #666; }}
            </style>
            <script>
                function openTab(tabName) {{
                    var tabs = document.getElementsByClassName('tab');
                    for (var i = 0; i < tabs.length; i++) {{
                        tabs[i].classList.remove('active');
                    }}
                    document.getElementById(tabName).classList.add('active');
                }}
            </script>
        </head>
        <body>
            <h1>Vulnerability Remediation Report</h1>
            <h2>Summary</h2>
            <p>Total Vulnerabilities: {total_vulns}</p>
            <p>Critical/High Priority: {high_priority_count}</p>
            <h2>Vulnerability Details</h2>
            <div class="tab-buttons">
                <button onclick="openTab('all')">All Vulnerabilities</button>
                <button onclick="openTab('critical')">Critical</button>
                <button onclick="openTab('high')">High</button>
                <button onclick="openTab('medium')">Medium</button>
                <button onclick="openTab('low')">Low</button>
            </div>
        """
        total_vulns = len(df)
        high_priority_count = len(df[df['ai_remediation'].apply(lambda x: x.get('priority', 'Low') in ['High', 'Critical'])])
        html_content = html_content.format(total_vulns=total_vulns, high_priority_count=high_priority_count)

        # Create tabs for different severity levels
        tabs = {'all': [], 'critical': [], 'high': [], 'medium': [], 'low': []}
        for idx, row in df.iterrows():
            remediation = row['ai_remediation']
            exploit_info = remediation.get('exploit_info', {})
            priority = remediation.get('priority', 'Low').lower()
            severity_class = f"severity-{priority}"
            
            # Get Vulners API data
            vulners_data = self.test_exploit_api_integration(row.get('cve_id', ''))
            
            # Build CWE information section
            cwe_section = ""
            if vulners_data and vulners_data.get('cwe_info'):
                cwe_section = "<div class='cwe-info'><h4>CWE Information:</h4><ul>"
                for cwe in vulners_data['cwe_info']:
                    cwe_section += f"<li>CWE-{cwe['id']}: {cwe['title']}</li>"
                cwe_section += "</ul></div>"
            
            # Build affected products section
            products_section = ""
            if vulners_data and vulners_data.get('affected_products'):
                products_section = "<div class='affected-products'><h4>Affected Products:</h4><ul>"
                for product in vulners_data['affected_products'][:5]:
                    if isinstance(product, dict):
                        products_section += f"<li>{product.get('name', 'N/A')} {product.get('version', 'N/A')}</li>"
                    else:
                        products_section += f"<li>{product}</li>"
                if len(vulners_data['affected_products']) > 5:
                    products_section += f"<li>... and {len(vulners_data['affected_products']) - 5} more products</li>"
                products_section += "</ul></div>"
            
            # Build remediation section with Vulners data
            remediation_section = "<div class='remediation-section'>"
            remediation_section += f"<h4>Remediation Steps:</h4><p>{remediation.get('remediation', 'No remediation available')}</p>"
            
            if vulners_data:
                # Add vendor advisories
                if vulners_data.get('vendor_advisories'):
                    remediation_section += "<h4>Vendor Advisories:</h4><ul>"
                    for advisory in vulners_data['vendor_advisories'][:3]:
                        remediation_section += f"<li><a href='{advisory.get('url', '#')}' target='_blank'>{advisory.get('title', 'N/A')}</a></li>"
                    if len(vulners_data['vendor_advisories']) > 3:
                        remediation_section += f"<li>... and {len(vulners_data['vendor_advisories']) - 3} more advisories</li>"
                    remediation_section += "</ul>"
                
                # Add patches
                if vulners_data.get('patches'):
                    remediation_section += "<h4>Available Patches:</h4><ul>"
                    for patch in vulners_data['patches'][:3]:
                        remediation_section += f"<li><a href='{patch.get('url', '#')}' target='_blank'>{patch.get('title', 'N/A')}</a></li>"
                    if len(vulners_data['patches']) > 3:
                        remediation_section += f"<li>... and {len(vulners_data['patches']) - 3} more patches</li>"
                    remediation_section += "</ul>"
            
            remediation_section += "</div>"
            
            # Build CVSS comparison section
            cvss_comparison = ""
            if vulners_data:
                original_score = vulners_data.get('original_cvss_score')
                model_score = vulners_data.get('model_predicted_score')
                if original_score and model_score:
                    score_diff = abs(float(original_score) - float(model_score))
                    match_class = "score-match" if score_diff < 1.0 else "score-mismatch"
                    cvss_comparison = f"""
                    <div class="cvss-comparison">
                        <h4>CVSS Score Comparison</h4>
                        <p>Original CVSS Score: {original_score}</p>
                        <p>Model Predicted Score: {model_score}</p>
                        <p class="score-difference {match_class}">Score Difference: {score_diff:.2f}</p>
                        <p>CVSS Vector: {vulners_data.get('cvss_vector', 'N/A')}</p>
                    </div>
                    """
            
            # Build exploit warning section
            exploit_warning = ""
            if exploit_info.get('has_exploit', False):
                exploits = exploit_info.get('exploits', [])
                exploit_warning = f"""
                <div class="exploit-warning">
                    <strong>⚠️ Exploit Alert:</strong> {exploit_info.get('exploit_count', 0)} known exploit(s) available.
                    Exploit maturity: {exploit_info.get('exploit_maturity', 'unknown').upper()}
                    <ul>
                """
                for exp in exploits:
                    exploit_id = exp.get('exploit_id', 'unknown')
                    exploit_warning += f"""
                        <li><a href="https://www.exploit-db.com/exploits/{exploit_id}" target="_blank">{exp.get('description', 'Exploit')}</a> ({exp.get('date', 'Unknown')})</li>
                    """
                exploit_warning += "</ul></div>"

            quality_pred = remediation.get('quality_prediction', {})
            quality_status = quality_pred.get('status', 'unknown')
            quality_score = quality_pred.get('quality_score', 0)
            quality_confidence = quality_pred.get('confidence', 0)

            nvd_severity_check = remediation.get('nvd_severity_check', {})
            nvd_severity_info = ""
            if nvd_severity_check:
                nvd_severity_info = f"""
                <p><strong>NVD Severity Check:</strong> Score: {nvd_severity_check.get('score', 'N/A')}, 
                Match: {nvd_severity_check.get('match', 'N/A')}, 
                Difference: {nvd_severity_check.get('difference', 'N/A')}</p>
                """

            # Build severity scores section
            severity_scores = ""
            if vulners_data:
                original_score = vulners_data.get('original_cvss_score')
                model_score = vulners_data.get('model_predicted_score')
                nvd_score = remediation.get('nvd_severity_check', {}).get('score')
                
                if any(score is not None for score in [original_score, model_score, nvd_score]):
                    severity_scores = """
                    <div class="severity-scores">
                        <div class="severity-score-box">
                            <h4>Vulners Score</h4>
                            <div class="severity-score-value">{original_score}</div>
                            <div class="severity-score-label">CVSS v3.1</div>
                        </div>
                        <div class="severity-score-box">
                            <h4>Model Prediction</h4>
                            <div class="severity-score-value">{model_score}</div>
                            <div class="severity-score-label">AI Model</div>
                        </div>
                        <div class="severity-score-box">
                            <h4>NVD Score</h4>
                            <div class="severity-score-value">{nvd_score}</div>
                            <div class="severity-score-label">NVD Database</div>
                        </div>
                    </div>
                    """.format(
                        original_score=original_score if original_score is not None else "N/A",
                        model_score=model_score if model_score is not None else "N/A",
                        nvd_score=nvd_score if nvd_score is not None else "N/A"
                    )

            card_content = f"""
            <div class="card">
                <h3>Vulnerability {idx + 1}: {row.get('cve_id', 'Unknown CVE')}</h3>
                <p><strong>Description:</strong> {row.get('description', 'No description available')}</p>
                <p><strong>Predicted Severity:</strong> <span class="{severity_class}">{row.get('predicted_severity', 'Unknown')}</span></p>
                <p><strong>Priority:</strong> {remediation.get('priority', 'Unknown')}</p>
                <p><strong>Urgency:</strong> {remediation.get('urgency', 'Unknown')}</p>
                {severity_scores}
                {cvss_comparison}
                {cwe_section}
                {products_section}
                {remediation_section}
                {exploit_warning}
                <p><strong>Remediation Quality:</strong> Score: {quality_score:.2f}, Confidence: {quality_confidence:.2f}, Status: {quality_status}</p>
                {nvd_severity_info}
            </div>
            """

            tabs['all'].append(card_content)
            if priority in tabs:
                tabs[priority].append(card_content)

        # Add tab content to HTML
        html_content += '<div id="all" class="tab active">' + ''.join(tabs['all']) + '</div>'
        html_content += '<div id="critical" class="tab">' + ''.join(tabs['critical']) + '</div>'
        html_content += '<div id="high" class="tab">' + ''.join(tabs['high']) + '</div>'
        html_content += '<div id="medium" class="tab">' + ''.join(tabs['medium']) + '</div>'
        html_content += '<div id="low" class="tab">' + ''.join(tabs['low']) + '</div>'

        html_content += """
        </body>
        </html>
        """

        output_file = os.path.join(output_dir, f"{source_name}_report.html")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logging.info(f"Enhanced report generated at {output_file}")
        
def predict_severity_from_cvss(df):
    """Predict severity based on CVSS scores with thresholds."""
    conditions = [
        (df['cvss_v3_score'] >= 9.0),  # Critical
        (df['cvss_v3_score'] >= 7.0),  # High
        (df['cvss_v3_score'] >= 4.0),  # Medium
        (df['cvss_v3_score'] < 4.0)     # Low
    ]
    choices = ['Critical', 'High', 'Medium', 'Low']
    df['predicted_severity'] = np.select(conditions, choices, default='Medium')
    
    # Set high confidence for CVSS-based prediction
    df['prediction_confidence'] = 0.9
    return df

def preprocess_openvas_data(vulnerabilities, exploit_db_path=None, config=None):
    df = pd.DataFrame(vulnerabilities)
    exploit_db = ExploitDBIntegration(exploit_db_path=exploit_db_path, config=config)
    exploit_cache = {}
    def cached_exploit_lookup(cve_id):
        if not cve_id:
            return {'has_exploit': False, 'exploit_maturity': 'none', 'exploits': []}
        if cve_id not in exploit_cache:
            exploit_cache[cve_id] = exploit_db.lookup_cve_exploit(cve_id)
        return exploit_cache[cve_id]
    df['has_known_exploit'] = df['cve_id'].apply(lambda x: cached_exploit_lookup(x).get('has_exploit', False))
    maturity_scores = {'none': 0, 'low': 1, 'medium': 1.5, 'high': 2}
    df['exploit_maturity_score'] = df['cve_id'].apply(lambda x: maturity_scores.get(cached_exploit_lookup(x).get('exploit_maturity', 'none'), 0))
    df['exploit_age_days'] = df['cve_id'].apply(lambda x: _calculate_exploit_age(cached_exploit_lookup(x)))
    return df

def _calculate_exploit_age(exploit_info):
    if not exploit_info.get('has_exploit', False):
        return 0
    today = datetime.now()
    oldest_date = today
    for exploit in exploit_info.get('exploits', []):
        try:
            date_str = exploit.get('date', '')
            if date_str:
                exploit_date = datetime.strptime(date_str, '%Y-%m-%d')
                if exploit_date < oldest_date:
                    oldest_date = exploit_date
        except (ValueError, TypeError):
            continue
    return (today - oldest_date).days if oldest_date != today else 0

if __name__ == "__main__":
    config = {
        'work_dir': "C:/Users/cb26h/Desktop/pipeline/pipeline",
        'cache_dir': "C:/Users/cb26h/Desktop/pipeline/pipeline/cve_cache",
        'remediation_cache_dir': "C:/Users/cb26h/Desktop/pipeline/pipeline/remediation_cache",
        'remediation_feedback_dir': "C:/Users/cb26h/Desktop/pipeline/pipeline/remediation_feedback",
        'integrated_results_dir': "C:/Users/cb26h/Desktop/pipeline/pipeline/integrated_results",
        'exploit_db_path': "C:/Users/cb26h/Desktop/pipeline/pipeline/exploitdb/files_exploits.csv",
        'embedding_model': 'all-MiniLM-L6-v2',
        'similarity_threshold': 0.7,
        'vulners_api_key': os.getenv('VULNERS_API_KEY', ''),
        'nvd_api_key': os.getenv('NVD_API_KEY', ''),
        'shodan_api_key': os.getenv('SHODAN_API_KEY', '')
    }
    
    # API keys are now loaded from environment variables via .env file
    
    remediation_system = EnhancedRemediationSystem(config)
    json_file = "C:/Users/cb26h/Desktop/pipeline/pipeline/test_vulnerabilities.json"
    df = remediation_system.integrated_pipeline(json_file)
    print(f"Processed {len(df)} vulnerabilities. Output saved to integrated_results directory.")