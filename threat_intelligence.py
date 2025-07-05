import requests
import json
import os
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import logging
from sentence_transformers import SentenceTransformer, util
import time
from collections import defaultdict
from bs4 import BeautifulSoup

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class MitreAttackIntegration:
    """
    Integration with MITRE ATT&CK framework to enhance vulnerability remediation
    by providing threat actor intelligence and relevant mitigations.
    """
    
    def __init__(self, cache_dir=None, embedding_model=None):
        self.cache_dir = cache_dir or os.path.join(os.getcwd(), "mitre_cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        
        self.enterprise_json_path = os.path.join(self.cache_dir, "enterprise_attack.json")
        self.techniques_cache_path = os.path.join(self.cache_dir, "techniques_cache.json")
        self.groups_cache_path = os.path.join(self.cache_dir, "groups_cache.json")
        self.mitigations_cache_path = os.path.join(self.cache_dir, "mitigations_cache.json")
        self.embeddings_cache_path = os.path.join(self.cache_dir, "embeddings_cache.pkl")
        
        self.mitre_data = None
        self.techniques = {}
        self.groups = {}
        self.mitigations = {}
        self.technique_embeddings = {}
        self.cache_valid_days = 7
        
        # Initialize embeddings if provided
        self.embedding_model = None
        if embedding_model:
            self.embedding_model = embedding_model
        else:
            try:
                self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
                logging.info("Initialized SentenceTransformer for MITRE data")
            except Exception as e:
                logging.error(f"Failed to initialize SentenceTransformer: {e}")
        
        # Load cached data or download fresh
        self._load_or_download_data()
    
    def _load_or_download_data(self):
        """Load cached MITRE ATT&CK data or download if cache is invalid/missing."""
        download_required = False
        
        if os.path.exists(self.enterprise_json_path):
            file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(self.enterprise_json_path))
            if file_age.days > self.cache_valid_days:
                logging.info(f"MITRE data cache is {file_age.days} days old, refreshing...")
                download_required = True
        else:
            logging.info("MITRE data cache not found, downloading...")
            download_required = True
        
        if download_required:
            try:
                self._download_mitre_data()
            except Exception as e:
                logging.error(f"Failed to download MITRE data: {e}")
                if os.path.exists(self.enterprise_json_path):
                    logging.info("Using existing cache despite age")
                else:
                    raise
        
        try:
            with open(self.enterprise_json_path, 'r') as f:
                self.mitre_data = json.load(f)
            self._process_mitre_data()
            logging.info(f"Loaded MITRE ATT&CK data: {len(self.techniques)} techniques, "
                         f"{len(self.groups)} groups, {len(self.mitigations)} mitigations")
        except Exception as e:
            logging.error(f"Failed to load or process MITRE data: {e}")
            raise
    
    def _download_mitre_data(self):
        """Download the latest MITRE ATT&CK Enterprise dataset."""
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            with open(self.enterprise_json_path, 'w') as f:
                json.dump(response.json(), f)
            logging.info(f"Successfully downloaded MITRE ATT&CK data to {self.enterprise_json_path}")
        except Exception as e:
            logging.error(f"Error downloading MITRE data: {e}")
            raise
    
    def _process_mitre_data(self):
        """Process the raw MITRE data into usable dictionaries."""
        if not self.mitre_data:
            logging.error("No MITRE data available to process")
            return
        
        techniques_cache_valid = self._check_cache_validity(self.techniques_cache_path)
        groups_cache_valid = self._check_cache_validity(self.groups_cache_path)
        mitigations_cache_valid = self._check_cache_validity(self.mitigations_cache_path)
        
        if techniques_cache_valid and groups_cache_valid and mitigations_cache_valid:
            logging.info("Loading processed MITRE data from cache")
            self._load_from_cache()
            return
        
        logging.info("Processing MITRE ATT&CK data...")
        for obj in self.mitre_data.get('objects', []):
            obj_type = obj.get('type')
            if obj_type == 'attack-pattern':
                self._process_technique(obj)
            elif obj_type == 'intrusion-set':
                self._process_group(obj)
            elif obj_type == 'course-of-action':
                self._process_mitigation(obj)
        
        self._save_to_cache()
        if self.embedding_model:
            self._compute_embeddings()
    
    def _check_cache_validity(self, cache_path):
        """Check if a cache file exists and is recent enough."""
        if os.path.exists(cache_path):
            file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(cache_path))
            return file_age.days <= self.cache_valid_days
        return False
    
    def _load_from_cache(self):
        """Load processed data from cache files."""
        with open(self.techniques_cache_path, 'r') as f:
            self.techniques = json.load(f)
        with open(self.groups_cache_path, 'r') as f:
            self.groups = json.load(f)
        with open(self.mitigations_cache_path, 'r') as f:
            self.mitigations = json.load(f)
        if os.path.exists(self.embeddings_cache_path) and self.embedding_model:
            try:
                import pickle
                with open(self.embeddings_cache_path, 'rb') as f:
                    self.technique_embeddings = pickle.load(f)
                logging.info(f"Loaded {len(self.technique_embeddings)} technique embeddings from cache")
            except Exception as e:
                logging.error(f"Failed to load embeddings cache: {e}")
                self._compute_embeddings()
    
    def _save_to_cache(self):
        """Save processed data to cache files."""
        with open(self.techniques_cache_path, 'w') as f:
            json.dump(self.techniques, f, indent=2)
        with open(self.groups_cache_path, 'w') as f:
            json.dump(self.groups, f, indent=2)
        with open(self.mitigations_cache_path, 'w') as f:
            json.dump(self.mitigations, f, indent=2)
    
    def _process_technique(self, technique_obj):
        """Process a MITRE ATT&CK technique object."""
        technique_id = technique_obj.get('external_references', [{}])[0].get('external_id', '')
        if not technique_id or not technique_id.startswith('T'):
            return
        name = technique_obj.get('name', '')
        description = technique_obj.get('description', '')
        tactics = [phase.get('phase_name', '') for phase in technique_obj.get('kill_chain_phases', []) 
                  if phase.get('kill_chain_name') == 'mitre-attack']
        mitigations = []
        related_techniques = []
        for relationship in self.mitre_data.get('objects', []):
            if relationship.get('type') != 'relationship':
                continue
            target_ref = relationship.get('target_ref', '')
            if target_ref == technique_obj.get('id'):
                if relationship.get('relationship_type') == 'mitigates' and relationship.get('source_ref', '').startswith('course-of-action--'):
                    for obj in self.mitre_data.get('objects', []):
                        if obj.get('id') == relationship.get('source_ref'):
                            mitigation_id = obj.get('external_references', [{}])[0].get('external_id', '')
                            if mitigation_id:
                                mitigations.append(mitigation_id)
                if relationship.get('relationship_type') == 'subtechnique-of' and relationship.get('source_ref') == technique_obj.get('id'):
                    for obj in self.mitre_data.get('objects', []):
                        if obj.get('id') == target_ref:
                            related_id = obj.get('external_references', [{}])[0].get('external_id', '')
                            if related_id:
                                related_techniques.append(related_id)
        self.techniques[technique_id] = {
            'id': technique_id,
            'name': name,
            'description': description,
            'tactics': tactics,
            'mitigations': mitigations,
            'related_techniques': related_techniques
        }
    
    def _process_group(self, group_obj):
        """Process a MITRE ATT&CK group (intrusion-set) object."""
        group_id = group_obj.get('external_references', [{}])[0].get('external_id', '')
        if not group_id or not group_id.startswith('G'):
            return
        name = group_obj.get('name', '')
        description = group_obj.get('description', '')
        aliases = group_obj.get('aliases', [])
        techniques_used = []
        for relationship in self.mitre_data.get('objects', []):
            if relationship.get('type') != 'relationship':
                continue
            source_ref = relationship.get('source_ref', '')
            target_ref = relationship.get('target_ref', '')
            if source_ref == group_obj.get('id') and relationship.get('relationship_type') == 'uses' and target_ref.startswith('attack-pattern--'):
                for obj in self.mitre_data.get('objects', []):
                    if obj.get('id') == target_ref:
                        technique_id = obj.get('external_references', [{}])[0].get('external_id', '')
                        if technique_id:
                            techniques_used.append(technique_id)
        self.groups[group_id] = {
            'id': group_id,
            'name': name,
            'description': description,
            'aliases': aliases,
            'techniques_used': techniques_used
        }
    
    def _process_mitigation(self, mitigation_obj):
        """Process a MITRE ATT&CK mitigation (course-of-action) object."""
        mitigation_id = mitigation_obj.get('external_references', [{}])[0].get('external_id', '')
        if not mitigation_id or not mitigation_id.startswith('M'):
            return
        name = mitigation_obj.get('name', '')
        description = mitigation_obj.get('description', '')
        mitigates_techniques = []
        for relationship in self.mitre_data.get('objects', []):
            if relationship.get('type') != 'relationship':
                continue
            source_ref = relationship.get('source_ref', '')
            target_ref = relationship.get('target_ref', '')
            if source_ref == mitigation_obj.get('id') and relationship.get('relationship_type') == 'mitigates' and target_ref.startswith('attack-pattern--'):
                for obj in self.mitre_data.get('objects', []):
                    if obj.get('id') == target_ref:
                        technique_id = obj.get('external_references', [{}])[0].get('external_id', '')
                        if technique_id:
                            mitigates_techniques.append(technique_id)
        self.mitigations[mitigation_id] = {
            'id': mitigation_id,
            'name': name,
            'description': description,
            'mitigates_techniques': mitigates_techniques
        }
    
    def _compute_embeddings(self):
        """Compute embeddings for technique descriptions."""
        if not self.embedding_model:
            logging.warning("No embedding model available, skipping embeddings computation")
            return
        try:
            logging.info("Computing embeddings for MITRE ATT&CK techniques")
            technique_ids = []
            technique_texts = []
            for technique_id, technique in self.techniques.items():
                combined_text = f"{technique['name']}. {technique['description']}"
                technique_ids.append(technique_id)
                technique_texts.append(combined_text)
            batch_size = 32
            self.technique_embeddings = {}
            for i in range(0, len(technique_texts), batch_size):
                batch_ids = technique_ids[i:i+batch_size]
                batch_texts = technique_texts[i:i+batch_size]
                batch_embeddings = self.embedding_model.encode(batch_texts, show_progress_bar=False)
                for j, technique_id in enumerate(batch_ids):
                    self.technique_embeddings[technique_id] = batch_embeddings[j]
            import pickle
            with open(self.embeddings_cache_path, 'wb') as f:
                pickle.dump(self.technique_embeddings, f)
            logging.info(f"Computed and saved embeddings for {len(self.technique_embeddings)} techniques")
        except Exception as e:
            logging.error(f"Error computing embeddings: {e}")
    
    def find_related_techniques(self, vulnerability_description, top_k=5):
        """
        Find MITRE ATT&CK techniques related to a vulnerability description.
        """
        if not self.embedding_model or not self.technique_embeddings:
            logging.warning("Embedding model or technique embeddings not available")
            return []
        try:
            query_embedding = self.embedding_model.encode(vulnerability_description)
            similarities = {}
            for technique_id, technique_embedding in self.technique_embeddings.items():
                similarity = util.cos_sim(query_embedding, technique_embedding).item()
                similarities[technique_id] = similarity
            top_techniques = sorted(similarities.items(), key=lambda x: x[1], reverse=True)[:top_k]
            results = []
            for technique_id, similarity in top_techniques:
                if similarity < 0.3:
                    continue
                technique = self.techniques.get(technique_id, {})
                results.append({
                    'id': technique_id,
                    'name': technique.get('name', ''),
                    'description': technique.get('description', ''),
                    'tactics': technique.get('tactics', []),
                    'similarity': similarity
                })
            return results
        except Exception as e:
            logging.error(f"Error finding related techniques: {e}")
            return []
    
    def find_threat_actors(self, technique_ids):
        """
        Find threat actors (groups) that use specific techniques.
        """
        if not technique_ids:
            return []
        relevant_groups = []
        for group_id, group in self.groups.items():
            techniques_used = set(group.get('techniques_used', []))
            matching_techniques = set(technique_ids).intersection(techniques_used)
            if matching_techniques:
                relevant_groups.append({
                    'id': group_id,
                    'name': group.get('name', ''),
                    'description': group.get('description', ''),
                    'aliases': group.get('aliases', []),
                    'matched_techniques': list(matching_techniques),
                    'match_count': len(matching_techniques)
                })
        relevant_groups.sort(key=lambda x: x['match_count'], reverse=True)
        return relevant_groups
    
    def get_mitigations_for_techniques(self, technique_ids):
        """
        Get relevant mitigations for a set of techniques.
        """
        if not technique_ids:
            return []
        technique_mitigations = {}
        for technique_id in technique_ids:
            technique = self.techniques.get(technique_id, {})
            for mitigation_id in technique.get('mitigations', []):
                if mitigation_id not in technique_mitigations:
                    mitigation = self.mitigations.get(mitigation_id, {})
                    technique_mitigations[mitigation_id] = {
                        'id': mitigation_id,
                        'name': mitigation.get('name', ''),
                        'description': mitigation.get('description', ''),
                        'mitigated_techniques': [technique_id],
                        'relevance_score': 1
                    }
                else:
                    technique_mitigations[mitigation_id]['mitigated_techniques'].append(technique_id)
                    technique_mitigations[mitigation_id]['relevance_score'] += 1
        mitigations_list = list(technique_mitigations.values())
        mitigations_list.sort(key=lambda x: x['relevance_score'], reverse=True)
        return mitigations_list
    
    def analyze_vulnerability(self, vulnerability_data):
        """
        Analyze a vulnerability using MITRE ATT&CK framework.
        """
        description = vulnerability_data.get('description', '')
        if not description:
            return {'error': 'No vulnerability description provided'}
        related_techniques = self.find_related_techniques(description)
        if not related_techniques:
            return {
                'techniques': [],
                'threat_actors': [],
                'mitigations': [],
                'summary': 'No related MITRE ATT&CK techniques found'
            }
        technique_ids = [technique['id'] for technique in related_techniques]
        threat_actors = self.find_threat_actors(technique_ids)
        mitigations = self.get_mitigations_for_techniques(technique_ids)
        tactics = set()
        for technique in related_techniques:
            tactics.update(technique.get('tactics', []))
        summary = f"This vulnerability is related to {len(related_techniques)} MITRE ATT&CK techniques"
        if tactics:
            tactics_str = ', '.join(tactics)
            summary += f" across the following tactics: {tactics_str}"
        if threat_actors:
            top_actors = ', '.join([actor['name'] for actor in threat_actors[:3]])
            summary += f". It may be exploited by threat actors such as {top_actors}"
            if len(threat_actors) > 3:
                summary += f" and {len(threat_actors) - 3} others"
        if mitigations:
            summary += ". "
            top_mitigations = ', '.join([m['name'] for m in mitigations[:3]])
            summary += f"Key mitigations include: {top_mitigations}"
        return {
            'techniques': related_techniques,
            'threat_actors': threat_actors,
            'mitigations': mitigations,
            'summary': summary
        }
    
    def generate_threat_intelligence_report(self, vulnerability_data):
        """
        Generate a threat intelligence report for a vulnerability.
        """
        analysis = self.analyze_vulnerability(vulnerability_data)
        cve_id = vulnerability_data.get('cve_id', 'Unknown CVE')
        description = vulnerability_data.get('description', '')
        html = f"""
        <div class="threat-intelligence-report">
            <h3>Threat Intelligence for {cve_id}</h3>
            <div class="summary-section">
                <h4>Summary</h4>
                <p>{analysis.get('summary', 'No MITRE ATT&CK information available')}</p>
            </div>
            <div class="techniques-section">
                <h4>Related ATT&CK Techniques</h4>
                <div class="techniques-list">
        """
        techniques = analysis.get('techniques', [])
        if techniques:
            html += "<ul>"
            for technique in techniques:
                tactics_str = ', '.join(technique.get('tactics', []))
                html += f"""
                <li>
                    <div class="technique-item">
                        <strong>{technique['id']}: {technique['name']}</strong>
                        <span class="similarity-score">Relevance: {technique['similarity']:.2f}</span>
                        <div class="tactics">Tactics: {tactics_str}</div>
                        <div class="description">{technique['description'][:200]}...</div>
                    </div>
                </li>
                """
            html += "</ul>"
        else:
            html += "<p>No related techniques found</p>"
        html += """
                </div>
            </div>
            <div class="actors-section">
                <h4>Potential Threat Actors</h4>
                <div class="actors-list">
        """
        actors = analysis.get('threat_actors', [])
        if actors:
            html += "<ul>"
            for actor in actors[:5]:
                techniques_str = ', '.join(actor.get('matched_techniques', []))
                html += f"""
                <li>
                    <div class="actor-item">
                        <strong>{actor['id']}: {actor['name']}</strong>
                        <div class="aliases">Also known as: {', '.join(actor['aliases'])}</div>
                        <div class="techniques-used">Relevant techniques: {techniques_str}</div>
                    </div>
                </li>
                """
            html += "</ul>"
            if len(actors) > 5:
                html += f"<p>And {len(actors) - 5} more potential threat actors</p>"
        else:
            html += "<p>No specific threat actors identified</p>"
        html += """
                </div>
            </div>
            <div class="mitigations-section">
                <h4>Recommended Mitigations</h4>
                <div class="mitigations-list">
        """
        mitigations = analysis.get('mitigations', [])
        if mitigations:
            html += "<ul>"
            for mitigation in mitigations:
                techniques_str = ', '.join(mitigation.get('mitigated_techniques', []))
                html += f"""
                <li>
                    <div class="mitigation-item">
                        <strong>{mitigation['id']}: {mitigation['name']}</strong>
                        <div class="mitigated-techniques">Addresses techniques: {techniques_str}</div>
                        <div class="description">{mitigation['description'][:200]}...</div>
                    </div>
                </li>
                """
            html += "</ul>"
        else:
            html += "<p>No specific mitigations found</p>"
        html += """
                </div>
            </div>
        </div>
        """
        return html

class ShodanIntegration:
    """
    Integration with Shodan API to enhance vulnerability intelligence
    with real-world exposure data.
    """
    
    def __init__(self, api_key=None, cache_dir=None):
        self.api_key = api_key or os.environ.get('SHODAN_API_KEY')
        self.cache_dir = cache_dir or os.path.join(os.getcwd(), "shodan_cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        self.cache_valid_hours = 24
        if not self.api_key:
            logging.warning("No Shodan API key provided. Shodan functionality will be limited.")
    
    def search_vulnerability(self, cve_id):
        """
        Search Shodan for hosts affected by a specific CVE.
        """
        if not self.api_key:
            return {'error': 'No Shodan API key available'}
        if not cve_id or not cve_id.startswith('CVE-'):
            return {'error': 'Invalid CVE ID format'}
        cache_path = os.path.join(self.cache_dir, f"{cve_id.replace('-', '_')}_shodan.json")
        if os.path.exists(cache_path):
            file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(cache_path))
            if file_age < timedelta(hours=self.cache_valid_hours):
                try:
                    with open(cache_path, 'r') as f:
                        return json.load(f)
                except Exception as e:
                    logging.error(f"Error reading Shodan cache: {e}")
        try:
            import shodan
            api = shodan.Shodan(self.api_key)
            query = f'vuln:{cve_id}'
            result = api.search(query)
            processed_result = {
                'cve_id': cve_id,
                'total_results': result.get('total', 0),
                'search_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'countries': defaultdict(int),
                'organizations': defaultdict(int),
                'ports': defaultdict(int),
                'os': defaultdict(int),
                'samples': []
            }
            for host in result.get('matches', [])[:100]:
                country = host.get('location', {}).get('country_name', 'Unknown')
                org = host.get('org', 'Unknown')
                port = host.get('port', 0)
                os_name = host.get('os', 'Unknown')
                processed_result['countries'][country] += 1
                processed_result['organizations'][org] += 1
                processed_result['ports'][str(port)] += 1
                processed_result['os'][os_name] += 1
                if len(processed_result['samples']) < 10:
                    processed_result['samples'].append({
                        'ip': host.get('ip_str', ''),
                        'port': port,
                        'org': org,
                        'country': country,
                        'os': os_name,
                        'timestamp': host.get('timestamp', '')
                    })
            processed_result['countries'] = dict(processed_result['countries'])
            processed_result['organizations'] = dict(processed_result['organizations'])
            processed_result['ports'] = dict(processed_result['ports'])
            processed_result['os'] = dict(processed_result['os'])
            exposure_score = min(100, (processed_result['total_results'] / 50) * 10)
            processed_result['exposure_score'] = round(exposure_score, 1)
            with open(cache_path, 'w') as f:
                json.dump(processed_result, f, indent=2)
            return processed_result
        except Exception as e:
            logging.error(f"Error searching Shodan: {e}")
            return {
                'error': f"Shodan search failed: {str(e)}",
                'cve_id': cve_id,
                'total_results': 0,
                'exposure_score': 0
            }
    
    def generate_exposure_report(self, cve_id):
        """
        Generate an HTML report on the exposure of a vulnerability.
        """
        data = self.search_vulnerability(cve_id)
        if 'error' in data:
            return f"<div class='error-message'>Error: {data['error']}</div>"
        html = f"""
        <div class="exposure-report">
            <h3>Shodan Exposure Report: {cve_id}</h3>
            <div class="exposure-summary">
                <div class="exposure-score">
                    <div class="score-circle" style="background-color: {self._get_exposure_color(data['exposure_score'])}">
                        <span>{data['exposure_score']}</span>
                    </div>
                    <div class="score-label">Exposure Score</div>
                </div>
                <div class="exposure-stats">
                    <div class="stat-item">
                        <span class="stat-value">{data['total_results']:,}</span>
                        <span class="stat-label">Exposed Hosts</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-value">{len(data['countries'])}</span>
                        <span class="stat-label">Countries</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-value">{len(data['organizations'])}</span>
                        <span class="stat-label">Organizations</span>
                    </div>
                </div>
            </div>
            <div class="exposure-details">
                <div class="geographical-distribution">
                    <h4>Geographical Distribution</h4>
                    <table class="data-table">
                        <thead><tr><th>Country</th><th>Count</th><th>Percentage</th></tr></thead><tbody>
        """
        top_countries = sorted(data['countries'].items(), key=lambda x: x[1], reverse=True)[:10]
        for country, count in top_countries:
            percentage = (count / data['total_results'] * 100) if data['total_results'] > 0 else 0
            html += f"<tr><td>{country}</td><td>{count:,}</td><td>{percentage:.1f}%</td></tr>"
        html += "</tbody></table></div><div class='port-distribution'><h4>Port Distribution</h4><table class='data-table'><thead><tr><th>Port</th><th>Count</th><th>Percentage</th></tr></thead><tbody>"
        top_ports = sorted(data['ports'].items(), key=lambda x: int(x[1]), reverse=True)[:10]
        for port, count in top_ports:
            percentage = (count / data['total_results'] * 100) if data['total_results'] > 0 else 0
            html += f"<tr><td>{port}</td><td>{count:,}</td><td>{percentage:.1f}%</td></tr>"
        html += "</tbody></table></div><div class='organization-distribution'><h4>Organization Distribution</h4><table class='data-table'><thead><tr><th>Organization</th><th>Count</th><th>Percentage</th></tr></thead><tbody>"
        top_orgs = sorted(data['organizations'].items(), key=lambda x: x[1], reverse=True)[:10]
        for org, count in top_orgs:
            percentage = (count / data['total_results'] * 100) if data['total_results'] > 0 else 0
            html += f"<tr><td>{org}</td><td>{count:,}</td><td>{percentage:.1f}%</td></tr>"
        html += "</tbody></table></div></div><div class='remediation-implications'><h4>Remediation Implications</h4><p>"
        if data['exposure_score'] >= 80:
            html += f"This vulnerability has <strong>critical exposure</strong> with {data['total_results']:,} affected hosts visible on the internet. Immediate remediation is strongly recommended as this vulnerability is likely being actively exploited in the wild."
        elif data['exposure_score'] >= 50:
            html += f"This vulnerability has <strong>high exposure</strong> with {data['total_results']:,} affected hosts visible on the internet. Prioritize remediation as this vulnerability presents a significant attack surface."
        elif data['exposure_score'] >= 20:
            html += f"This vulnerability has <strong>moderate exposure</strong> with {data['total_results']:,} affected hosts visible on the internet. Remediation should be scheduled as part of your regular patching cycle."
        else:
            html += f"This vulnerability has <strong>limited exposure</strong> with {data['total_results']:,} affected hosts visible on the internet. While remediation is still recommended, this may be lower priority than other vulnerabilities."
        html += "</p></div><div class='exposure-samples'><h4>Sample Affected Hosts</h4><div class='samples-notice'><p><em>Note: This data is provided for informational purposes to understand the scope of exposure. Always respect privacy and legal regulations when handling this information.</em></p></div><table class='data-table'><thead><tr><th>IP Address</th><th>Port</th><th>Organization</th><th>Country</th><th>Operating System</th></tr></thead><tbody>"
        for sample in data.get('samples', []):
            html += f"<tr><td>{sample.get('ip', 'Unknown')}</td><td>{sample.get('port', 'Unknown')}</td><td>{sample.get('org', 'Unknown')}</td><td>{sample.get('country', 'Unknown')}</td><td>{sample.get('os', 'Unknown')}</td></tr>"
        html += "</tbody></table></div><div class='report-footer'><p>Data sourced from Shodan as of {data['search_time']}</p></div></div>"
        return html
    
    def _get_exposure_color(self, score):
        """Get color for exposure score visualization."""
        if score >= 80:
            return "#d9534f"  # Red
        elif score >= 50:
            return "#f0ad4e"  # Orange
        elif score >= 20:
            return "#5bc0de"  # Blue
        else:
            return "#5cb85c"  # Green
    
    def calculate_exposure_severity_adjustment(self, cve_id, base_severity):
        """
        Calculate a severity adjustment based on real-world exposure.
        """
        severity_levels = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        base_level = severity_levels.get(base_severity, 2)
        adjusted_level = base_level
        adjustment_reason = "No adjustment based on exposure data"
        exposure_data = self.search_vulnerability(cve_id)
        if 'error' in exposure_data:
            return base_severity, "No exposure data available"
        exposure_score = exposure_data.get('exposure_score', 0)
        total_results = exposure_data.get('total_results', 0)
        if exposure_score >= 70 and base_level < 4:
            adjusted_level = min(4, base_level + 1)
            adjustment_reason = f"Elevated due to critical exposure ({total_results:,} hosts visible)"
        elif exposure_score >= 40 and base_level < 3:
            adjusted_level = min(3, base_level + 1)
            adjustment_reason = f"Elevated due to significant exposure ({total_results:,} hosts visible)"
        elif exposure_score <= 10 and base_level > 1 and total_results < 100:
            adjusted_level = max(1, base_level - 1)
            adjustment_reason = f"Reduced due to limited real-world exposure (only {total_results:,} hosts visible)"
        adjusted_severity = next((k for k, v in severity_levels.items() if v == adjusted_level), base_severity)
        return adjusted_severity, adjustment_reason