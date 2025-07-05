import os
import uuid
import threading
import subprocess
import re
import json
import time
import logging
import random
from pathlib import Path
from flask import Flask, render_template, request, redirect, jsonify, send_from_directory, url_for
from bs4 import BeautifulSoup
import pandas as pd
from flask_cors import CORS
from werkzeug.utils import secure_filename
import xml.etree.ElementTree as ET
import requests

# Import your actual XML to JSON converter
import xml_to_json

# Import centralized configuration
from config import (
    PATHS, CACHE_DIRS, DATA_DIRS, FILE_PATTERNS, API_CONFIG, 
    APP_SETTINGS, SCAN_CONFIG, SECURITY_CONFIG,
    get_path, get_cache_path, get_data_path, get_api_config, get_app_setting
)

# Setup logging with configuration
logging.basicConfig(
    level=getattr(logging, get_app_setting('LOGGING', 'LEVEL')),
    format=get_app_setting('LOGGING', 'FORMAT'),
    handlers=[
        logging.FileHandler(get_app_setting('LOGGING', 'FILE')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ─── Application Configuration ───────────────────────────────────────────────
# Initialize Flask app with configuration
app = Flask(
    __name__, 
    static_folder=str(get_path('STATIC_FOLDER')), 
    template_folder=str(get_path('TEMPLATES_FOLDER'))
)

# Configure Flask app settings
app.config.update(
    UPLOAD_FOLDER=str(get_path('UPLOAD_FOLDER')),
    SECRET_KEY=get_app_setting('FLASK', 'SECRET_KEY'),
    MAX_CONTENT_LENGTH=get_app_setting('PROCESSING', 'MAX_FILE_SIZE')
)

# Configure CORS with security settings
if SECURITY_CONFIG['CORS']['ENABLED']:
    CORS(app, resources={
        r"/*": {
            "origins": SECURITY_CONFIG['CORS']['ORIGINS'],
            "methods": SECURITY_CONFIG['CORS']['METHODS'],
            "headers": SECURITY_CONFIG['CORS']['HEADERS']
        }
    })

# In-memory stores
jobs = {}
scans = {}

def load_jobs():
    """Load jobs from persistence file."""
    global jobs
    try:
        jobs_file = get_path('JOBS_PERSISTENCE')
        if jobs_file.exists():
            with open(jobs_file, 'r') as f:
                jobs = json.load(f)
                logger.info(f"Loaded {len(jobs)} jobs from persistence file")
        else:
            jobs = {}
    except Exception as e:
        logger.error(f"Error loading jobs from persistence file: {e}")
        jobs = {}

def save_jobs():
    """Save jobs to persistence file."""
    try:
        jobs_file = get_path('JOBS_PERSISTENCE')
        
        # Convert Path objects to strings for JSON serialization
        serializable_jobs = {}
        for job_id, job_data in jobs.items():
            serializable_job = {}
            for key, value in job_data.items():
                if isinstance(value, Path):
                    serializable_job[key] = str(value)
                else:
                    serializable_job[key] = value
            serializable_jobs[job_id] = serializable_job
        
        with open(jobs_file, 'w') as f:
            json.dump(serializable_jobs, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving jobs to persistence file: {e}")

# Load jobs on startup
load_jobs()

def allowed_file(filename):
    """Check if uploaded file has allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in FILE_PATTERNS['ALLOWED_EXTENSIONS']

def process_job(job_id, xml_path):
    job = jobs[job_id]
    try:
        job['stage'] = 'Loading XML'
        job['progress'] = 10
        save_jobs()  # Save job status
        logger.info(f"Job {job_id}: Loading XML file {xml_path}")
        time.sleep(1)

        job['stage'] = 'Converting to JSON'
        job['progress'] = 30
        save_jobs()  # Save job status
        logger.info(f"Job {job_id}: Converting XML to JSON")
        
        # Use the direct conversion function from xml_to_json module
        json_output = get_path('JSON_OUTPUT')
        xml_to_json.convert_openvas_xml_to_json(xml_path, str(json_output))
        logger.info(f"Job {job_id}: XML to JSON conversion completed")

        job['stage'] = 'Running analysis script'
        job['progress'] = 60
        save_jobs()  # Save job status
        logger.info(f"Job {job_id}: Running remediation system script")
        
        # Run the enhanced remediation system script
        try:
            result = subprocess.run(
                ['python', 'enhanced_remediation_system_fixed.py'],
                cwd=str(get_path('BASE_DIR')),
                check=True,
                capture_output=True,
                text=True
            )
            logger.info(f"Job {job_id}: Remediation script output: {result.stdout}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Job {job_id}: Remediation script failed: {e.stderr}")
            raise Exception(f"Remediation system script failed: {e.stderr}")
        
        csv_path = get_path('RESULTS_FOLDER') / FILE_PATTERNS['DEFAULT_FILES']['INTEGRATED_CSV']
        report_path = get_path('RESULTS_FOLDER') / FILE_PATTERNS['DEFAULT_FILES']['INTEGRATED_REPORT']
        vulnerabilities_data_path = get_data_path('STATIC_DATA', FILE_PATTERNS['DEFAULT_FILES']['VULNERABILITIES_DATA'])
        
        if not os.path.exists(csv_path) or not os.path.exists(report_path):
            raise Exception("Remediation system did not generate expected output files")

        # Run the vulnerability extraction script after HTML report is generated
        try:
            logger.info(f"Job {job_id}: Running vulnerability extraction script")
            extraction_script = get_path('RESULTS_FOLDER') / 'vulnerabilities_extraction.py'
            result = subprocess.run(
                ['python', str(extraction_script)],
                cwd=str(get_path('BASE_DIR')),
                check=True,
                capture_output=True,
                text=True
            )
            logger.info(f"Job {job_id}: Vulnerability extraction script output: {result.stdout}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Job {job_id}: Vulnerability extraction script failed: {e.stderr}")
            raise Exception(f"Vulnerability extraction script failed: {e.stderr}")

        # Run the remediation generation script after vulnerability extraction
        try:
            logger.info(f"Job {job_id}: Running remediation generation script")
            remediation_script_path = get_data_path('STATIC_DATA', 'generate_remediation_data.py')
            result = subprocess.run(
                ['python', str(remediation_script_path)],
                cwd=str(get_path('BASE_DIR')),
                check=True,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            logger.info(f"Job {job_id}: Remediation generation script output: {result.stdout}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Job {job_id}: Remediation generation script failed: {e.stderr}")
            raise Exception(f"Remediation generation script failed: {e.stderr}")
        except FileNotFoundError:
            logger.error(f"Job {job_id}: Remediation generation script not found at {remediation_script_path}")
            # You might want to decide if this is a critical failure or if the process can continue
            raise Exception(f"Remediation generation script not found. Ensure 'generate_remediation_data.py' is in 'static/data/'")

        job['stage'] = 'Parsing results'
        job['progress'] = 80
        save_jobs()  # Save job status
        logger.info(f"Job {job_id}: Reading data from CSV and static/data/vulnerabilities_data.json")

        try:
            # Read data from CSV file
            df = pd.read_csv(csv_path)
            logger.info(f"Successfully read CSV file with {len(df)} vulnerabilities")
            
            # Convert DataFrame to list of dictionaries
            vulnerabilities = df.to_dict('records')
            
            # Calculate severity counts from CSV data using predicted_severity
            severity_counts = {
                'Critical': len(df[df['predicted_severity'].str.lower() == 'critical']),
                'High': len(df[df['predicted_severity'].str.lower() == 'high']),
                'Medium': len(df[df['predicted_severity'].str.lower() == 'medium']),
                'Low': len(df[df['predicted_severity'].str.lower() == 'low'])
            }
            
            logger.info(f"Calculated severity counts from CSV: {severity_counts}")

            # Read threat intelligence and remediation data from static/data/vulnerabilities_data.json
            threat_intel = {}
            if os.path.exists(vulnerabilities_data_path):
                with open(vulnerabilities_data_path, 'r', encoding='utf-8') as f:
                    vuln_data = json.load(f)
                    logger.info("Successfully read static/data/vulnerabilities_data.json")
                    
                    # Process each vulnerability in the data
                    for vuln in vuln_data:
                        cve_id = vuln.get('cve_id')
                        if not cve_id:
                            continue
                            
                        # Extract threat intelligence data
                        threat_intel[cve_id] = {
                            'severity': vuln.get('predicted_severity', 'UNKNOWN'),
                            'source': 'MITRE & OpenVAS',
                            'date': vuln.get('date', time.strftime('%Y-%m-%d')),
                            'details': vuln.get('description', ''),
                            'cwe': vuln.get('cwe', []),
                            'exploits': vuln.get('exploits', []),
                            'remediation': vuln.get('remediation', ''),
                            'mitre_data': vuln.get('mitre_data', {}),
                            'cvss_score': vuln.get('cvss_score', 'N/A'),
                            'cvss_vector': vuln.get('cvss_vector', 'N/A'),
                            'affected_products': vuln.get('affected_products', []),
                            'references': vuln.get('references', []),
                            'ai_remediation': vuln.get('ai_remediation', {}),
                            'remediation_steps': vuln.get('remediation_steps', []),
                            'remediation_priority': vuln.get('priority', 'Medium'),
                            'remediation_impact': vuln.get('impact', ''),
                            'remediation_resources': vuln.get('resources', []),
                            'remediation_validation': vuln.get('validation', '')
                        }
                        
                        # Add any additional threat intelligence data
                        if 'threat_intel' in vuln:
                            threat_intel[cve_id].update(vuln['threat_intel'])
                            
                        logger.info(f"Processed threat intelligence for: {cve_id}")

            # Store the parsed data in the job object
            job['data'] = {
                'vulnerabilities': vulnerabilities,
                'threat_intel': threat_intel,
                'severity_counts': severity_counts,
                'total_vulnerabilities': len(vulnerabilities)
            }

            # Update the dashboard data immediately
            update_dashboard_data(job['data'])

            job['stage'] = 'Complete'
            job['progress'] = 100
            job['done'] = True
            job['result_path'] = csv_path
            job['report_path'] = report_path
            job['redirect'] = '/'
            save_jobs()  # Save final job status
            
            logger.info(f"Job {job_id}: Processing completed successfully")

        except Exception as e:
            logger.error(f"Error reading data files: {str(e)}")
            raise Exception(f"Failed to read data files: {str(e)}")

    except Exception as e:
        job['stage'] = f'Error: {str(e)}'
        job['done'] = True
        save_jobs()  # Save error status
        logger.error(f"Job {job_id} failed: {str(e)}")
        raise

def update_dashboard_data(data):
    """
    Update all dashboard components with the latest data
    """
    try:
        logger.info("Starting dashboard data update...")
        
        # Update the CSV file
        csv_path = get_path('RESULTS_FOLDER') / 'test_vulnerabilities_integrated.csv'
        df = pd.DataFrame(data['vulnerabilities'])
        df.to_csv(csv_path, index=False)
        logger.info(f"Updated CSV file with {len(data['vulnerabilities'])} vulnerabilities")
        
        # Generate trend data based on current vulnerabilities
        current_month = time.strftime('%b')
        months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        current_month_index = months.index(current_month)
        
        # Calculate base values for trend data
        base_values = {
            'Critical': max(1, data['severity_counts']['Critical'] // 2),
            'High': max(2, data['severity_counts']['High'] // 2),
            'Medium': max(3, data['severity_counts']['Medium'] // 2),
            'Low': max(4, data['severity_counts']['Low'] // 2)
        }
        
        # Generate trend data with realistic progression
        trend_data = {
            'labels': months[current_month_index-6:current_month_index+1],
            'datasets': []
        }
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            base = base_values[severity]
            # Generate a realistic progression with some randomness
            progression = [
                int(base * (0.3 + 0.1 * i + 0.1 * random.random()))
                for i in range(6)
            ]
            # Add current month's actual count
            progression.append(data['severity_counts'][severity])
            
            trend_data['datasets'].append({
                'label': severity,
                'data': progression
            })
        
        # Update the JSON file with the latest data
        json_path = get_path('DASHBOARD_DATA')
        dashboard_data = {
            'vulnerabilities': data['vulnerabilities'],
            'threat_intel': data['threat_intel'],
            'severity_counts': data['severity_counts'],
            'total_vulnerabilities': data['total_vulnerabilities'],
            'timestamp': time.time(),
            'severity_groups': {
                'Critical': [v for v in data['vulnerabilities'] if v['predicted_severity'].lower() == 'critical'],
                'High': [v for v in data['vulnerabilities'] if v['predicted_severity'].lower() == 'high'],
                'Medium': [v for v in data['vulnerabilities'] if v['predicted_severity'].lower() == 'medium'],
                'Low': [v for v in data['vulnerabilities'] if v['predicted_severity'].lower() == 'low']
            },
            'trend_data': trend_data
        }
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(dashboard_data, f, indent=4)
            
        logger.info("Dashboard data updated successfully with:")
        logger.info(f"- Total vulnerabilities: {data['total_vulnerabilities']}")
        logger.info(f"- Severity counts: {data['severity_counts']}")
        logger.info(f"- Threat intelligence entries: {len(data['threat_intel'])}")
        
        # Update scan history
        scan_history_path = get_path('SCAN_HISTORY')
        try:
            if scan_history_path.exists():
                with open(scan_history_path, 'r', encoding='utf-8') as f:
                    scan_history = json.load(f)
            else:
                scan_history = []
                
            # Add new scan to history
            new_scan = {
                'timestamp': time.time(),
                'total_vulnerabilities': data['total_vulnerabilities'],
                'severity_counts': data['severity_counts'],
                'report_path': str(get_path('RESULTS_FOLDER') / FILE_PATTERNS['DEFAULT_FILES']['INTEGRATED_REPORT'])
            }
            scan_history.append(new_scan)
            
            # Keep only last 10 scans
            scan_history = scan_history[-10:]
            
            with open(scan_history_path, 'w', encoding='utf-8') as f:
                json.dump(scan_history, f, indent=4)
                
            logger.info("Scan history updated successfully")
            
        except Exception as e:
            logger.error(f"Error updating scan history: {str(e)}")
            
    except Exception as e:
        logger.error(f"Error updating dashboard data: {str(e)}")
        raise

def process_scan(scan_id, target, scan_type, options):
    scan = scans[scan_id]
    try:
        scan['stage'] = 'Initializing'
        scan['progress'] = 10
        time.sleep(1)

        scan['stage'] = 'Scanning Ports'
        scan['progress'] = 30
        time.sleep(2)

        scan['stage'] = 'Detecting Vulnerabilities'
        scan['progress'] = 60
        time.sleep(2)

        scan['stage'] = 'Generating Report'
        scan['progress'] = 80
        scan_result = {
            'target': target,
            'scan_type': scan_type,
            'options': options,
            'date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration': '5m 23s',
            'ports': [
                {'port': '22/tcp', 'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 7.6p1'},
                {'port': '80/tcp', 'state': 'open', 'service': 'http', 'version': 'Apache httpd 2.4.29'},
                {'port': '443/tcp', 'state': 'open', 'service': 'ssl/https', 'version': 'Apache httpd 2.4.29'}
            ],
            'vulnerabilities': [
                {'port': '80', 'description': 'Potential XSS vulnerability detected'},
                {'port': '443', 'description': 'SSL/TLS version vulnerable to POODLE attack'},
                {'port': '22', 'description': 'Weak SSH encryption algorithms detected'}
            ],
            'severity_counts': {'Critical': 4, 'High': 7, 'Medium': 12, 'Low': 0}
        }
        scan_path = get_path('SCANS_FOLDER') / f'scan_{scan_id}.json'
        with open(scan_path, 'w') as f:
            json.dump(scan_result, f)
        time.sleep(1)

        scan['stage'] = 'Complete'
        scan['progress'] = 100
        scan['done'] = True
        scan['result'] = scan_result

    except Exception as e:
        scan['stage'] = f'Error: {e}'
        scan['done'] = True
        logger.error(f"Scan {scan_id} failed: {e}")

@app.route('/', methods=['GET'])
def index():
    """Main dashboard page - shows the vulnerability dashboard"""
    try:
        # Try to load the latest dashboard data
        json_path = get_path('DASHBOARD_DATA')
        if json_path.exists():
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                logger.info("Loaded dashboard data from JSON file")
        else:
            # If no dashboard data exists, get the latest job data
            latest_job = None
            for job_id, job in jobs.items():
                if job.get('done') and job.get('data'):
                    if not latest_job or job.get('timestamp', 0) > latest_job.get('timestamp', 0):
                        latest_job = job

            if latest_job and latest_job.get('data'):
                data = latest_job['data']
                logger.info("Loaded dashboard data from latest job")
            else:
                logger.info("No dashboard data available, showing empty dashboard")
                return render_template(
                    'dashboard.html',
                    total=0,
                    counts={},
                    all_vulns=[],
                    data_by_severity={},
                    threat_intel={},
                    trend_data={
                        'labels': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
                        'datasets': [
                            {'label': 'Critical', 'data': [0, 0, 0, 0, 0, 0, 0]},
                            {'label': 'High', 'data': [0, 0, 0, 0, 0, 0, 0]},
                            {'label': 'Medium', 'data': [0, 0, 0, 0, 0, 0, 0]},
                            {'label': 'Low', 'data': [0, 0, 0, 0, 0, 0, 0]}
                        ]
                    }
                )

        # Load scan history
        scan_history_path = get_path('SCAN_HISTORY')
        scan_history = []
        if scan_history_path.exists():
            with open(scan_history_path, 'r', encoding='utf-8') as f:
                scan_history = json.load(f)
                logger.info(f"Loaded {len(scan_history)} previous scans")

        return render_template(
            'dashboard.html',
            total=data['total_vulnerabilities'],
            counts=data['severity_counts'],
            all_vulns=data['vulnerabilities'],
            data_by_severity={
                'Critical': [v for v in data['vulnerabilities'] if v['predicted_severity'].lower() == 'critical'],
                'High': [v for v in data['vulnerabilities'] if v['predicted_severity'].lower() == 'high'],
                'Medium': [v for v in data['vulnerabilities'] if v['predicted_severity'].lower() == 'medium'],
                'Low': [v for v in data['vulnerabilities'] if v['predicted_severity'].lower() == 'low']
            },
            threat_intel=data.get('threat_intel', []),
            trend_data=data.get('trend_data', {
                'labels': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
                'datasets': [
                    {'label': 'Critical', 'data': [0, 0, 0, 0, 0, 0, 0]},
                    {'label': 'High', 'data': [0, 0, 0, 0, 0, 0, 0]},
                    {'label': 'Medium', 'data': [0, 0, 0, 0, 0, 0, 0]},
                    {'label': 'Low', 'data': [0, 0, 0, 0, 0, 0, 0]}
                ]
            }),
            scan_history=scan_history
        )
    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}")
        return render_template(
            'dashboard.html',
            total=0,
            counts={},
            all_vulns=[],
            data_by_severity={},
            threat_intel={},
            trend_data={
                'labels': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
                'datasets': [
                    {'label': 'Critical', 'data': [0, 0, 0, 0, 0, 0, 0]},
                    {'label': 'High', 'data': [0, 0, 0, 0, 0, 0, 0]},
                    {'label': 'Medium', 'data': [0, 0, 0, 0, 0, 0, 0]},
                    {'label': 'Low', 'data': [0, 0, 0, 0, 0, 0, 0]}
                ]
            }
        )

@app.route('/upload', methods=['GET'])
def upload():
    """File upload page"""
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start():
    try:
        file = request.files.get('file')
        if not file or file.filename == '' or not allowed_file(file.filename):
            return jsonify(error='Please upload a valid .xml file'), 400

        filename = secure_filename(file.filename)
        xml_path = get_path('UPLOAD_FOLDER') / filename
        file.save(xml_path)
        
        logger.info(f"File uploaded successfully to {xml_path}")

        # Verify XML file exists and is readable
        if not xml_path.exists():
            raise Exception("Uploaded file not found")
            
        # Try parsing XML to verify it's valid
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            logger.info("XML file parsed successfully")
        except ET.ParseError as e:
            raise Exception(f"Invalid XML file: {str(e)}")

        job_id = str(uuid.uuid4())
        jobs[job_id] = {
            'stage': 'Queued',
            'progress': 0,
            'done': False,
            'timestamp': time.time(),
            'xml_path': xml_path
        }
        
        # Save job to persistence file
        save_jobs()
        
        logger.info(f"Created new job {job_id} for file {filename}")
        
        # Start processing in background
        threading.Thread(target=process_job, args=(job_id, xml_path), daemon=True).start()

        return jsonify(job_id=job_id, redirect_url=url_for('results', job_id=job_id))
        
    except Exception as e:
        logger.error(f"Error in upload process: {str(e)}")
        return jsonify(error=str(e)), 500

@app.route('/status/<job_id>')
def status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify(error='Unknown job ID'), 404
    
    response = {
        'stage': job['stage'],
        'progress': job['progress'],
        'done': job['done']
    }
    
    # Add redirect URL if job is complete
    if job.get('done') and job.get('redirect'):
        response['redirect'] = job['redirect']
        
    return jsonify(response)

@app.route('/results', methods=['GET'])
def results():
    job_id = request.args.get('job_id')
    if not job_id or job_id not in jobs:
        return render_template('results.html', tables=[], error='No job ID provided or job not found')
    
    job = jobs[job_id]
    if not job.get('done'):
        return render_template('results.html', tables=[], error='Job is still processing')
    
    if job.get('stage').startswith('Error'):
        return render_template('results.html', tables=[], error=job['stage'])
    
    csv_path = job.get('result_path', str(get_path('RESULTS_FOLDER') / FILE_PATTERNS['DEFAULT_FILES']['INTEGRATED_CSV']))
    try:
        df = pd.read_csv(csv_path)
        tables = df.to_dict('records')
    except (FileNotFoundError, pd.errors.EmptyDataError):
        tables = []
        logger.error(f"CSV file not found: {csv_path}")
    
    return render_template('results.html', tables=tables, error=None)

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        target = request.form.get('target')
        scan_type = request.form.get('scan_type')
        options = request.form.getlist('options')

        if not target or not scan_type:
            return jsonify(error='Target and scan type are required'), 400

        scan_id = str(uuid.uuid4())
        scans[scan_id] = {'stage': 'Queued', 'progress': 0, 'done': False, 'target': target}
        threading.Thread(target=process_scan, args=(scan_id, target, scan_type, options), daemon=True).start()

        return jsonify(scan_id=scan_id, redirect_url=url_for('scan'))

    recent_scans = []
    scans_folder = get_path('SCANS_FOLDER')
    for scan_file in scans_folder.iterdir():
        if scan_file.name.endswith('.json'):
            scan_id = scan_file.name.replace('scan_', '').replace('.json', '')
            try:
                with open(scan_file) as f:
                    scan_data = json.load(f)
                recent_scans.append({
                    'id': scan_id,
                    'target': scan_data['target'],
                    'date': scan_data['date'],
                    'scan_type': scan_data['scan_type'],
                    'severity_counts': scan_data['severity_counts'],
                    'status': 'Completed'
                })
            except Exception as e:
                logger.error(f"Error loading scan {scan_file}: {e}")
    recent_scans.sort(key=lambda x: x['date'], reverse=True)
    return render_template('scan.html', vm_ip=load_config().get('vm_ip', '127.0.0.1'), recent_scans=recent_scans)

@app.route('/scan/status/<scan_id>')
def scan_status(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify(error='Unknown scan ID'), 404
    return jsonify(scan)

@app.route('/scan/result/<scan_id>')
def scan_result(scan_id):
    scan_path = get_path('SCANS_FOLDER') / f'scan_{scan_id}.json'
    try:
        with open(scan_path) as f:
            result = json.load(f)
        return jsonify(result)
    except FileNotFoundError:
        return jsonify(error='Scan result not found'), 404

@app.route('/dashboard')
def dashboard():
    """Redirect to main dashboard page"""
    return redirect(url_for('index'))

@app.route('/report')
def report():
    return send_from_directory(str(get_path('RESULTS_FOLDER')), FILE_PATTERNS['DEFAULT_FILES']['INTEGRATED_REPORT'])

@app.route('/download/csv')
def download_csv():
    return send_from_directory(str(get_path('RESULTS_FOLDER')), FILE_PATTERNS['DEFAULT_FILES']['INTEGRATED_CSV'], as_attachment=True)

@app.route('/download/json')
def download_json():
    return send_from_directory(str(get_path('BASE_DIR')), 'test_vulnerabilities.json', as_attachment=True)

def generate_vulnerabilities_data(scan_results):
    """Generate static/data/vulnerabilities_data.json from scan results."""
    try:
        vulnerabilities_data = []
        
        # Process each vulnerability from scan results
        for vuln in scan_results:
            vuln_data = {
                'cve_id': vuln.get('cve_id', ''),
                'predicted_severity': vuln.get('severity', 'UNKNOWN'),
                'description': vuln.get('description', ''),
                'cvss_score': vuln.get('cvss_score', 'N/A'),
                'cvss_vector': vuln.get('cvss_vector', 'N/A'),
                'cwe': vuln.get('cwe', []),
                'exploits': vuln.get('exploits', []),
                'affected_products': vuln.get('affected_products', []),
                'references': vuln.get('references', []),
                'mitre_data': vuln.get('mitre_data', {}),
                'ai_remediation': {
                    'remediation': vuln.get('remediation', ''),
                    'remediation_steps': vuln.get('remediation_steps', []),
                    'priority': vuln.get('remediation_priority', 'Medium'),
                    'impact': vuln.get('remediation_impact', ''),
                    'resources': vuln.get('remediation_resources', []),
                    'validation': vuln.get('remediation_validation', '')
                },
                'date': time.strftime('%Y-%m-%d')
            }
            vulnerabilities_data.append(vuln_data)
        
        # Save to static/data/vulnerabilities_data.json
        vulnerabilities_data_path = get_data_path('STATIC_DATA', FILE_PATTERNS['DEFAULT_FILES']['VULNERABILITIES_DATA'])
        with open(vulnerabilities_data_path, 'w', encoding='utf-8') as f:
            json.dump(vulnerabilities_data, f, indent=4)
        logging.info(f"Created static/data/vulnerabilities_data.json with {len(vulnerabilities_data)} entries")
        
        return True
    except Exception as e:
        logging.error(f"Error generating static/data/vulnerabilities_data.json: {str(e)}")
        return False

def get_latest_job():
    """Get the most recent job from the jobs directory."""
    try:
        jobs_dir = get_path('BASE_DIR') / 'jobs'
        if not jobs_dir.exists():
            return None
            
        # Get all job directories
        job_dirs = [d for d in jobs_dir.iterdir() if d.is_dir()]
        if not job_dirs:
            return None
            
        # Sort by creation time (newest first)
        job_dirs.sort(key=lambda x: x.stat().st_ctime, reverse=True)
        
        # Get the latest job directory
        latest_job_dir = job_dirs[0]
        
        # Read job metadata
        job_metadata_path = latest_job_dir / 'metadata.json'
        if job_metadata_path.exists():
            with open(job_metadata_path, 'r') as f:
                return json.load(f)
                
        return {'id': latest_job_dir.name}
    except Exception as e:
        logging.error(f"Error getting latest job: {str(e)}")
        return None

@app.route('/dashboard/data')
def dashboard_data():
    """Serve the latest dashboard data."""
    try:
        # Try to load from dashboard_data.json first
        dashboard_data_path = get_path('DASHBOARD_DATA')
        if dashboard_data_path.exists():
            with open(dashboard_data_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return jsonify({
                    'status': 'success',
                    'data': data.get('vulnerabilities', []),
                    'severity_counts': data.get('severity_counts', {}),
                    'threat_intel': data.get('threat_intel', {}),
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                })
        
        # If dashboard_data.json doesn't exist, try to load from the most recent job
        latest_job = get_latest_job()
        if latest_job:
            job_dir = get_path('BASE_DIR') / 'jobs' / latest_job['id']
            scan_results_path = job_dir / 'scan_results.json'
            
            if scan_results_path.exists():
                with open(scan_results_path, 'r', encoding='utf-8') as f:
                    scan_results = json.load(f)
                    # Generate static/data/vulnerabilities_data.json from scan results
                    if generate_vulnerabilities_data(scan_results):
                        with open(dashboard_data_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            return jsonify({
                                'status': 'success',
                                'data': data.get('vulnerabilities', []),
                                'severity_counts': data.get('severity_counts', {}),
                                'threat_intel': data.get('threat_intel', {}),
                                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                            })
        
        # If no data is available, return empty data structure
        return jsonify({
            'status': 'success',
            'data': [],
            'severity_counts': {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0
            },
            'threat_intel': {},
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        logging.error(f"Error serving dashboard data: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/api/threat-intel')
def get_threat_intel():
    """Get threat intelligence data from static/data/vulnerabilities_data.json"""
    try:
        # Check if static/data/vulnerabilities_data.json exists
        json_file = get_data_path('STATIC_DATA', FILE_PATTERNS['DEFAULT_FILES']['VULNERABILITIES_DATA'])
        if not json_file.exists():
            # If JSON doesn't exist, try to generate it from the HTML report
            try:
                from integrated_results.vulnerabilities_extraction import main as extract_vulnerabilities
                extract_vulnerabilities()
            except Exception as e:
                logger.error(f"Failed to generate vulnerabilities data: {str(e)}")
                return jsonify({'error': 'Failed to generate vulnerabilities data'}), 500

        # Read the JSON file
        with open(json_file, 'r', encoding='utf-8') as f:
            vulnerabilities_data = json.load(f)

        # Process the data for frontend display
        threat_intel_data = []
        for vuln in vulnerabilities_data:
            # Get the best available score
            cvss_score = vuln.get('cvss_score', 'N/A')
            nvd_score = vuln.get('nvd_score', 'N/A')
            vulners_score = vuln.get('vulners_score', 'N/A')
            
            # Determine severity based on scores
            severity = 'Unknown'
            if cvss_score != 'N/A':
                score = float(cvss_score)
                if score >= 9.0:
                    severity = 'Critical'
                elif score >= 7.0:
                    severity = 'High'
                elif score >= 4.0:
                    severity = 'Medium'
                else:
                    severity = 'Low'
            elif nvd_score != 'N/A':
                score = float(nvd_score)
                if score >= 9.0:
                    severity = 'Critical'
                elif score >= 7.0:
                    severity = 'High'
                elif score >= 4.0:
                    severity = 'Medium'
                else:
                    severity = 'Low'
            elif vulners_score != 'N/A':
                score = float(vulners_score)
                if score >= 9.0:
                    severity = 'Critical'
                elif score >= 7.0:
                    severity = 'High'
                elif score >= 4.0:
                    severity = 'Medium'
                else:
                    severity = 'Low'

            threat_intel_data.append({
                'cve_id': vuln.get('cve_id', 'N/A'),
                'description': vuln.get('description', 'N/A'),
                'severity': severity,
                'cvss_score': cvss_score,
                'nvd_score': nvd_score,
                'vulners_score': vulners_score,
                'cvss_vector': vuln.get('cvss_vector', 'N/A'),
                'cwe': vuln.get('cwe', 'N/A'),
                'date': vuln.get('date', 'N/A'),
                'source': vuln.get('source', 'N/A'),
                'ai_remediation': vuln.get('ai_remediation', {}),
                'affected_products': vuln.get('affected_products', []),
                'references': vuln.get('references', []),
                'mitre_data': vuln.get('mitre_data', {})
            })

        return jsonify(threat_intel_data)

    except Exception as e:
        logger.error(f"Error in get_threat_intel: {str(e)}")
        return jsonify({'error': str(e)}), 500

def load_config():
    try:
        config_file = get_path('CONFIG_FILE')
        with open(config_file) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            'vm_ip': '127.0.0.1',
            'scan_mode': 'quick',
            'api_key': '',
            'webhook_url': '',
            'auto_scan': False,
            'email_notify': False,
            'debug_mode': False
        }

def save_config(config):
    config_file = get_path('CONFIG_FILE')
    with open(config_file, 'w') as f:
        json.dump(config, f)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        config = {
            'vm_ip': request.form.get('vm_ip', '127.0.0.1'),
            'scan_mode': request.form.get('scan_mode', 'quick'),
            'api_key': request.form.get('api_key', ''),
            'webhook_url': request.form.get('webhook_url', ''),
            'auto_scan': request.form.get('auto_scan') == 'on',
            'email_notify': request.form.get('email_notify') == 'on',
            'debug_mode': request.form.get('debug_mode') == 'on'
        }
        save_config(config)
        return redirect('/settings')
    config = load_config()
    return render_template('settings.html', **config)
@app.route('/chatbot', methods=['POST'])
def chatbot():
    user_message = request.json.get('message', '')
    remediation_path = str(get_data_path('STATIC_DATA', 'remediations_training_dataset.csv'))
    vuln_path = str(get_data_path('STATIC_DATA', FILE_PATTERNS['DEFAULT_FILES']['VULNERABILITIES_CSV']))
    prompt = f"""
You are a cybersecurity assistant. Use the following data sources for context:
- Remediation dataset: {remediation_path}
- Vulnerabilities dataset: {vuln_path}

User question: {user_message}

If the answer is in the data, cite it. If not, answer as best you can.
"""
    try:
        # Get Ollama configuration
        ollama_config = get_api_config('OLLAMA')
        response = requests.post(
            f"{ollama_config['BASE_URL']}/api/generate",
            json={
                "model": ollama_config['DEFAULT_MODEL'],
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": ollama_config['TEMPERATURE'], 
                    "num_ctx": ollama_config['CONTEXT_SIZE']
                }
            },
            timeout=ollama_config['TIMEOUT']
        )
        answer = response.json().get("response", "Sorry, I couldn't get an answer.")
    except Exception as e:
        answer = f"Error querying Ollama: {e}"
    return jsonify({"answer": answer})
if __name__ == '__main__':
    logger.debug(f"Starting Flask app with static folder: {app.static_folder}")
    app.run(
        debug=get_app_setting('FLASK', 'DEBUG'),
        host=get_app_setting('FLASK', 'HOST'),
        port=get_app_setting('FLASK', 'PORT'),
        threaded=get_app_setting('FLASK', 'THREADED')
    )