# Advanced Vulnerability Management System

A comprehensive vulnerability assessment and remediation platform that processes OpenVAS XML scan reports and provides AI-powered remediation recommendations with threat intelligence integration.

## 🚀 Features

- **OpenVAS XML Report Processing**: Convert and analyze OpenVAS scan reports
- **AI-Powered Remediation**: Machine learning-based vulnerability remediation recommendations
- **Threat Intelligence Integration**: Real-time CVE data from multiple sources (NVD, Vulners, MITRE)
- **Exploit Database Integration**: ExploitDB integration for exploit availability assessment
- **Interactive Dashboard**: Real-time vulnerability tracking and visualization
- **Multi-API Support**: Vulners, NVD, Shodan, and Ollama API integration
- **Severity Prediction**: ML-based vulnerability severity classification
- **Comprehensive Reporting**: HTML reports with detailed vulnerability analysis

## 📋 Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [XML File Upload Workflow](#xml-file-upload-workflow)
- [Supported File Formats](#supported-file-formats)
- [API Integration](#api-integration)
- [Usage](#usage)
- [Architecture](#architecture)
- [API Endpoints](#api-endpoints)
- [Troubleshooting](#troubleshooting)

## 🛠️ Installation

### Prerequisites

- Python 3.8+
- pip package manager
- Git
- **GPU Requirements** (for AI processing):
  - NVIDIA GPU with CUDA support (recommended)
  - Minimum 4GB VRAM for basic models
  - 8GB+ VRAM for optimal performance
  - CUDA 11.0+ and cuDNN 8.0+
- **System Requirements**:
  - 8GB+ RAM (16GB+ recommended)
  - 10GB+ free disk space
  - Internet connection for API access

### Ollama Installation & Setup

#### 1. **Install Ollama**

**Windows:**
```bash
# Download from https://ollama.ai/download
# Or use winget
winget install Ollama.Ollama
```

**macOS:**
```bash
# Download from https://ollama.ai/download
# Or use Homebrew
brew install ollama
```

**Linux:**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

#### 2. **Start Ollama Service**
```bash
# Start the Ollama service
ollama serve

# In a new terminal, pull a model
ollama pull mistral
```

#### 3. **Verify Installation**
```bash
# Test Ollama API
curl http://localhost:11434/api/tags
```

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd pipeline
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure paths in settings.py**
   
   **IMPORTANT**: You must update the paths in `config/settings.py` to match your system:
   
   ```python
   # Change this line in config/settings.py (around line 25)
   BASE_DIR = Path(__file__).parent.parent.absolute()
   
   # If your project is in a different location, update it like this:
   # BASE_DIR = Path("C:/Users/YourUsername/Desktop/pipeline/pipeline")
   # BASE_DIR = Path("/home/username/pipeline/pipeline")
   ```

4. **Set up environment variables**
   Create a `.env` file in the root directory:
   ```env
   VULNERS_API_KEY=your_vulners_api_key
   SHODAN_API_KEY=your_shodan_api_key
   OLLAMA_API_KEY=your_ollama_api_key
   NVD_API_KEY=your_nvd_api_key_optional
   OLLAMA_BASE_URL=http://localhost:11434
   OLLAMA_MODEL=mistral
   FLASK_SECRET_KEY=your-secure-secret-key
   ```

5. **Create required directories**
   ```bash
   # The system will create these automatically, but you can pre-create them:
   mkdir -p uploads integrated_results cve_cache mitre_cache remediation_cache
   mkdir -p exploitdb models static/data templates
   ```

6. **Run Prerequisite Check (Recommended)**
   ```bash
   python prereq-script-updated.py
   ```
   This script will:
   - Check Python version compatibility
   - Verify all required directories exist
   - Validate required files are present
   - Check package dependencies
   - Create missing files if needed
   - Test OpenVAS module functionality

7. **Initialize the system**
   ```bash
   python app2.py
   ```

## ⚙️ Configuration

### Configuration File (`config.json`)

```json
{
  "vm_ip": "192.168.1.11",
  "scan_mode": "quick",
  "api_key": "your_api_key",
  "webhook_url": "",
  "auto_scan": false,
  "email_notify": false,
  "debug_mode": false
}
```

### Network Configuration & OpenVAS Backend Setup

#### **OpenVAS Server Configuration**

The system is designed to work with an OpenVAS backend running on Kali Linux or similar penetration testing distributions. The frontend communicates with the OpenVAS server via HTTP requests.

#### **VMware Network Setup (Required)**

If you're using VMware for the OpenVAS backend:

1. **Network Adapter Configuration**
   ```
   VMware Settings → Network Adapter → Bridge Mode
   ```
   - **Bridge Mode**: Allows direct network communication between host and VM
   - **NAT Mode**: Will NOT work for OpenVAS scanning
   - **Host-Only**: Will NOT work for external scanning

2. **Why Bridge Mode is Required**
   - OpenVAS sends HTTP requests to target systems
   - Bridge mode allows the VM to appear as a separate device on your network
   - Enables proper port scanning and vulnerability assessment
   - Allows bidirectional communication between frontend and backend

#### **Port Forwarding Configuration**

The OpenVAS server typically runs on specific ports that need to be accessible:

| Service | Default Port | Purpose |
|---------|-------------|---------|
| OpenVAS Manager | 9390 | Management interface |
| OpenVAS Scanner | 9391 | Scanning engine |
| Greenbone Security Manager | 9392 | Web interface |
| GSA (Web UI) | 9392 | Web-based management |

#### **OpenVAS Server IP Address Configuration**

In the application settings page, configure the **OpenVAS Server IP Address**:

1. **Find Your VM's IP Address**
   ```bash
   # On Kali Linux VM
   ip addr show
   # or
   ifconfig
   ```

2. **Configure in Application**
   - Go to Settings page in the web interface
   - Set "OpenVAS Server IP Address" to your VM's IP
   - Example: `192.168.1.100` (your VM's bridge network IP)

3. **Test Connectivity**
   ```bash
   # From Windows host, test connection to VM
   ping 192.168.1.100
   
   # Test OpenVAS web interface
   curl http://192.168.1.100:9392
   ```

#### **Firewall Configuration**

**Windows Host:**
```powershell
# Allow incoming connections from VM
netsh advfirewall firewall add rule name="OpenVAS Backend" dir=in action=allow remoteip=192.168.1.100
```

**Kali Linux VM:**
```bash
# Allow OpenVAS services through firewall
ufw allow 9390/tcp
ufw allow 9391/tcp
ufw allow 9392/tcp
```

#### **OpenVAS Service Verification**

On your Kali Linux VM, ensure OpenVAS services are running:

```bash
# Check OpenVAS services status
systemctl status openvas-manager
systemctl status openvas-scanner
systemctl status greenbone-security-assistant

# Start services if not running
systemctl start openvas-manager
systemctl start openvas-scanner
systemctl start greenbone-security-assistant

# Enable services to start on boot
systemctl enable openvas-manager
systemctl enable openvas-scanner
systemctl enable greenbone-security-assistant
```

#### **Network Troubleshooting**

**Common Issues:**

1. **Connection Refused**
   ```
   Error: Cannot connect to OpenVAS server
   ```
   **Solution:**
   - Verify VM is using Bridge mode
   - Check OpenVAS services are running
   - Verify IP address in settings
   - Test network connectivity

2. **Port Not Accessible**
   ```
   Error: Port 9392 is not accessible
   ```
   **Solution:**
   - Check firewall settings on both host and VM
   - Verify OpenVAS is listening on correct ports
   - Use `netstat -tlnp` to check listening ports

3. **Scan Targets Not Reachable**
   ```
   Error: Cannot reach scan targets
   ```
   **Solution:**
   - Ensure VM has network access to target systems
   - Check routing table: `route -n`
   - Verify DNS resolution if scanning by hostname

#### **Alternative Network Configurations**

**Docker Setup:**
```bash
# If using Docker for OpenVAS
docker run -d -p 9390:9390 -p 9391:9391 -p 9392:9392 greenbone/openvas
```

**Direct Installation:**
```bash
# Install OpenVAS directly on host system
apt update && apt install openvas
openvas-setup
```

### Settings Configuration (`config/settings.py`)

**CRITICAL**: You must configure the paths in `config/settings.py` before running the system.

#### 1. **Base Directory Configuration**
```python
# Line 25 in config/settings.py
BASE_DIR = Path(__file__).parent.parent.absolute()

# If your project is in a different location, change it to:
BASE_DIR = Path("C:/Users/YourUsername/Desktop/pipeline/pipeline")  # Windows
# BASE_DIR = Path("/home/username/pipeline/pipeline")  # Linux/macOS
```

#### 2. **API Configuration**
```python
# Update API keys in config/settings.py (lines 100-150)
API_CONFIG = {
    'VULNERS': {
        'API_KEY': os.getenv('VULNERS_API_KEY', ''),
        'RATE_LIMIT': 100,
    },
    'NVD': {
        'API_KEY': os.getenv('NVD_API_KEY', ''),
        'RATE_LIMIT': 1000,
    },
    'SHODAN': {
        'API_KEY': os.getenv('SHODAN_API_KEY', ''),
        'RATE_LIMIT': 100,
    },
    'OLLAMA': {
        'BASE_URL': os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434'),
        'DEFAULT_MODEL': os.getenv('OLLAMA_MODEL', 'mistral'),
    },
}
```

#### 3. **Flask Application Settings**
```python
# Lines 160-180 in config/settings.py
APP_SETTINGS = {
    'FLASK': {
        'SECRET_KEY': os.getenv('FLASK_SECRET_KEY', 'replace-me-with-a-secure-key'),
        'DEBUG': os.getenv('FLASK_DEBUG', 'False').lower() == 'true',
        'HOST': os.getenv('FLASK_HOST', '127.0.0.1'),
        'PORT': int(os.getenv('FLASK_PORT', 5000)),
    },
}
```

#### 4. **Processing Settings**
```python
# Lines 190-200 in config/settings.py
'PROCESSING': {
    'MAX_FILE_SIZE': 50 * 1024 * 1024,  # 50MB file size limit
    'CHUNK_SIZE': 8192,
    'ENCODING': 'utf-8',
},
```

### Directory Structure

```
pipeline/
├── app2.py                          # Main Flask application
├── xml_to_json.py                   # XML to JSON converter
├── enhanced_remediation_system_fixed.py  # AI remediation engine
├── prereq-script-updated.py         # Prerequisite checker (run first)
├── threat_intelligence.py           # Threat intelligence integration
├── process_download_openvas.py      # OpenVAS processing module
├── config/
│   ├── settings.py                  # Main configuration file
│   └── __init__.py
├── uploads/                         # Uploaded XML files
├── integrated_results/              # Processing results
├── cve_cache/                       # CVE data cache
├── mitre_cache/                     # MITRE ATT&CK cache
├── remediation_cache/               # Remediation data cache
├── exploitdb/                       # Exploit database files
├── models/                          # ML models
├── static/                          # Web assets
│   ├── css/                         # Stylesheets
│   ├── js/                          # JavaScript files
│   └── data/                        # Static data files
├── templates/                       # HTML templates
└── logs/                           # Application logs
```

### Network Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Windows Host  │    │   VMware VM     │    │  Target Systems │
│   (Frontend)    │◄──►│   (Kali Linux)  │◄──►│   (Scan Targets)│
│   Port 5000     │    │   (OpenVAS)     │    │                 │
│                 │    │   Port 9390-9392│    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │ Bridge Mode           │ Bridge Mode           │
         │ Network               │ Network               │
         ▼                       ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Local Network (192.168.1.x)                 │
└─────────────────────────────────────────────────────────────────┘
```

### Environment Variables (.env)

Create a `.env` file in the root directory with these variables:

```env
# API Keys
VULNERS_API_KEY=your_vulners_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
NVD_API_KEY=your_nvd_api_key_here

# Ollama Configuration
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=mistral
OLLAMA_TIMEOUT=60
OLLAMA_TEMPERATURE=0.3

# Flask Configuration
FLASK_SECRET_KEY=your-secure-secret-key-here
FLASK_DEBUG=False
FLASK_HOST=127.0.0.1
FLASK_PORT=5000

# Logging
LOG_LEVEL=INFO
```

## 📤 XML File Upload Workflow

### Complete Processing Pipeline

When you upload an OpenVAS XML file, the system follows this comprehensive workflow:

#### 1. **File Upload & Validation**
- **Route**: `/upload` (GET) and `/start` (POST)
- **File Validation**: 
  - Checks for `.xml` extension
  - Validates XML structure
  - Verifies OpenVAS format compliance
- **Security**: Uses `secure_filename()` for safe file handling

#### 2. **XML to JSON Conversion**
- **Script**: `xml_to_json.py`
- **Process**: 
  - Parses OpenVAS XML structure
  - Extracts vulnerability data
  - Converts to standardized JSON format
  - Filters results to include only CVE-associated vulnerabilities

#### 3. **AI Remediation Processing**
- **Script**: `enhanced_remediation_system_fixed.py`
- **Features**:
  - Machine learning-based severity prediction
  - Exploit availability assessment
  - Threat intelligence enrichment
  - AI-generated remediation recommendations

#### 4. **Data Integration & Analysis**
- **Threat Intelligence Sources**:
  - NVD (National Vulnerability Database)
  - Vulners API
  - MITRE ATT&CK Framework
  - ExploitDB
- **Processing**:
  - CVE details enrichment
  - CVSS scoring
  - Exploit maturity assessment
  - Remediation quality scoring

#### 5. **Report Generation**
- **Outputs**:
  - CSV file with integrated results
  - HTML report with detailed analysis
  - JSON data for dashboard visualization
  - Threat intelligence summary

### Processing Stages

```
Upload → Validation → XML→JSON → AI Analysis → Threat Intel → Report Generation → Dashboard Update
```

### Detailed Processing Flow & Output Files

#### **Stage 1: File Upload & Validation**
- **Input**: OpenVAS XML file (e.g., `report-*.xml`)
- **Process**: File validation and security checks
- **Output**: File saved to `uploads/` directory
- **Logs**: Upload confirmation in application logs

#### **Stage 2: XML to JSON Conversion**
- **Script**: `xml_to_json.py`
- **Input**: XML file from `uploads/` directory
- **Process**: 
  - Parse OpenVAS XML structure
  - Extract vulnerability data
  - Filter CVE-associated vulnerabilities
- **Output**: `test_vulnerabilities.json` (root directory)
- **Logs**: `Converting XML to JSON` → `XML to JSON conversion completed`

#### **Stage 3: Enhanced Remediation System Processing**
- **Script**: `enhanced_remediation_system_fixed.py`
- **Input**: `test_vulnerabilities.json`
- **Process**:
  - **ExploitDB Integration**: Download and process 46,000+ exploits
  - **CVE Mapping**: Create exploit-to-CVE mappings
  - **API Integration**: Query Vulners, NVD, Shodan APIs
  - **Threat Intelligence**: MITRE ATT&CK framework integration
  - **Severity Prediction**: ML-based vulnerability classification
- **Output Files**:
  - `cve_cache/cve_exploit_mappings.json` - CVE to exploit mappings
  - `integrated_results/test_vulnerabilities_integrated.csv` - Enhanced CSV data
  - `integrated_results/test_vulnerabilities_report.html` - HTML report
- **Logs**: `Running remediation system script` → ExploitDB processing progress

#### **Stage 4: Vulnerability Extraction**
- **Script**: `integrated_results/vulnerabilities_extraction.py`
- **Input**: HTML report from Stage 3
- **Process**: Extract structured vulnerability data
- **Output Files**:
  - `static/data/vulnerabilities.csv` - Frontend CSV data
  - `static/data/vulnerabilities_data.json` - Frontend JSON data
- **Logs**: `Running vulnerability extraction script` → `vulnerabilities.csv has been created`

#### **Stage 5: AI Remediation Generation (Ollama)**
- **Script**: `static/data/generate_remediation_data.py`
- **Input**: CSV and JSON data from Stage 4
- **Process**:
  - **Ollama Integration**: AI-powered remediation generation
  - **Model**: `mistral:latest` (default)
  - **Enhancement**: Structured remediation steps
  - **Quality Assessment**: Remediation quality scoring
- **Output Files**:
  - `static/data/structured_remediation_enhanced.js` - Enhanced remediation data
  - Updated `static/data/vulnerabilities_data.json` - AI-enhanced data
- **Logs**: `Running remediation generation script` → `Ollama available with models: mistral:latest`

#### **Stage 6: Dashboard Data Update**
- **Process**: Parse final results and update dashboard
- **Input**: All generated files from previous stages
- **Output Files**:
  - `dashboard_data.json` - Real-time dashboard data
  - `jobs_persistence.json` - Job status tracking
- **Logs**: `Reading data from CSV and static/data/vulnerabilities_data.json`

### File Output Summary

| Stage | Output Files | Location | Purpose |
|-------|-------------|----------|---------|
| **1** | Uploaded XML | `uploads/` | Original scan data |
| **2** | `test_vulnerabilities.json` | Root | Parsed vulnerability data |
| **3** | `cve_exploit_mappings.json` | `cve_cache/` | Exploit database mappings |
| **3** | `test_vulnerabilities_integrated.csv` | `integrated_results/` | Enhanced vulnerability data |
| **3** | `test_vulnerabilities_report.html` | `integrated_results/` | HTML report |
| **4** | `vulnerabilities.csv` | `static/data/` | Frontend CSV data |
| **4** | `vulnerabilities_data.json` | `static/data/` | Frontend JSON data |
| **5** | `structured_remediation_enhanced.js` | `static/data/` | AI-enhanced remediation |
| **6** | `dashboard_data.json` | Root | Dashboard visualization data |

### Processing Time Estimates

| Stage | Duration | Dependencies |
|-------|----------|-------------|
| **1** | 1-5 seconds | File size |
| **2** | 2-10 seconds | XML complexity |
| **3** | 30-120 seconds | API response times, ExploitDB processing |
| **4** | 5-15 seconds | Report size |
| **5** | 20-60 seconds | Ollama model, vulnerability count |
| **6** | 2-5 seconds | Data parsing |

### Error Handling & Recovery

- **Stage Failures**: Each stage logs errors and can be retried
- **API Timeouts**: Automatic retry with exponential backoff
- **File Corruption**: Validation checks at each stage
- **Ollama Unavailable**: Falls back to rule-based remediation
- **Partial Failures**: Continues processing with available data

## 📄 Supported File Formats

### OpenVAS XML Format

The system accepts **OpenVAS XML scan reports** with the following structure:

#### Required XML Schema

```xml
<report>
  <results>
    <result id="unique_id">
      <name>Vulnerability Name</name>
      <host>IP_ADDRESS</host>
      <port>PORT/PROTOCOL</port>
      <threat>SEVERITY_LEVEL</threat>
      <severity>CVSS_SCORE</severity>
      <nvt oid="NVT_OID">
        <name>NVT Name</name>
        <tags>cvss_base_vector=...|summary=...|insight=...|solution=...</tags>
        <refs>
          <ref type="cve" id="CVE-YYYY-NNNNN"/>
        </refs>
      </nvt>
      <description>Detailed description</description>
    </result>
  </results>
</report>
```

#### Key XML Elements

| Element | Description | Required |
|---------|-------------|----------|
| `<result>` | Individual vulnerability finding | Yes |
| `<name>` | Vulnerability name/title | Yes |
| `<host>` | Target IP address | Yes |
| `<port>` | Affected port/protocol | Yes |
| `<threat>` | Severity level (High/Medium/Low) | Yes |
| `<severity>` | CVSS score (0.0-10.0) | Yes |
| `<nvt>` | Network Vulnerability Test details | Yes |
| `<refs>` | References including CVE IDs | Yes |
| `<description>` | Detailed vulnerability description | Optional |

#### Example XML Structure

```xml
<report content_type="text/xml" extension="xml" id="report-id">
  <report>
    <results>
      <result id="0dfac365-534b-4aef-b03e-cb958ca82d8d">
        <name>Microsoft Windows Server Service Remote Code Execution Vulnerability</name>
        <host>192.168.183.134</host>
        <port>445/tcp</port>
        <threat>High</threat>
        <severity>10.0</severity>
        <nvt oid="1.3.6.1.4.1.25623.1.0.902782">
          <name>Microsoft Windows Server Service Remote Code Execution Vulnerability</name>
          <tags>cvss_base_vector=AV:N/AC:L/Au:N/C:C/I:C/A:C|summary=This host is missing important security update...</tags>
          <refs>
            <ref type="cve" id="CVE-2006-3439"/>
          </refs>
        </nvt>
        <description>Detailed vulnerability description...</description>
      </result>
    </results>
  </report>
</report>
```

### File Requirements

- **Format**: OpenVAS XML export
- **Encoding**: UTF-8
- **Size Limit**: No specific limit (handled by Flask)
- **Content**: Must contain at least one `<result>` with CVE reference
- **Source**: Generated by OpenVAS/GVM scanner

## 🔌 API Integration

### Supported APIs

#### 1. **Vulners API**
- **Purpose**: CVE details and exploit information
- **Configuration**: `VULNERS_API_KEY` in `.env`
- **Rate Limit**: Depends on subscription tier

#### 2. **NVD API**
- **Purpose**: Official CVE database
- **Configuration**: `NVD_API_KEY` in `.env` (optional)
- **Rate Limit**: 1000 requests/hour without key, 5000/hour with key

#### 3. **Shodan API**
- **Purpose**: Internet-wide vulnerability scanning
- **Configuration**: `SHODAN_API_KEY` in `.env`
- **Rate Limit**: Depends on subscription

#### 4. **Ollama API**
- **Purpose**: Local AI model inference
- **Configuration**: `OLLAMA_API_KEY` in `.env`
- **Usage**: AI-powered remediation generation

### API Configuration

```python
# Example API configuration
API_CONFIG = {
    'vulners': {
        'base_url': 'https://vulners.com/api/v3/',
        'api_key': os.getenv('VULNERS_API_KEY')
    },
    'nvd': {
        'base_url': 'https://services.nvd.nist.gov/rest/json/cves/2.0/',
        'api_key': os.getenv('NVD_API_KEY')
    },
    'shodan': {
        'base_url': 'https://api.shodan.io/',
        'api_key': os.getenv('SHODAN_API_KEY')
    }
}
```

## 🚀 Usage

### Starting the Application

```bash
python app2.py
```

The application will be available at `http://localhost:5000`

### OpenVAS Backend Setup

Before using the scanning features, ensure your OpenVAS backend is properly configured:

1. **Start OpenVAS Services on Kali Linux VM**
   ```bash
   # On your Kali Linux VM
   systemctl start openvas-manager
   systemctl start openvas-scanner
   systemctl start greenbone-security-assistant
   ```

2. **Configure OpenVAS Server IP**
   - Open the web interface: `http://localhost:5000`
   - Go to Settings page
   - Set "OpenVAS Server IP Address" to your VM's IP address
   - Example: `192.168.1.100`

3. **Test Backend Connection**
   - Use the test connection feature in settings
   - Or manually test: `curl http://<vm_ip>:9392`

4. **Create Scan Tasks**
   - Navigate to Scan page
   - Enter target IP addresses or hostnames
   - Select scan type (Quick, Full, Custom)
   - Start scanning

### Uploading XML Files

1. **Navigate to Upload Page**
   - Go to `/upload` or click "Upload" in the dashboard
   - Select your OpenVAS XML report file

2. **File Processing**
   - System validates XML format
   - Converts to JSON for processing
   - Runs AI analysis pipeline
   - Generates comprehensive reports

3. **View Results**
   - Check processing status at `/status/<job_id>`
   - View results in dashboard
   - Download reports in various formats

### Dashboard Features

- **Real-time Processing**: Live status updates with progress tracking
- **Vulnerability Overview**: Severity distribution charts and statistics
- **Threat Intelligence**: CVE details and exploit information
- **Remediation Recommendations**: AI-generated fixes with quality scores
- **Export Options**: CSV, JSON, and HTML reports
- **Processing Status**: Stage-by-stage progress monitoring

### Processing Status Monitoring

The dashboard provides real-time updates for each processing stage:

1. **Queued** → Job created and waiting
2. **Loading XML** (10%) → File validation and parsing
3. **Converting to JSON** (30%) → XML to JSON conversion
4. **Running analysis script** (60%) → Enhanced remediation processing
5. **Parsing results** (80%) → Data extraction and formatting
6. **Complete** (100%) → All stages finished, dashboard updated

**Example Log Output:**
```
Job e7413258-c65a-4f0d-a955-9dbb4a174859: Loading XML file
Job e7413258-c65a-4f0d-a955-9dbb4a174859: Converting XML to JSON
Job e7413258-c65a-4f0d-a955-9dbb4a174859: XML to JSON conversion completed
Job e7413258-c65a-4f0d-a955-9dbb4a174859: Running remediation system script
Processing 46834 exploits from ExploitDB...
Job e7413258-c65a-4f0d-a955-9dbb4a174859: Running vulnerability extraction script
Job e7413258-c65a-4f0d-a955-9dbb4a174859: Running remediation generation script
[AI] Ollama available with models: mistral:latest
Job e7413258-c65a-4f0d-a955-9dbb4a174859: Reading data from CSV and static/data/vulnerabilities_data.json
Calculated severity counts from CSV: {'Critical': 2, 'High': 1, 'Medium': 0, 'Low': 1}
```

## 🏗️ Architecture

### System Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Interface │    │  XML Processor  │    │  AI Engine      │
│   (Flask App)   │◄──►│  (xml_to_json)  │◄──►│  (ML Models)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Dashboard     │    │ Threat Intel    │    │  Report Gen     │
│   (Real-time)   │    │  (Multi-API)    │    │  (HTML/CSV)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Data Flow

1. **Input**: OpenVAS XML → Validation
2. **Processing**: XML→JSON → AI Analysis → Threat Intel
3. **Output**: Reports + Dashboard Data
4. **Storage**: Cached data for performance

### Processing Pipeline Visualization

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   File Upload   │    │  XML→JSON Conv  │    │  Enhanced Rem   │
│   (Stage 1)     │───►│   (Stage 2)     │───►│   (Stage 3)     │
│                 │    │                 │    │                 │
│ • Validation    │    │ • Parse XML     │    │ • ExploitDB     │
│ • Security      │    │ • Extract Data  │    │ • API Calls     │
│ • Save to       │    │ • Filter CVEs   │    │ • Threat Intel  │
│   uploads/      │    │ • Output JSON   │    │ • ML Prediction │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Vulnerability   │    │  AI Remediation │    │ Dashboard Update│
│ Extraction      │    │   Generation    │    │   (Stage 6)     │
│ (Stage 4)       │    │   (Stage 5)     │    │                 │
│                 │    │                 │    │                 │
│ • Parse HTML    │    │ • Ollama AI     │    │ • Parse Results │
│ • Extract CSV   │    │ • Mistral Model │    │ • Update Charts │
│ • Generate JSON │    │ • Enhancement   │    │ • Real-time     │
│ • Frontend Data │    │ • Quality Score │    │   Visualization │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📡 API Endpoints

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard |
| `/upload` | GET | File upload page |
| `/start` | POST | Process uploaded file |
| `/status/<job_id>` | GET | Job processing status |
| `/results` | GET | View processing results |
| `/dashboard/data` | GET | Dashboard data API |
| `/api/threat-intel` | GET | Threat intelligence data |

### File Processing Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/download/csv` | GET | Download CSV report |
| `/download/json` | GET | Download JSON data |
| `/report` | GET | View HTML report |

## 🔧 Troubleshooting

### Prerequisite Verification

Before troubleshooting, ensure your system meets all requirements:

```bash
# Run the prerequisite checker
python prereq-script-updated.py
```

This script will:
- ✅ **Check Python Version**: Ensures Python 3.6+ is installed
- ✅ **Verify Directories**: Creates missing directories automatically
- ✅ **Check Required Files**: Validates all essential files exist
- ✅ **Package Dependencies**: Installs missing Python packages
- ✅ **OpenVAS Module**: Tests OpenVAS processing functionality
- ✅ **Sample Data**: Creates test data if needed

**Example Output:**
```
--- Checking Python Version ---
✅ Python version 3.8.10 is compatible

--- Checking Required Directories ---
✅ All required directories exist

--- Checking Required Files ---
✅ All required files are present

--- Checking Package Dependencies ---
✅ All required packages are installed

--- System Ready ---
✅ All prerequisites are met. System is ready to run.
```

### Common Issues

#### 1. **Path Configuration Errors**
```
Error: Path key 'UPLOAD_FOLDER' not found in configuration
```
**Solution**: 
- Check `config/settings.py` and ensure `BASE_DIR` is set correctly
- Update the path to match your system directory structure
- Example: `BASE_DIR = Path("C:/Users/YourUsername/Desktop/pipeline/pipeline")`

#### 2. **Ollama Connection Issues**
```
Error: Connection refused to Ollama API
```
**Solution**:
- Ensure Ollama is running: `ollama serve`
- Check if the model is downloaded: `ollama list`
- Verify API endpoint: `curl http://localhost:11434/api/tags`
- Update `OLLAMA_BASE_URL` in `.env` if using different port

#### 3. **GPU/CUDA Issues**
```
Error: CUDA not available for PyTorch
```
**Solution**:
- Install CUDA toolkit: `conda install pytorch torchvision torchaudio pytorch-cuda=11.8 -c pytorch -c nvidia`
- Check GPU availability: `nvidia-smi`
- For CPU-only: Install CPU version: `pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu`

#### 4. **XML Parsing Errors**
```
Error: Invalid XML file
```
**Solution**: Ensure XML is well-formed and follows OpenVAS schema

#### 5. **API Key Issues**
```
Error: API authentication failed
```
**Solution**: Check `.env` file and API key validity

#### 6. **Processing Timeout**
```
Error: Job processing timeout
```
**Solution**: Check file size and system resources

#### 7. **Missing Dependencies**
```
Error: Module not found
```
**Solution**: 
- Run `pip install -r requirements.txt`
- Or use the prerequisite checker: `python prereq-script-updated.py`

#### 8. **Directory Permission Issues**
```
Error: Permission denied creating directory
```
**Solution**:
- Ensure write permissions to the project directory
- Run as administrator (Windows) or with sudo (Linux) if needed
- Check disk space availability

#### 9. **OpenVAS Connection Issues**
```
Error: Cannot connect to OpenVAS server
```
**Solution**:
- Verify VMware is using Bridge mode (not NAT or Host-Only)
- Check OpenVAS services are running on VM
- Verify IP address in settings matches VM's bridge network IP
- Test connectivity: `ping <vm_ip>` and `curl http://<vm_ip>:9392`
- Check firewall settings on both host and VM

### Performance Optimization

#### GPU Acceleration
```bash
# Install CUDA-enabled PyTorch
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118

# Verify GPU availability
python -c "import torch; print(torch.cuda.is_available())"
```

#### Memory Optimization
```python
# In config/settings.py, adjust these settings:
APP_SETTINGS = {
    'JOBS': {
        'MAX_CONCURRENT_JOBS': 2,  # Reduce for low memory systems
    },
    'PROCESSING': {
        'CHUNK_SIZE': 4096,  # Reduce for low memory systems
    },
}
```

### Debug Mode

Enable debug mode in `config/settings.py` or `.env`:
```python
# In config/settings.py
APP_SETTINGS = {
    'FLASK': {
        'DEBUG': True,
    },
}
```

Or in `.env`:
```env
FLASK_DEBUG=True
LOG_LEVEL=DEBUG
```

### Logs

Check log files for detailed error information:
- `remediation_system.log`: AI processing logs
- `logs/app.log`: Application logs
- Flask application logs: Console output

## 📊 Performance Optimization

### Caching Strategy

- **CVE Cache**: Reduces API calls for repeated CVEs
- **MITRE Cache**: Cached ATT&CK framework data
- **Embedding Cache**: ML model embeddings for faster processing

### Processing Optimization

- **Parallel Processing**: Multi-threaded API calls
- **Batch Processing**: Grouped vulnerability analysis
- **Incremental Updates**: Only process new vulnerabilities

## 🔒 Security Considerations

### File Upload Security

- **File Type Validation**: Only `.xml` files accepted
- **Path Traversal Protection**: Secure filename handling
- **Size Limits**: Configurable file size restrictions

### API Security

- **Key Management**: Environment variable storage
- **Rate Limiting**: API call throttling
- **Error Handling**: Secure error messages

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review the logs for error details
3. Open an issue on GitHub
4. Contact the development team

---

**Note**: This system is designed for security professionals and should be used in controlled environments. Always follow responsible disclosure practices when working with vulnerability data. 