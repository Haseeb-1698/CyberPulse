#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Download, preprocess and analyze real OpenVAS and NVD data with the optimized model pipeline
All-in-one script that combines download, preprocessing, and prediction
"""

import os
import requests
import gzip
import json
import tempfile
from pathlib import Path
import argparse
import sys
import pandas as pd
import numpy as np
import joblib
from sentence_transformers import SentenceTransformer
import re
import time
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

def parse_args():
    parser = argparse.ArgumentParser(description='Download, process and analyze OpenVAS and NVD data')
    parser.add_argument('--output_dir', type=str, default='openvas_test_data',
                        help='Directory to save downloaded data')
    parser.add_argument('--model', type=str, default='vulnerability_classifier.pkl',
                        help='Path to trained model file')
    parser.add_argument('--download_only', action='store_true',
                        help='Only download data without processing')
    parser.add_argument('--debug', '-d', action='store_true',
                        help='Enable debug mode with additional logging')
    parser.add_argument('--train_model', action='store_true',
                        help='Train a new model instead of loading an existing one')
    parser.add_argument('--custom_scan', type=str,
                        help='Path to custom OpenVAS scan file (XML or JSON) to process')
    return parser.parse_args()

def download_file(url, filename):
    """Download a file from a URL to the specified filename"""
    try:
        print(f"Downloading from {url}...")
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        block_size = 8192
        downloaded = 0
        
        with open(filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=block_size):
                f.write(chunk)
                downloaded += len(chunk)
                
                if total_size > 0:
                    done = int(50 * downloaded / total_size)
                    sys.stdout.write(f"\r[{'=' * done}{' ' * (50-done)}] {downloaded/1024/1024:.1f}/{total_size/1024/1024:.1f} MB")
                    sys.stdout.flush()
        
        if total_size > 0:
            print()  # New line after progress bar
            
        return True
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return False

def extract_openvas_data(json_file, debug=False):
    """
    Extract relevant data from OpenVAS JSON output.
    
    Args:
        json_file: Path to OpenVAS JSON file
        debug: Whether to print debug information
        
    Returns:
        List of dictionaries containing vulnerability data
    """
    print(f"Reading OpenVAS JSON data from {json_file}...")
    
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading JSON file: {e}")
        return []
    
    vulnerabilities = []
    
    if 'report' in data and 'results' in data['report']:
        results = data['report']['results'].get('result', [])
        if isinstance(results, dict):
            results = [results]
    elif 'results' in data:
        results = data['results'].get('result', [])
        if isinstance(results, dict):
            results = [results]
    else:
        print("Could not find results in OpenVAS JSON. Check the file structure.")
        return []
    
    print(f"Found {len(results)} vulnerability results")
    
    for result in results:
        vuln = {}
        
        vuln['nvt'] = result.get('nvt', {})
        vuln['cve_id'] = result.get('cve', '')
        if not vuln['cve_id']:
            refs = vuln['nvt'].get('refs', {}).get('ref', [])
            if isinstance(refs, dict):
                refs = [refs]
            for ref in refs:
                if ref.get('type') == 'cve':
                    vuln['cve_id'] = ref.get('id', '')
                    break
        
        vuln['cvss_v3_score'] = float(result.get('severity', 0.0))
        
        threat = result.get('threat', 'Unknown')
        vuln['original_threat'] = threat
        
        threat_map = {
            'Low': 0, 
            'Medium': 1, 
            'High': 2, 
            'Critical': 2
        }
        vuln['original_priority_category'] = threat_map.get(threat, 1)
        
        vuln['description'] = result.get('description', '')
        if not vuln['description'] and 'nvt' in result:
            vuln['description'] = result['nvt'].get('description', '')
        
        vuln['port'] = result.get('port', 'general')
        vuln['host'] = result.get('host', {}).get('ip', '')
        vuln['solution'] = result.get('solution', '')
        if not vuln['solution'] and 'nvt' in result:
            vuln['solution'] = result['nvt'].get('solution', {}).get('text', '')

        vuln['qod'] = None
        qod = result.get('qod', {})
        if isinstance(qod, dict):
            vuln['qod'] = qod.get('value', None)
        elif isinstance(qod, str) and qod.isdigit():
            vuln['qod'] = int(qod)
        
        vulnerabilities.append(vuln)
        
        if debug and len(vulnerabilities) <= 3:
            print(f"\nDEBUG - Sample vulnerability {len(vulnerabilities)}:")
            print(f"  CVE: {vuln['cve_id']}")
            print(f"  CVSS: {vuln['cvss_v3_score']}")
            print(f"  Threat: {vuln['original_threat']}")
            print(f"  Description: {vuln['description'][:100]}...")
    
    return vulnerabilities

def preprocess_openvas_data(vulnerabilities, debug=False):
    """
    Preprocess OpenVAS/NVD vulnerability data to match the model's expected features.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        debug: Whether to print debug information
        
    Returns:
        DataFrame with features matching the model's input requirements
    """
    print("Preprocessing data...")
    
    if not vulnerabilities:
        print("No vulnerabilities to process!")
        return pd.DataFrame()
    
    # Create DataFrame and add solution field
    df = pd.DataFrame(vulnerabilities)
    df['solution'] = df['nvt'].apply(lambda x: x.get('solution', {}).get('text', '') if isinstance(x, dict) else '')
    
    # Convert severity to cvss_v3_score
    df['cvss_v3_score'] = pd.to_numeric(df['severity'], errors='coerce').fillna(0.0)
    
    # Preserve original threat and map to priority categories
    df['original_threat'] = df['threat']
    threat_map = {
        'Low': 0,
        'Medium': 1,
        'High': 2,
        'Critical': 2
    }
    df['original_priority_category'] = df['threat'].map(threat_map).fillna(1)  # Default to Medium (1) if unknown
    
    descriptions = df['description'].fillna('').tolist()
    
    print("Loading Sentence Transformer model...")
    model = SentenceTransformer('all-MiniLM-L6-v2')
    
    print("Generating embeddings from descriptions...")
    embeddings = model.encode(descriptions, show_progress_bar=True)
    
    # Create all new columns at once to avoid fragmentation
    new_columns = {}
    
    # Add embedding columns
    for i in range(embeddings.shape[1]):
        new_columns[f'embed_{i}'] = embeddings[:, i]
    
    # Define all keyword patterns
    keyword_patterns = {
        'has_remote': r'remote|network|internet|web|http|https|ftp|ssh|telnet|smb|dns|port|url|protocol|tls|ssl',
        'has_os': r'windows|linux|ubuntu|centos|macos|unix|os\b|operating system|kernel|filesystem|system32|device driver|registry',
        'has_windows': r'windows|microsoft|win32|win64|powershell|\.net|activex|directx|ntfs|registry|COM\b|IIS\b',
        'has_linux': r'linux|ubuntu|debian|centos|redhat|unix|bash|shell|libc|glibc|systemd|SELinux|iptables',
        'has_execution': r'execution|exec|run|command|code execution|rce|arbitrary code|malicious code|shell|backdoor',
        'has_overflow': r'overflow|buffer|stack|heap|memory corruption|out-of-bounds|boundary|integer overflow|underflow',
        'has_injection': r'injection|sql|xss|script|cross-site|CSRF|command injection|code injection|format string',
        'has_privilege_escalation': r'privilege|escalation|elevation|root|admin|administrator|superuser|system|compromise',
        'has_auth_bypass': r'authentication|bypass|credentials|password|login|logout|session|token|identity',
        'has_info_disclosure': r'information disclosure|sensitive data|leak|expose|confidential|private|credentials',
        'has_update_available': r'update|upgrade|patch|latest version|fixed|fixes|secure version'
    }
    
    # Create all binary features at once
    for feature, pattern in keyword_patterns.items():
        new_columns[feature] = df['description'].str.contains(pattern, case=False, regex=True).astype(int)
    
    # Add port and network features
    new_columns['has_port'] = ((df['port'] != 'general') & (df['port'] != 'general/tcp')).astype(int)
    new_columns['has_network'] = (new_columns['has_remote'] | new_columns['has_port']).astype(int)
    new_columns['has_patch_available'] = (df['solution'].str.len() > 10).astype(int)
    
    # Add all new columns at once
    df = pd.concat([df, pd.DataFrame(new_columns, index=df.index)], axis=1)
    
    # Calculate CVSS scores and ratios
    df['cvss_v3_exploitability'] = np.nan
    df['cvss_v3_impact'] = np.nan
    
    high_exploit_mask = (
        (df['has_remote'] == 1) | 
        (df['has_execution'] == 1) | 
        (df['has_auth_bypass'] == 1)
    )
    medium_exploit_mask = (
        (df['has_injection'] == 1) | 
        (df['has_overflow'] == 1)
    )
    
    df.loc[high_exploit_mask, 'cvss_v3_exploitability'] = df.loc[high_exploit_mask, 'cvss_v3_score'] * 0.8
    df.loc[medium_exploit_mask, 'cvss_v3_exploitability'] = df.loc[medium_exploit_mask, 'cvss_v3_score'] * 0.6
    df.loc[df['cvss_v3_exploitability'].isna(), 'cvss_v3_exploitability'] = df.loc[df['cvss_v3_exploitability'].isna(), 'cvss_v3_score'] * 0.5
    
    high_impact_mask = (
        (df['has_privilege_escalation'] == 1) | 
        (df['has_execution'] == 1)
    )
    medium_impact_mask = (
        (df['has_info_disclosure'] == 1) | 
        (df['has_injection'] == 1)
    )
    
    df.loc[high_impact_mask, 'cvss_v3_impact'] = df.loc[high_impact_mask, 'cvss_v3_score'] * 0.9
    df.loc[medium_impact_mask, 'cvss_v3_impact'] = df.loc[medium_impact_mask, 'cvss_v3_score'] * 0.7
    df.loc[df['cvss_v3_impact'].isna(), 'cvss_v3_impact'] = df.loc[df['cvss_v3_impact'].isna(), 'cvss_v3_score'] * 0.4
    
    df['exploit_to_impact_ratio'] = df['cvss_v3_exploitability'] / (df['cvss_v3_impact'] + 0.1)
    
    df['cvss_v3_exploitability'] = df['cvss_v3_exploitability'].clip(0.0, 10.0)
    df['cvss_v3_impact'] = df['cvss_v3_impact'].clip(0.0, 10.0)
    df['exploit_to_impact_ratio'] = df['exploit_to_impact_ratio'].clip(0.1, 10.0)
    
    df['severity_score_normalized'] = df['cvss_v3_score'] / 10.0
    
    df['cvss_severity_indicator'] = 0
    df.loc[df['cvss_v3_score'] >= 4.0, 'cvss_severity_indicator'] = 1
    df.loc[df['cvss_v3_score'] >= 7.0, 'cvss_severity_indicator'] = 2
    df.loc[df['cvss_v3_score'] >= 9.0, 'cvss_severity_indicator'] = 2
    
    if debug:
        print("\nDEBUG - Feature statistics:")
        for col in df.columns:
            if col.startswith('has_') or col.startswith('cvss_') or col == 'severity_score_normalized':
                if df[col].dtype in [np.int64, np.float64, int, float]:
                    print(f"  {col}: mean={df[col].mean():.3f}, std={df[col].std():.3f}, min={df[col].min()}, max={df[col].max()}")
        
        print("\nDEBUG - Sample row features:")
        for i in range(min(3, len(df))):
            row = df.iloc[i]
            print(f"\nSample {i+1}: {row.get('cve_id', 'Unknown CVE')} (Original: {row.get('original_threat', 'Unknown')})")
            print(f"  CVSS: {row.get('cvss_v3_score', 0):.1f}")
            print(f"  Exploitability: {row.get('cvss_v3_exploitability', 0):.2f}")
            print(f"  Impact: {row.get('cvss_v3_impact', 0):.2f}")
            print(f"  Network: has_remote={row.get('has_remote', 0)}, has_network={row.get('has_network', 0)}")
            print(f"  Vulnerability: execution={row.get('has_execution', 0)}, overflow={row.get('has_overflow', 0)}, injection={row.get('has_injection', 0)}")
            print(f"  Severity: privilege={row.get('has_privilege_escalation', 0)}, auth_bypass={row.get('has_auth_bypass', 0)}")
    
    return df

def predict_severity(df, model_path, debug=False, train_model=False):
    """
    Use the trained model to predict vulnerability severity or train a new model.
    
    Args:
        df: DataFrame with preprocessed features
        model_path: Path to trained model file
        debug: Whether to print debug information
        train_model: Whether to train a new model
        
    Returns:
        DataFrame with predictions added
    """
    embed_cols = [f'embed_{i}' for i in range(384)]
    core_features = [
        'cvss_v3_score',
        'cvss_v3_exploitability',
        'cvss_v3_impact',
        'exploit_to_impact_ratio',
        'has_patch_available',
        'has_remote',
        'has_port',
        'has_network',
        'has_os',
        'has_windows',
        'has_linux',
        'has_execution',
        'has_overflow',
        'has_injection'
    ]
    additional_features = [
        'has_privilege_escalation',
        'has_auth_bypass',
        'has_info_disclosure',
        'has_update_available',
        'severity_score_normalized',
        'cvss_severity_indicator'
    ]
    model_features = embed_cols + core_features
    
    for feature in model_features:
        if feature not in df.columns:
            if feature.startswith('embed_'):
                df[feature] = 0.5
            else:
                df[feature] = 0
    
    X = df[model_features]
    y = df['original_priority_category']
    
    if train_model:
        print("Training a new RandomForest model...")
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        model.fit(X_train, y_train)
        
        print("Evaluating model performance...")
        y_pred = model.predict(X_test)
        print(classification_report(y_test, y_pred, target_names=['Low', 'Medium', 'High/Critical']))
        
        print(f"Saving trained model to {model_path}...")
        joblib.dump(model, model_path)
    else:
        print(f"Loading trained model from {model_path}...")
        try:
            model = joblib.load(model_path)
        except Exception as e:
            print(f"Error loading model: {e}")
            return df
    
    print("Predicting vulnerability severity...")
    if debug:
        print(f"\nDEBUG - Feature set for prediction: {len(model_features)} features")
        print(f"  Embedding features: {len(embed_cols)}")
        print(f"  Non-embedding features: {len(core_features)}")
        nan_cols = X.columns[X.isna().any()].tolist()
        if nan_cols:
            print(f"  WARNING: NaN values found in columns: {nan_cols}")
            X = X.fillna(0)
    
    y_pred_proba = model.predict_proba(X)
    y_pred = model.predict(X)
    
    df['predicted_priority_category'] = y_pred
    for i in range(y_pred_proba.shape[1]):
        df[f'probability_class_{i}'] = y_pred_proba[:, i]
    
    severity_map = {
        0: 'Low',
        1: 'Medium',
        2: 'High/Critical'
    }
    df['predicted_severity'] = df['predicted_priority_category'].map(severity_map)
    df['prediction_confidence'] = y_pred_proba.max(axis=1)
    df['severity_changed'] = (df['predicted_priority_category'] != df['original_priority_category']).astype(int)
    df['significant_change'] = (abs(df['predicted_priority_category'] - df['original_priority_category']) > 1).astype(int)
    df['cvss_based_severity'] = 'Low'
    df.loc[df['cvss_v3_score'] >= 4.0, 'cvss_based_severity'] = 'Medium'
    df.loc[df['cvss_v3_score'] >= 7.0, 'cvss_based_severity'] = 'High/Critical'
    df['disagrees_with_cvss'] = (
        ((df['cvss_v3_score'] >= 7.0) & (df['predicted_priority_category'] == 0)) | 
        ((df['cvss_v3_score'] < 4.0) & (df['predicted_priority_category'] == 2))
    ).astype(int)
    
    if debug:
        print("\nDEBUG - Prediction distribution:")
        print(df['predicted_severity'].value_counts())
        print("\nDEBUG - Confidence statistics:")
        print(f"  Mean: {df['prediction_confidence'].mean():.3f}")
        print(f"  Min: {df['prediction_confidence'].min():.3f}")
        print(f"  Max: {df['prediction_confidence'].max():.3f}")
        disagree_count = df['disagrees_with_cvss'].sum()
        if disagree_count > 0:
            print(f"\nDEBUG - {disagree_count} predictions disagree significantly with CVSS-based severity")
        print("\nDEBUG - Sample predictions:")
        for i in range(min(5, len(df))):
            row = df.iloc[i]
            print(f"  CVE: {row.get('cve_id', 'Unknown')}")
            print(f"    CVSS: {row.get('cvss_v3_score', 0):.1f}, CVSS-based: {row.get('cvss_based_severity', 'Unknown')}")
            print(f"    Original: {row.get('original_threat', 'Unknown')}, Predicted: {row.get('predicted_severity', 'Unknown')}")
            print(f"    Confidence: {row.get('prediction_confidence', 0):.2f}")
            print(f"    Key features: remote={row.get('has_remote', 0)}, execution={row.get('has_execution', 0)}, privilege={row.get('has_privilege_escalation', 0)}")
    
    return df

def fallback_cvss_based_severity(df):
    """Apply CVSS-based severity as a fallback for low-confidence predictions"""
    low_confidence_mask = df['prediction_confidence'] < 0.6
    cvss_severity = pd.Series(index=df.index, dtype=int)
    cvss_severity.loc[:] = 0
    cvss_severity.loc[df['cvss_v3_score'] >= 4.0] = 1
    cvss_severity.loc[df['cvss_v3_score'] >= 7.0] = 2
    df.loc[low_confidence_mask, 'predicted_priority_category'] = cvss_severity.loc[low_confidence_mask]
    severity_map = {
        0: 'Low',
        1: 'Medium',
        2: 'High/Critical'
    }
    df.loc[low_confidence_mask, 'predicted_severity'] = df.loc[low_confidence_mask, 'predicted_priority_category'].map(severity_map)
    df['used_fallback'] = 0
    df.loc[low_confidence_mask, 'used_fallback'] = 1
    return df

def enhanced_calibration(df):
    """Apply enhanced calibration rules to fix common misclassification patterns"""
    # Create a copy
    fixed_df = df.copy()
    
    # Rule 1: Never let high CVSS scores be classified as Low
    high_cvss_mask = (df['cvss_v3_score'] >= 7.0) & (df['predicted_priority_category'] == 0)
    fixed_df.loc[high_cvss_mask, 'predicted_priority_category'] = 2  # High/Critical
    fixed_df.loc[high_cvss_mask, 'predicted_severity'] = 'High/Critical'
    
    # Rule 2: Never let authentication bypass vulnerabilities be classified as Low
    auth_mask = df['description'].str.contains('authentication bypass', case=False, na=False) & (df['predicted_priority_category'] == 0)
    fixed_df.loc[auth_mask, 'predicted_priority_category'] = 1  # Medium
    fixed_df.loc[auth_mask, 'predicted_severity'] = 'Medium'
    
    # Rule 3: Be more conservative with buffer overflow vulnerabilities
    overflow_mask = df['description'].str.contains('buffer overflow', case=False, na=False) & (df['predicted_priority_category'] == 0)
    fixed_df.loc[overflow_mask, 'predicted_priority_category'] = 1  # Medium
    fixed_df.loc[overflow_mask, 'predicted_severity'] = 'Medium'
    
    # Rule 4: Increase confidence for newer vulnerabilities (2023+)
    year_mask = df['cve_id'].str.contains(r'CVE-(202[3-5])', case=False, na=False, regex=True)
    cvss_priority = df.loc[year_mask, 'cvss_v3_score'].apply(lambda score: 
                                                            2 if score >= 7.0 else 
                                                            1 if score >= 4.0 else 0)
    
    new_year_mask = year_mask & (df['prediction_confidence'] < 0.45)
    fixed_df.loc[new_year_mask, 'predicted_priority_category'] = cvss_priority[new_year_mask.index]
    fixed_df.loc[new_year_mask, 'predicted_severity'] = fixed_df.loc[new_year_mask, 'predicted_priority_category'].map({
        0: 'Low', 1: 'Medium', 2: 'High/Critical'
    })
    
    # Count changes made by enhanced calibration
    changes = (fixed_df['predicted_priority_category'] != df['predicted_priority_category']).sum()
    print(f"Enhanced calibration made {changes} changes to predictions")
    
    return fixed_df

def visualize_results(df, output_dir, source_name):
    """Create visualizations of prediction results"""
    viz_dir = os.path.join(output_dir, "visualizations")
    os.makedirs(viz_dir, exist_ok=True)
    
    plt.figure(figsize=(12, 6))
    original_counts = df['original_threat'].value_counts().sort_index()
    predicted_counts = df['predicted_severity'].value_counts().sort_index()
    
    # Create a consistent set of categories
    all_categories = sorted(set(original_counts.index) | set(predicted_counts.index))
    
    # Initialize arrays with zeros
    original_values = np.zeros(len(all_categories))
    predicted_values = np.zeros(len(all_categories))
    
    # Fill in the values we have
    for i, cat in enumerate(all_categories):
        if cat in original_counts:
            original_values[i] = original_counts[cat]
        if cat in predicted_counts:
            predicted_values[i] = predicted_counts[cat]
    
    x = np.arange(len(all_categories))
    width = 0.35
    plt.bar(x - width/2, original_values, width, label='Original OpenVAS')
    plt.bar(x + width/2, predicted_values, width, label='Model Prediction')
    plt.xlabel('Severity Level')
    plt.ylabel('Number of Vulnerabilities')
    plt.title('Comparison of Original vs. Predicted Severity')
    plt.xticks(x, all_categories)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(viz_dir, f"{source_name}_severity_comparison.png"))
    plt.close()
    
    plt.figure(figsize=(10, 6))
    sns.violinplot(x='predicted_severity', y='cvss_v3_score', data=df, palette='viridis')
    plt.axhline(y=4.0, color='orange', linestyle='--', alpha=0.7, label='Low/Medium Threshold')
    plt.axhline(y=7.0, color='red', linestyle='--', alpha=0.7, label='Medium/High Threshold')
    plt.xlabel('Predicted Severity')
    plt.ylabel('CVSS Score')
    plt.title('CVSS Score Distribution by Predicted Severity')
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(viz_dir, f"{source_name}_cvss_distribution.png"))
    plt.close()
    
    plt.figure(figsize=(10, 6))
    sns.boxplot(x='predicted_severity', y='prediction_confidence', data=df, palette='viridis')
    plt.axhline(y=0.6, color='red', linestyle='--', alpha=0.7, label='Fallback Threshold')
    plt.xlabel('Predicted Severity')
    plt.ylabel('Prediction Confidence')
    plt.title('Model Confidence by Severity Level')
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(viz_dir, f"{source_name}_confidence_levels.png"))
    plt.close()
    
    if 'High/Critical' in df['predicted_severity'].values:
        high_severity = df[df['predicted_severity'] == 'High/Critical'].sort_values('cvss_v3_score', ascending=False).head(10)
        plt.figure(figsize=(12, len(high_severity)*0.8))
        table_data = []
        for _, row in high_severity.iterrows():
            cve_id = row.get('cve_id', 'Unknown')
            if not cve_id or cve_id == 'Unknown':
                cve_id = row.get('nvt', {}).get('name', 'Unknown')[:20]
            table_data.append([
                cve_id,
                f"{row['cvss_v3_score']:.1f}",
                row['original_threat'],
                row['predicted_severity'],
                f"{row['prediction_confidence']:.2f}"
            ])
        table = plt.table(
            cellText=table_data,
            colLabels=['CVE/Vuln', 'CVSS', 'Original', 'Predicted', 'Confidence'],
            loc='center',
            cellLoc='center'
        )
        table.auto_set_font_size(False)
        table.set_fontsize(10)
        table.scale(1, 1.5)
        plt.axis('off')
        plt.title('Top High Severity Vulnerabilities')
        plt.tight_layout()
        plt.savefig(os.path.join(viz_dir, f"{source_name}_top_vulnerabilities.png"))
        plt.close()
    
    return viz_dir

def generate_report(df, output_dir, source_name, viz_dir):
    """Generate an HTML report of vulnerability findings"""
    report_file = os.path.join(output_dir, f"{source_name}_report.html")
    total_vulns = len(df)
    severity_counts = df['predicted_severity'].value_counts()
    low_count = severity_counts.get('Low', 0)
    medium_count = severity_counts.get('Medium', 0)
    high_count = severity_counts.get('High/Critical', 0)
    changes = df['severity_changed'].sum()
    significant_changes = df['significant_change'].sum()
    fallbacks = df['used_fallback'].sum()
    top_high = df[df['predicted_severity'] == 'High/Critical'].sort_values('cvss_v3_score', ascending=False).head(10)
    top_medium = df[df['predicted_severity'] == 'Medium'].sort_values('cvss_v3_score', ascending=False).head(5)
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerability Analysis Report - {source_name}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
            h1, h2, h3 {{ color: #333; }}
            .summary-box {{ background-color: #f8f9fa; border-radius: 5px; padding: 15px; margin-bottom: 20px; }}
            .severity-high {{ color: #dc3545; }}
            .severity-medium {{ color: #fd7e14; }}
            .severity-low {{ color: #28a745; }}
            .note-box {{ background-color: #e9f5ff; border-radius: 5px; padding: 15px; margin-bottom: 20px; border-left: 4px solid #0d6efd; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f2f2f2; }}
            tr:hover {{ background-color: #f5f5f5; }}
            .chart-container {{ margin: 20px 0; text-align: center; }}
            .chart {{ max-width: 100%; height: auto; border: 1px solid #ddd; }}
        </style>
    </head>
    <body>
        <h1>Vulnerability Analysis Report</h1>
        <p>Source: {source_name}</p>
        <p>Analysis Date: {time.strftime('%Y-%m-%d %H:%M')}</p>
        
        <div class="note-box">
            <h3>Model Calibration Note</h3>
            <p>This report applies enhanced calibration rules to ensure consistent severity ratings. Special attention is given to:</p>
            <ul>
                <li>Authentication bypass vulnerabilities</li>
                <li>Buffer overflow vulnerabilities</li>
                <li>Newer vulnerabilities (2023+)</li>
                <li>Vulnerabilities with high CVSS scores</li>
            </ul>
        </div>
        
        <div class="summary-box">
            <h2>Executive Summary</h2>
            <p>Total vulnerabilities analyzed: <strong>{total_vulns}</strong></p>
            <ul>
                <li><span class="severity-high"><strong>High/Critical severity:</strong></span> {high_count} ({high_count/total_vulns*100:.1f}%)</li>
                <li><span class="severity-medium"><strong>Medium severity:</strong></span> {medium_count} ({medium_count/total_vulns*100:.1f}%)</li>
                <li><span class="severity-low"><strong>Low severity:</strong></span> {low_count} ({low_count/total_vulns*100:.1f}%)</li>
            </ul>
            <p><strong>{changes}</strong> vulnerabilities ({changes/total_vulns*100:.1f}%) were reclassified from their original severity.</p>
            <p><strong>{significant_changes}</strong> vulnerabilities ({significant_changes/total_vulns*100:.1f}%) had significant severity changes.</p>
            <p><strong>{fallbacks}</strong> vulnerabilities ({fallbacks/total_vulns*100:.1f}%) used CVSS-based fallback.</p>
        </div>
        
        <div class="chart-container">
            <h2>Severity Distribution</h2>
            <img class="chart" src="visualizations/{source_name}_severity_comparison.png" alt="Severity Distribution">
        </div>
        
        <div class="chart-container">
            <h2>CVSS Score Distribution</h2>
            <img class="chart" src="visualizations/{source_name}_cvss_distribution.png" alt="CVSS Distribution">
        </div>
        
        <div class="chart-container">
            <h2>Model Confidence</h2>
            <img class="chart" src="visualizations/{source_name}_confidence_levels.png" alt="Model Confidence">
        </div>
    """
    
    if len(top_high) > 0:
        html_content += f"""
        <h2>Top High/Critical Severity Vulnerabilities</h2>
        <table>
            <tr>
                <th>CVE/Vulnerability</th>
                <th>CVSS</th>
                <th>Description</th>
                <th>Original</th>
                <th>Predicted</th>
                <th>Confidence</th>
            </tr>
        """
        for _, row in top_high.iterrows():
            cve_id = row.get('cve_id', 'Unknown')
            if not cve_id or cve_id == 'Unknown':
                cve_id = row.get('nvt', {}).get('name', 'Unknown')[:30]
            description = row.get('description', '')[:150] + '...' if row.get('description', '') else 'No description available'
            html_content += f"""
            <tr>
                <td>{cve_id}</td>
                <td>{row['cvss_v3_score']:.1f}</td>
                <td>{description}</td>
                <td>{row['original_threat']}</td>
                <td class="severity-high">{row['predicted_severity']}</td>
                <td>{row['prediction_confidence']:.2f}</td>
            </tr>
            """
        html_content += "</table>"
    
    if len(top_medium) > 0:
        html_content += f"""
        <h2>Top Medium Severity Vulnerabilities</h2>
        <table>
            <tr>
                <th>CVE/Vulnerability</th>
                <th>CVSS</th>
                <th>Description</th>
                <th>Original</th>
                <th>Predicted</th>
                <th>Confidence</th>
            </tr>
        """
        for _, row in top_medium.iterrows():
            cve_id = row.get('cve_id', 'Unknown')
            if not cve_id or cve_id == 'Unknown':
                cve_id = row.get('nvt', {}).get('name', 'Unknown')[:30]
            description = row.get('description', '')[:150] + '...' if row.get('description', '') else 'No description available'
            html_content += f"""
            <tr>
                <td>{cve_id}</td>
                <td>{row['cvss_v3_score']:.1f}</td>
                <td>{description}</td>
                <td>{row['original_threat']}</td>
                <td class="severity-medium">{row['predicted_severity']}</td>
                <td>{row['prediction_confidence']:.2f}</td>
            </tr>
            """
        html_content += "</table>"
    
    significant_changes_df = df[df['significant_change'] == 1].sort_values('cvss_v3_score', ascending=False).head(10)
    if len(significant_changes_df) > 0:
        html_content += f"""
        <h2>Significant Severity Changes</h2>
        <p>These vulnerabilities had their severity significantly changed from the original assessment:</p>
        <table>
            <tr>
                <th>CVE/Vulnerability</th>
                <th>CVSS</th>
                <th>Original</th>
                <th>Predicted</th>
                <th>Confidence</th>
            </tr>
        """
        for _, row in significant_changes_df.iterrows():
            cve_id = row.get('cve_id', 'Unknown')
            if not cve_id or cve_id == 'Unknown':
                cve_id = row.get('nvt', {}).get('name', 'Unknown')[:30]
            severity_class = "severity-high" if row['predicted_severity'] == 'High/Critical' else \
                            "severity-medium" if row['predicted_severity'] == 'Medium' else "severity-low"
            html_content += f"""
            <tr>
                <td>{cve_id}</td>
                <td>{row['cvss_v3_score']:.1f}</td>
                <td>{row['original_threat']}</td>
                <td class="{severity_class}">{row['predicted_severity']}</td>
                <td>{row['prediction_confidence']:.2f}</td>
            </tr>
            """
        html_content += "</table>"
    
    html_content += """
        <h2>Next Steps</h2>
        <ol>
            <li>Prioritize remediation of High/Critical vulnerabilities</li>
            <li>Schedule fixes for Medium vulnerabilities based on business impact</li>
            <li>Document and monitor Low vulnerabilities</li>
            <li>Consider regular scanning and reassessment</li>
        </ol>
        <p style="margin-top: 40px; color: #666; font-size: 0.9em;">This report was generated by the AI-Driven Vulnerability Prioritization and Remediation System.</p>
    </body>
    </html>
    """
    
    with open(report_file, 'w') as f:
        f.write(html_content)
    
    return report_file

def convert_openvas_format(input_file, output_file=None):
    """
    Convert OpenVAS XML-to-JSON format to the expected format for processing.
    
    Args:
        input_file: Path to the input JSON file
        output_file: Path to save the converted JSON file (if None, will use input_file with _converted suffix)
    
    Returns:
        Path to the converted file
    """
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Initialize the new structure
        converted = {
            "report": {
                "results": {
                    "result": []
                }
            }
        }
        
        # Try to find results in different possible locations
        results = []
        if 'report' in data:
            if 'results' in data['report']:
                if 'result' in data['report']['results']:
                    results = data['report']['results']['result']
        elif 'results' in data:
            if 'result' in data['results']:
                results = data['results']['result']
        
        # If no results found, try to find them in other common locations
        if not results:
            for key in ['report_results', 'results', 'report']:
                if key in data:
                    if isinstance(data[key], list):
                        results = data[key]
                        break
                    elif isinstance(data[key], dict):
                        for subkey in ['result', 'results']:
                            if subkey in data[key]:
                                if isinstance(data[key][subkey], list):
                                    results = data[key][subkey]
                                    break
        
        if not results:
            print("Could not find results in the input file. Please check the file structure.")
            return None
        
        # Convert each result to the expected format
        for result in results:
            new_result = {}
            
            # Extract basic information
            new_result['severity'] = str(result.get('severity', result.get('cvss_base_score', '0.0')))
            new_result['threat'] = result.get('threat', result.get('severity', 'Medium'))
            new_result['description'] = result.get('description', result.get('summary', ''))
            new_result['port'] = result.get('port', 'general/tcp')
            new_result['host'] = {"ip": result.get('host', {}).get('ip', '192.168.1.1')}
            new_result['qod'] = {"value": str(result.get('qod', {}).get('value', '90'))}
            
            # Handle CVE information
            cve_id = result.get('cve', '')
            if not cve_id:
                refs = result.get('refs', {}).get('ref', [])
                if isinstance(refs, dict):
                    refs = [refs]
                for ref in refs:
                    if ref.get('type') == 'cve':
                        cve_id = ref.get('id', '')
                        break
            new_result['cve'] = cve_id
            
            # Handle NVT information
            nvt = result.get('nvt', {})
            if not nvt:
                nvt = {
                    "name": result.get('name', 'Unknown vulnerability'),
                    "description": result.get('description', ''),
                    "solution": {
                        "text": result.get('solution', '')
                    },
                    "refs": {
                        "ref": []
                    }
                }
                if cve_id:
                    nvt['refs']['ref'].append({"id": cve_id, "type": "cve"})
            new_result['nvt'] = nvt
            
            converted['report']['results']['result'].append(new_result)
        
        # Save the converted file
        if output_file is None:
            base, ext = os.path.splitext(input_file)
            output_file = f"{base}_converted{ext}"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(converted, f, indent=2)
        
        print(f"Successfully converted file. Saved to: {output_file}")
        return output_file
    
    except Exception as e:
        print(f"Error converting file: {e}")
        return None

def convert_xml_to_json(xml_file, output_file=None):
    """
    Convert OpenVAS XML file to the expected JSON format for processing.
    
    Args:
        xml_file: Path to the input XML file
        output_file: Path to save the converted JSON file (if None, will use xml_file with .json extension)
    
    Returns:
        Path to the converted file
    """
    try:
        import xml.etree.ElementTree as ET
        
        print(f"Reading XML file: {xml_file}")
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        # Initialize the new structure
        converted = {
            "report": {
                "results": {
                    "result": []
                }
            }
        }
        
        # Find all results in the XML
        # Try different possible XML structures
        results = []
        
        # Try to find results in different possible locations
        for result_path in [
            './/result',  # Direct result elements
            './/report/results/result',  # Nested in report/results
            './/report_result',  # Alternative naming
            './/vulnerability',  # Alternative naming
            './/finding'  # Alternative naming
        ]:
            results = root.findall(result_path)
            if results:
                break
        
        if not results:
            print("Could not find results in the XML file. Please check the file structure.")
            return None
        
        print(f"Found {len(results)} results in XML file")
        
        # Convert each result to the expected format
        for result in results:
            new_result = {}
            
            # Extract basic information
            new_result['severity'] = str(result.get('severity', result.get('cvss_base_score', '0.0')))
            new_result['threat'] = result.get('threat', result.get('severity', 'Medium'))
            
            # Get description from different possible locations
            description = ''
            for desc_path in ['description', 'summary', 'details', 'nvt/description']:
                desc_elem = result.find(desc_path)
                if desc_elem is not None:
                    description = desc_elem.text or ''
                    if description:
                        break
            new_result['description'] = description
            
            # Get port information
            port = result.get('port', 'general/tcp')
            if port == 'general':
                port = 'general/tcp'
            new_result['port'] = port
            
            # Get host information
            host_ip = '192.168.1.1'
            host_elem = result.find('host')
            if host_elem is not None:
                host_ip = host_elem.get('ip', host_ip)
            new_result['host'] = {"ip": host_ip}
            
            # Get QoD (Quality of Detection)
            qod = result.get('qod', '90')
            new_result['qod'] = {"value": str(qod)}
            
            # Handle CVE information
            cve_id = ''
            for ref in result.findall('.//ref'):
                if ref.get('type') == 'cve':
                    cve_id = ref.get('id', '')
                    break
            new_result['cve'] = cve_id
            
            # Handle NVT information
            nvt = {
                "name": result.get('name', 'Unknown vulnerability'),
                "description": description,
                "solution": {
                    "text": result.get('solution', '')
                },
                "refs": {
                    "ref": []
                }
            }
            
            # Add CVE reference if available
            if cve_id:
                nvt['refs']['ref'].append({"id": cve_id, "type": "cve"})
            
            new_result['nvt'] = nvt
            converted['report']['results']['result'].append(new_result)
        
        # Save the converted file
        if output_file is None:
            output_file = os.path.splitext(xml_file)[0] + '.json'
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(converted, f, indent=2)
        
        print(f"Successfully converted XML to JSON. Saved to: {output_file}")
        return output_file
    
    except Exception as e:
        print(f"Error converting XML file: {e}")
        return None

def process_custom_scan(scan_file, output_dir, model_path, debug=False, train_model=False):
    """Process a custom OpenVAS scan file"""
    print(f"\n{'='*60}")
    print(f"Processing custom OpenVAS scan file: {scan_file}")
    print(f"{'='*60}")
    
    if not os.path.exists(scan_file):
        print(f"Error: Scan file {scan_file} does not exist")
        return None
    
    try:
        # Check if the file is XML or JSON
        file_ext = os.path.splitext(scan_file)[1].lower()
        converted_file = None
        
        if file_ext == '.xml':
            # Convert XML to JSON
            converted_file = convert_xml_to_json(scan_file)
        else:
            # Convert JSON to expected format
            converted_file = convert_openvas_format(scan_file)
        
        if not converted_file:
            print("Failed to convert the scan file to the expected format")
            return None
        
        vulnerabilities = extract_openvas_data(converted_file, debug)
        if not vulnerabilities:
            print(f"No vulnerability data found in {scan_file}")
            return None
        
        df = preprocess_openvas_data(vulnerabilities, debug)
        if df.empty:
            print(f"Failed to preprocess data from {scan_file}")
            return None
        
        results = predict_severity(df, model_path, debug, train_model)
        results = fallback_cvss_based_severity(results)
        results = enhanced_calibration(results)
        
        # Use the scan filename (without extension) as the source name
        source_name = os.path.splitext(os.path.basename(scan_file))[0]
        
        output_csv = os.path.join(output_dir, f"{source_name}_processed.csv")
        results.to_csv(output_csv, index=False)
        print(f"Results saved to {output_csv}")
        
        viz_dir = visualize_results(results, output_dir, source_name)
        print(f"Visualizations saved to {viz_dir}")
        
        report_file = generate_report(results, output_dir, source_name, viz_dir)
        print(f"HTML report saved to {report_file}")
        
        print("\nSEVERITY PREDICTION SUMMARY:")
        print("============================")
        print(f"Total vulnerabilities: {len(results)}")
        original_counts = results['original_threat'].value_counts()
        print("\nOriginal severity distribution:")
        for threat, count in original_counts.items():
            print(f"  {threat}: {count} ({count/len(results)*100:.1f}%)")
        predicted_counts = results['predicted_severity'].value_counts()
        print("\nPredicted severity distribution:")
        for threat, count in predicted_counts.items():
            print(f"  {threat}: {count} ({count/len(results)*100:.1f}%)")
        
        return results
    except Exception as e:
        print(f"Error processing custom scan file: {e}")
        return None

def download_and_process_data(args):
    """Main function to download and process OpenVAS and NVD data"""
    WORK_DIR = "C:/Users/cb26h/Desktop/pipeline/pipeline"
    output_dir = os.path.join(WORK_DIR, args.output_dir)
    os.makedirs(output_dir, exist_ok=True)
    print(f"Downloading and processing data to {output_dir}")
    
    # Latest year and 3 random past years
    sources = [
        {
            "name": "nvd_2025",
            "url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2025.json.gz",
            "type": "nvd"
        },
    ]
    
    processed_files = []
    successful_sources = 0
    total_vulnerabilities = 0
    all_vulnerabilities = []
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        for source in sources:
            print(f"\n{'='*60}")
            print(f"Processing {source['name']} from {source['url']}")
            print(f"{'='*60}")
            
            try:
                if source['type'] == 'nvd':
                    nvd_file = temp_path / f"{source['name']}.json.gz"
                    if download_file(source['url'], nvd_file):
                        print("Converting NVD data to OpenVAS format...")
                        with gzip.open(nvd_file, 'rt', encoding='utf-8') as f:
                            nvd_data = json.load(f)
                        
                        cve_items = nvd_data.get('CVE_Items', [])
                        print(f"Found {len(cve_items)} CVEs in NVD data")
                        
                        if len(cve_items) > 0:
                            results = []
                            for item in cve_items:
                                try:
                                    cve_id = item['cve']['CVE_data_meta']['ID']
                                    description_data = item['cve']['description']['description_data']
                                    description = next((d['value'] for d in description_data if d['lang'] == 'en'), "")
                                    if not description:
                                        continue
                                    impact = item.get('impact', {})
                                    if not impact:
                                        continue
                                    base_score = None
                                    severity_type = None
                                    if 'baseMetricV3' in impact:
                                        base_score = impact['baseMetricV3']['cvssV3']['baseScore']
                                        severity_type = impact['baseMetricV3']['cvssV3']['baseSeverity']
                                    elif 'baseMetricV2' in impact:
                                        base_score = impact['baseMetricV2']['cvssV2']['baseScore']
                                        severity_type = impact['baseMetricV2']['severity']
                                    if base_score is None:
                                        continue
                                    threat_map = {
                                        'NONE': 'Low',
                                        'LOW': 'Low',
                                        'MEDIUM': 'Medium',
                                        'HIGH': 'High',
                                        'CRITICAL': 'Critical'
                                    }
                                    threat = threat_map.get(severity_type.upper(), 'Medium')
                                    solution = "Update affected software to the latest version."
                                    result = {
                                        "cve": cve_id,
                                        "severity": str(base_score),
                                        "threat": threat,
                                        "description": description,  # Add description directly to result
                                        "nvt": {
                                            "name": f"{cve_id} vulnerability",
                                            "description": description,
                                            "solution": {
                                                "text": solution
                                            },
                                            "refs": {
                                                "ref": [
                                                    {"id": cve_id, "type": "cve"}
                                                ]
                                            }
                                        },
                                        "port": "general/tcp",
                                        "host": {"ip": "192.168.1.1"},
                                        "qod": {"value": "90"}
                                    }
                                    network_ports = ["80/tcp", "443/tcp", "22/tcp", "21/tcp", "25/tcp", "3389/tcp"]
                                    if any(word in description.lower() for word in ['web', 'http', 'server', 'network', 'ssl', 'tls', 'ssh', 'ftp']):
                                        result['port'] = network_ports[hash(cve_id) % len(network_ports)]
                                    results.append(result)
                                except Exception as e:
                                    print(f"Error processing CVE: {e}")
                                    continue
                            
                            openvas_data = {
                                "report": {
                                    "results": {
                                        "result": results
                                    }
                                }
                            }
                            json_file = os.path.join(output_dir, f"{source['name']}.json")
                            with open(json_file, 'w') as f:
                                json.dump(openvas_data, f, indent=2)
                            print(f"Created NVD-based OpenVAS report with {len(results)} vulnerabilities")
                            successful_sources += 1
                            total_vulnerabilities += len(results)
                            processed_files.append(('nvd', source['name'], json_file))
                            all_vulnerabilities.extend(results)
                        else:
                            print("No CVE items found in NVD data")
                    else:
                        print("Failed to download NVD data")
            except Exception as e:
                print(f"Error processing {source['name']}: {e}")
        
        if successful_sources == 0:
            print("\nNo successful data sources. Creating minimal test data...")
            sample_cves = [
                {"id": "CVE-2021-44228", "desc": "Log4j Remote Code Execution Vulnerability", "score": 10.0, "threat": "Critical"},
                {"id": "CVE-2020-1472", "desc": "Netlogon Elevation of Privilege Vulnerability (Zerologon)", "score": 10.0, "threat": "Critical"},
                {"id": "CVE-2019-0708", "desc": "Remote Desktop Services Remote Code Execution Vulnerability (BlueKeep)", "score": 9.8, "threat": "Critical"},
                {"id": "CVE-2017-0144", "desc": "SMB Remote Code Execution Vulnerability (EternalBlue)", "score": 9.3, "threat": "Critical"},
                {"id": "CVE-2022-3786", "desc": "OpenSSL X.509 Email Address Buffer Overflow", "score": 7.5, "threat": "High"},
            ]
            results = []
            for cve in sample_cves:
                is_network = "Remote" in cve["desc"] or "SMB" in cve["desc"]
                port = "445/tcp" if "SMB" in cve["desc"] else "general/tcp"
                solution = "Apply the latest security patches for the affected software."
                full_desc = f"A vulnerability in {cve['desc'].split(' ')[0]} could allow an attacker to {cve['desc'].lower()}. "
                full_desc += "This may lead to unauthorized access, information disclosure, or complete system compromise."
                result = {
                    "cve": cve["id"],
                    "severity": str(cve["score"]),
                    "threat": cve["threat"],
                    "nvt": {
                        "name": f"{cve['id']} - {cve['desc']}",
                        "description": full_desc,
                        "solution": {
                            "text": solution
                        },
                        "refs": {
                            "ref": [
                                {"id": cve["id"], "type": "cve"}
                            ]
                        }
                    },
                    "port": port,
                    "host": {"ip": "192.168.1.1"},
                    "qod": {"value": "90"}
                }
                results.append(result)
            openvas_data = {
                "report": {
                    "results": {
                        "result": results
                    }
                }
            }
            source_name = "minimal_sample"
            json_file = os.path.join(output_dir, f"{source_name}.json")
            with open(json_file, 'w') as f:
                json.dump(openvas_data, f, indent=2)
            print(f"Created minimal OpenVAS sample with {len(results)} vulnerabilities")
            successful_sources += 1
            total_vulnerabilities += len(results)
            processed_files.append(('manual', source_name, json_file))
    
    print("\n" + "="*60)
    print(f"SUMMARY: Downloaded {successful_sources} report(s) with {total_vulnerabilities} vulnerabilities")
    print("="*60)
    
    if len(processed_files) > 0:
        print("\nAvailable test files:")
        for source_type, name, file_path in processed_files:
            print(f"  - {os.path.basename(file_path)} ({source_type} source, {name})")
    
    if args.download_only:
        print("\nDownload completed. Skipping processing as requested.")
        return processed_files
    
    print("\nProcessing combined vulnerability data...")
    if all_vulnerabilities:
        print(f"Processing {len(all_vulnerabilities)} total vulnerabilities from all sources")
        
        df = preprocess_openvas_data(all_vulnerabilities, args.debug)
        if df.empty:
            print("Failed to preprocess combined data. Skipping.")
            return processed_files
        
        model_path = os.path.join(WORK_DIR, args.model)
        results = predict_severity(df, model_path, args.debug, args.train_model)
        results = fallback_cvss_based_severity(results)
        results = enhanced_calibration(results)
        
        # Save combined results
        output_csv = os.path.join(output_dir, "combined_results.csv")
        results.to_csv(output_csv, index=False)
        print(f"Combined results saved to {output_csv}")
        
        # Generate visualizations and report for combined data
        viz_dir = visualize_results(results, output_dir, "combined")
        print(f"Combined visualizations saved to {viz_dir}")
        
        report_file = generate_report(results, output_dir, "combined", viz_dir)
        print(f"Combined HTML report saved to {report_file}")
        
        print("\nCOMBINED SEVERITY PREDICTION SUMMARY:")
        print("====================================")
        print(f"Total vulnerabilities: {len(results)}")
        original_counts = results['original_threat'].value_counts()
        print("\nOriginal severity distribution:")
        for threat, count in original_counts.items():
            print(f"  {threat}: {count} ({count/len(results)*100:.1f}%)")
        predicted_counts = results['predicted_severity'].value_counts()
        print("\nPredicted severity distribution:")
        for threat, count in predicted_counts.items():
            print(f"  {threat}: {count} ({count/len(results)*100:.1f}%)")
        changes = results['severity_changed'].sum()
        significant = results['significant_change'].sum()
        fallbacks = results['used_fallback'].sum()
        print(f"\nSeverity changes: {changes} ({changes/len(results)*100:.1f}%)")
        print(f"Significant changes: {significant} ({significant/len(results)*100:.1f}%)")
        print(f"Fallback predictions used: {fallbacks} ({fallbacks/len(results)*100:.1f}%)")
    
    print("\n" + "="*60)
    print(f"PROCESSING COMPLETED: {len(processed_files)} file(s) processed")
    print("="*60)
    
    return processed_files

def main():
    args = parse_args()
    
    # Create output directory
    output_dir = os.path.join("C:/Users/cb26h/Desktop/pipeline/pipeline", args.output_dir)
    os.makedirs(output_dir, exist_ok=True)
    
    # If custom scan file is provided, process it
    if args.custom_scan:
        model_path = os.path.join("C:/Users/cb26h/Desktop/pipeline/pipeline", args.model)
        process_custom_scan(args.custom_scan, output_dir, model_path, args.debug, args.train_model)
    else:
        # Otherwise, proceed with normal download and processing
        download_and_process_data(args)

if __name__ == "__main__":
    start_time = time.time()
    main()
    elapsed = time.time() - start_time
    print(f"Total processing time: {elapsed:.2f} seconds ({elapsed/60:.2f} minutes)")