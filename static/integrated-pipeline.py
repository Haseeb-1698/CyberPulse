"""
Integrated Vulnerability Analysis Pipeline

This script integrates both the vulnerability severity prediction and remediation components
into a single, unified pipeline. It takes OpenVAS JSON data as input and produces a comprehensive
report with severity predictions and remediation recommendations.

Features:
1. Severity prediction using trained Random Forest model
2. Remediation recommendations using similarity and rule-based methods
3. Comprehensive CSV/JSON outputs for downstream use
4. Support for various OpenVAS/JSON input formats
"""

import os
import sys
import json
import pandas as pd
import numpy as np
from datetime import datetime
import argparse
import importlib.util
from pathlib import Path
import joblib

# Set working directory to project root (optional)
WORK_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(WORK_DIR)


def parse_args():
    parser = argparse.ArgumentParser(description='Integrated Vulnerability Analysis Pipeline')
    parser.add_argument('--input', '-i', type=str, required=True,
                        help='Path to OpenVAS JSON file')
    parser.add_argument('--output_dir', '-o', type=str, default='analysis_results',
                        help='Directory to save analysis results')
    parser.add_argument('--model', '-m', type=str, default='vulnerability_classifier.pkl',
                        help='Path to trained severity model file')
    parser.add_argument('--remediation_db', '-r', type=str, default=None,
                        help='Path to remediation database (optional)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode with additional logging')
    return parser.parse_args()


def load_remediation_system():
    """Dynamically load the RemediationSystem class from remediation_system.py"""
    remediation_file = os.path.join(WORK_DIR, 'remediation_system.py')
    if not os.path.exists(remediation_file):
        print(f"[Warning] remediation_system.py not found at {remediation_file}")
        return None
    spec = importlib.util.spec_from_file_location('remediation_system', remediation_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.RemediationSystem


def extract_openvas_data(json_file, debug=False):
    """
    Extract only CVE‐bearing results from OpenVAS JSON output.
    Results without at least one CVE are skipped.
    Returns a list of dicts with:
      - result_id, result_name
      - cve_id (primary), additional_cves
      - cvss_v3_score, original_threat
      - description, solution
      - host, port, qod
    """
    import json
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading JSON file: {e}")
        return []

    # locate the list
    if 'report' in data and 'results' in data['report']:
        results = data['report']['results'].get('result', [])
    elif 'results' in data:
        results = data['results'].get('result', [])
    else:
        print("Could not find 'results' in JSON")
        return []

    if isinstance(results, dict):
        results = [results]
    if debug:
        print(f"[Debug] Found {len(results)} total result entries")

    vulns = []
    for idx, r in enumerate(results):
        # Extract all CVEs
        # 1) top-level
        cve_id = (r.get('cve') or "").strip()
        # 2) fallback to first in additional_cves
        if not cve_id:
            add = r.get('additional_cves', [])
            if isinstance(add, list) and add:
                cve_id = add[0].strip()

        # If still empty, skip this entry
        if not cve_id:
            if debug:
                print(f"[Debug] Skipping entry #{idx} with no CVE")
            continue

        # Build output dict
        result = {
            'result_id':       r.get('result_id', ''),
            'result_name':     r.get('result_name',
                                     r.get('nvt', {}).get('name', '')).strip(),
            'cve_id':          cve_id,
            'additional_cves': r.get('additional_cves', []),
            'cvss_v3_score':   _to_float(r.get('severity', 0.0)),
            'original_threat': r.get('threat', 'Unknown').strip(),
            'description':     (r.get('description','') or
                                r.get('nvt',{}).get('description','')).strip(),
            'solution':        (r.get('solution','') or
                                r.get('nvt',{}).get('solution',{}).get('text','')).strip(),
            'host':            r.get('host',{}).get('ip','').strip(),
            'port':            r.get('port','general').strip(),
            'qod':             _extract_qod(r.get('qod'))
        }

        if debug and len(vulns) < 3:
            print(f"[Debug] Kept CVE entry: {result}")

        vulns.append(result)

    return vulns

def _to_float(val):
    try:
        return float(val)
    except:
        return 0.0

def _extract_qod(qod):
    if isinstance(qod, dict):
        return qod.get('value')
    return None


def process_features(df, debug=False):
    """Compute derived features and apply clipping."""
    # Example: compute exploit_to_impact_ratio if both columns exist
    if 'cvss_v3_exploitability' in df.columns and 'cvss_v3_score' in df.columns:
        df['exploit_to_impact_ratio'] = (
            df['cvss_v3_exploitability'] / (df['cvss_v3_score'].replace(0, np.nan))
        ).fillna(0)
    else:
        df['exploit_to_impact_ratio'] = 0.0

    # Clip extremes
    df['exploit_to_impact_ratio'] = df['exploit_to_impact_ratio'].clip(0.1, 10.0)

    if debug:
        cols = ['cvss_v3_score', 'exploit_to_impact_ratio']
        for c in cols:
            if c in df.columns:
                print(f"[Debug] {c}: mean={df[c].mean():.3f}, std={df[c].std():.3f}")
    return df


def main():
    args = parse_args()

    # 1. Extract raw vulnerabilities
    vulns = extract_openvas_data(args.input, debug=args.debug)
    if not vulns:
        sys.exit(1)

    # 2. Load into DataFrame
    df = pd.DataFrame(vulns)

    # 3. Compute additional features
    df = process_features(df, debug=args.debug)

    # 4. Ensure output directory
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 5. Save intermediate data
    df.to_csv(out_dir / 'vulnerabilities_processed.csv', index=False)
    with open(out_dir / 'vulnerabilities_processed.json', 'w') as f:
        json.dump(df.to_dict(orient='records'), f, indent=2)
    if args.debug:
        print(f"[Debug] Processed data saved to {out_dir}")

    # 6. Optionally load remediation system and generate recommendations
    RemedClass = load_remediation_system()
    if RemedClass and args.remediation_db:
        rem_sys = RemedClass(args.remediation_db)
        recommendations = rem_sys.recommend(df.to_dict(orient='records'))
        with open(out_dir / 'recommendations.json', 'w') as f:
            json.dump(recommendations, f, indent=2)
        print(f"Recommendations saved to {out_dir / 'recommendations.json'}")
    else:
        if args.remediation_db:
            print("[Warning] RemediationSystem loaded but no DB path provided.")
        else:
            print("[Info] Skipping remediation (no system or DB path provided)")

    print("Pipeline execution complete.")


if __name__ == '__main__':
    main()