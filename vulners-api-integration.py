def _query_vulners_api(self, cve_id):
    """
    Query the Vulners API for exploit information about a CVE.
    
    Args:
        cve_id: The CVE ID to look up
        
    Returns:
        Dictionary with exploit information or None if API call fails
    """
    # Get API key from environment variable or config
    api_key = os.getenv("VULNERS_API_KEY")
    if not api_key:
        # Check if we have a config file with the API key
        config_path = os.path.join(self.cache_dir, "api_config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    api_key = config.get("vulners_api_key")
            except Exception as e:
                print(f"Error loading API config: {e}")
    
    if not api_key:
        print("No Vulners API key found. Using alternative lookup methods.")
        return None
    
    # Cache key for this CVE
    cache_file = os.path.join(self.cache_dir, f"vulners_{cve_id}.json")
    
    # Check cache first
    if os.path.exists(cache_file):
        cache_age = time.time() - os.path.getmtime(cache_file)
        # Cache valid for 7 days (604800 seconds)
        if cache_age < 604800:
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error reading cache file: {e}")
    
    # Prepare request
    headers = {
        "X-Vulners-API-Key": api_key,
        "Content-Type": "application/json"
    }
    
    # Vulners API endpoint for CVE lookup
    url = "https://vulners.com/api/v3/search/id/"
    
    try:
        # Make API request
        response = requests.get(
            url,
            params={"id": cve_id},
            headers=headers,
            timeout=15
        )
        
        # Raise exception for HTTP errors
        response.raise_for_status()
        
        # Parse response
        data = response.json()
        
        # Check if successful
        if data.get("status") != "success":
            print(f"Vulners API returned error: {data.get('data', {}).get('error', 'Unknown error')}")
            return None
        
        # Extract exploit information
        result = {
            'has_exploit': False,
            'exploit_count': 0,
            'exploit_maturity': 'none',
            'exploits': []
        }
        
        # Check if we have data and exploits
        if 'data' in data and cve_id in data['data']:
            cve_data = data['data'][cve_id]
            
            # Check different exploit sources
            exploit_sources = ['exploit', 'exploitdb', 'metasploit', 'packetstorm']
            all_exploits = []
            
            for source in exploit_sources:
                if source in cve_data:
                    all_exploits.extend(cve_data[source])
            
            if all_exploits:
                result['has_exploit'] = True
                result['exploit_count'] = len(all_exploits)
                
                # Determine maturity level
                if len(all_exploits) > 3:
                    result['exploit_maturity'] = 'high'
                elif len(all_exploits) > 1:
                    result['exploit_maturity'] = 'medium'
                else:
                    result['exploit_maturity'] = 'low'
                
                # Extract exploit details
                for exploit in all_exploits:
                    result['exploits'].append({
                        'exploit_id': exploit.get('id', 'unknown'),
                        'type': exploit.get('type', 'unknown'),
                        'date': exploit.get('published', datetime.now().strftime('%Y-%m-%d')),
                        'source': 'vulners.com',
                        'title': exploit.get('title', ''),
                        'description': exploit.get('description', '')[:200]  # Truncate long descriptions
                    })
        
        # Cache the result
        with open(cache_file, 'w') as f:
            json.dump(result, f, indent=2)
        
        return result
        
    except requests.RequestException as e:
        print(f"Vulners API request failed for {cve_id}: {e}")
        return None
    except ValueError as e:
        print(f"Error parsing Vulners API response for {cve_id}: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error querying Vulners API for {cve_id}: {e}")
        return None
