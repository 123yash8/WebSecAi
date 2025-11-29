import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.exceptions import RequestException
payload_file="G:\Project\Phase 8\Payloads\sensitive_paths.txt"
DEFAULT_SENSITIVE_PATHS = {'admin', 'private', 'dashboard', 'config', 'control', 'manage'}
HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE']
MAX_THREADS = 10

def check_broken_access(endpoint, sitemap):
    """Main function preserved for external dependencies"""
    findings = []
    endpoint_lower = endpoint.lower()
    
    # Load sensitive paths from file or use default
    sensitive_paths = DEFAULT_SENSITIVE_PATHS
    if sitemap and isinstance(sitemap, str):
        try:
            with open(sitemap, 'r') as f:
                sensitive_paths = {line.strip().lower() for line in f}
        except FileNotFoundError:
            pass
    
    if any(path in endpoint_lower for path in sensitive_paths):
        with requests.Session() as session:
            session.headers.update({'User-Agent': 'SecurityScanner/1.0'})
            
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {
                    executor.submit(
                        session.request,
                        method,
                        endpoint,
                        timeout=10,
                        allow_redirects=False
                    ): method for method in HTTP_METHODS
                }
                
                for future in as_completed(futures):
                    method = futures[future]
                    try:
                        res = future.result()
                        if res.status_code // 100 == 2:
                            findings.append({
                                "endpoint": endpoint,
                                "type": "Broken Access Control",
                                "issue": f"Unauthorized {method} access to privileged endpoint",
                                "status_code": res.status_code,
                                "response_snippet": res.text[:500],
                                "severity": "High"
                            })
                    except RequestException as e:
                        findings.append({
                            "endpoint": endpoint,
                            "type": "Access Check Failed",
                            "issue": str(e),
                            "severity": "Low"
                        })
    return findings

def scan_endpoints(endpoints, payload_file):
    """Scan endpoints with optional payload file"""
    findings = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_endpoint = {
            executor.submit(check_broken_access, endpoint, payload_file): endpoint 
            for endpoint in endpoints
        }
        for future in as_completed(future_to_endpoint):
            findings.extend(future.result())
    return findings