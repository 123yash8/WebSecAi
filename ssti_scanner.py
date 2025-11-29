# ssti_scanner.py
import requests

def check_ssti(url):
    payloads = [
        "{{7*7}}", 
        "${7*7}", 
        "<%= 7*7 %>", 
        "${{7*7}}", 
        "#{7*7}"
    ]
    
    results = []
    for payload in payloads:
        try:
            # Test URL parameters
            resp = requests.get(url, params={"test": payload}, timeout=10)
            if "49" in resp.text:
                results.append({
                    'type': 'SSTI',
                    'issue': f"Server-Side Template Injection detected with payload: {payload}",
                    'endpoint': resp.url,
                    'severity': 'Critical',
                    'response_snippet': resp.text[:200]
                })
            
            # Test POST data
            resp_post = requests.post(url, data={"input": payload}, timeout=10)
            if "49" in resp_post.text:
                results.append({
                    'type': 'SSTI',
                    'issue': f"Server-Side Template Injection detected with payload: {payload}",
                    'endpoint': url,
                    'severity': 'Critical',
                    'response_snippet': resp_post.text[:200]
                })
                
        except Exception as e:
            continue
            
    return results