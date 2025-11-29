import requests

def check_host_header_injection(url):
    vulnerabilities = []
    test_headers = {'Host': 'evil.com', 'X-Forwarded-Host': 'evil.com'}
    
    try:
        response = requests.get(url, headers=test_headers, timeout=5)
        
        # Check for host reflection
        if 'evil.com' in response.text:
            vulnerabilities.append({
                'type': 'Host Header Reflection',
                'endpoint': url,
                'payload': 'evil.com',
                'response_snippet': response.text,
                'severity': 'Medium'
            })
            
        # Check for cache poisoning
        if 'evil.com' in response.headers.get('Location', ''):
            vulnerabilities.append({
                'type': 'Redirect Hijacking',
                'endpoint': url,
                'payload': 'evil.com',
                'response_snippet': response.headers['Location'],
                'severity': 'High'
            })
            
    except Exception as e:
        vulnerabilities.append({
            'type': 'Host Header Check Failed',
            'endpoint': url,
            'issue': str(e),
            'severity': 'Low'
        })
    
    return vulnerabilities