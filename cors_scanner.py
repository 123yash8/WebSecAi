import requests

def check_cors_misconfig(url):
    vulnerabilities = []
    origin = 'https://malicious.example.com'
    
    try:
        response = requests.get(url, headers={'Origin': origin}, timeout=5)
        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')
        
        if acao == '*' or origin in acao:
            vuln = {
                'type': 'Overly Permissive CORS',
                'endpoint': url,
                'vulnerable_header': 'Access-Control-Allow-Origin',
                'headers': dict(response.headers),
                'severity': 'High'
            }
            if acac.lower() == 'true':
                vuln['severity'] = 'Critical'
            vulnerabilities.append(vuln)
            
    except Exception as e:
        vulnerabilities.append({
            'type': 'CORS Check Failed',
            'endpoint': url,
            'issue': str(e),
            'severity': 'Low'
        })
    
    return vulnerabilities