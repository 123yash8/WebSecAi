from bs4 import BeautifulSoup
import requests

def check_csrf(url):
    vulnerabilities = []
    
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for form in soup.find_all('form'):
            if not form.find(attrs={'name': 'csrf_token'}):
                vulnerabilities.append({
                    'type': 'Missing CSRF Protection',
                    'endpoint': url,
                    'form_action': form.get('action', ''),
                    'html_snippet': str(form),
                    'severity': 'Medium'
                })
                
    except Exception as e:
        vulnerabilities.append({
            'type': 'CSRF Check Failed',
            'endpoint': url,
            'issue': str(e),
            'severity': 'Low'
        })
    
    return vulnerabilities