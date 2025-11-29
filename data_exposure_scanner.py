import re
import requests

def check_sensitive_data(url):
    try:
        response = requests.get(url, timeout=3)
        findings = []
        
        # Email detection
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response.text)
        if emails:
            findings.append({
                "type": "Email Exposure",
                "endpoint": url,
                "sample": emails[:3],  # First 3 emails only
                "response_snippet": response.text,
                "severity": "Medium"
            })
            
        # Add credit card pattern detection here if needed
            
        return findings
        
    except Exception as e:
        return []