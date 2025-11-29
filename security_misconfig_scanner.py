REQUIRED_HEADERS = {
    'Content-Security-Policy': 'medium',
    'X-Content-Type-Options': 'medium',
    'X-Frame-Options': 'medium',
    'Strict-Transport-Security': 'high'
}

def check_security_headers(headers):
    missing = []
    for header, severity in REQUIRED_HEADERS.items():
        if header not in headers:
            missing.append(header)
    return missing