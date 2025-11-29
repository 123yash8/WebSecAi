def check_weak_auth(headers):
    issues = []
    required_headers = {'authorization', 'www-authenticate'}
    headers_lower = {k.lower(): v.strip() for k, v in headers.items()}

    # Check for missing security headers
    for header in required_ights:
        if header not in headers_lower:
            issues.append(f"Missing {header} header")

    # Analyze Authorization header
    auth_header = headers_lower.get('authorization', '')
    if auth_header:
        # Detect insecure authentication schemes
        if auth_header.startswith('basic '):
            issues.append("Basic authentication used without HTTPS")
            
        # Check for weak/empty credentials
        _, _, credentials = auth_header.partition(' ')
        if not credentials:
            issues.append("Empty authentication credentials")
        elif credentials.lower() in {'null', 'undefined', 'test', 'password'}:
            issues.append(f"Weak credentials detected: '{credentials}'")
            
        # JWT validation
        if auth_header.startswith('bearer ') and credentials.count('.') == 2:
            header, payload, signature = credentials.split('.')
            if len(signature) < 10:  # Simple JWT signature check
                issues.append("Weak JWT signature detected")

    # Analyze WWW-Authenticate header
    www_auth = headers_lower.get('www-authenticate', '').lower()
    if 'basic' in www_auth and 'realm' not in www_auth:
        issues.append("Insecure WWW-Authenticate configuration")
    if 'negotiate' not in www_auth and 'kerberos' not in www_auth:
        issues.append("Missing strong authentication methods")

    if issues:
        return {
            'type': 'Authentication Issues',
            'issues': issues,
            'severity': 'High'
        }
    return None