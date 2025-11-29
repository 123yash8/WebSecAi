# http_smuggling_scanner.py
import requests

def check_http_smuggling(url):
    smuggled_requests = [
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 52\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: localhost\r\n\r\n"
    ]
    
    results = []
    for payload in smuggled_requests:
        try:
            response = requests.request(
                method='POST',
                url=url,
                data=payload,
                headers={'Connection': 'keep-alive'},
                timeout=15,
                verify=False
            )
            
            if 'smuggled' in response.text or response.status_code == 404:
                results.append({
                    'type': 'HTTP Smuggling',
                    'issue': "Potential HTTP Request Smuggling vulnerability detected",
                    'endpoint': url,
                    'severity': 'High',
                    'payload': payload[:100] + "...",
                    'response_snippet': response.text[:200]
                })
                
        except Exception as e:
            continue
            
    return results