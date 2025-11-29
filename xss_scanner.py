import requests
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

def load_xss_payloads(payload_file=r"G:\Project\Phase 9\Payloads\xss-payloads.txt"):
    """Load XSS payloads from simple text file"""
    payloads = []
    try:
        with open(payload_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    payloads.append((line, "XSS Payload"))
    except FileNotFoundError:
        print(f"Payload file {payload_file} not found. Using default payloads.")
        return [
            ("<script>alert(1)</script>", "Basic XSS"),
            ("<img src=x onerror=alert(1)>", "Image Tag XSS")
        ]
    return payloads

def check_xss(url, method="GET", data=None, headers=None, cookies=None, max_threads=10):
    """Multi-threaded XSS scanner with early termination after 15 findings"""
    vulnerabilities = []
    payloads = load_xss_payloads()
    lock = threading.Lock()
    stop_event = threading.Event()  # Event to signal early termination
    
    if headers is None:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        }

    def test_payload(param_name, payload, payload_type, is_get=True):
        """Test individual payload with early termination checks"""
        if stop_event.is_set():
            return

        try:
            if is_get:
                url_parts = urlparse(url)
                query_params = parse_qsl(url_parts.query, keep_blank_values=True)
                new_query = [(name, payload if name == param_name else value) 
                            for name, value in query_params]
                encoded_query = urlencode(new_query, doseq=True)
                target_url = urlunparse(url_parts._replace(query=encoded_query))
                response = requests.get(target_url, headers=headers, cookies=cookies, timeout=5)
            else:
                target_url = url
                modified_data = data.copy()
                modified_data[param_name] = payload
                response = requests.post(target_url, data=modified_data, 
                                       headers=headers, cookies=cookies, timeout=5)

            if payload in response.text:
                with lock:
                    if len(vulnerabilities) < 5:
                        vulnerabilities.append({
                            "endpoint": target_url,
                            "type": payload_type,
                            "payload": payload,
                            "response_snippet": response.text[:2000000000],
                            "severity": "High"
                        })
                        # Stop scanning after 15 findings
                        if len(vulnerabilities) >= 5:
                            stop_event.set()
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        
        # Process GET parameters
        if method.upper() == "GET":
            url_parts = urlparse(url)
            query_params = parse_qsl(url_parts.query, keep_blank_values=True)
            for param_name, _ in query_params:
                if stop_event.is_set():
                    break
                for payload, payload_type in payloads:
                    if stop_event.is_set():
                        break
                    futures.append(executor.submit(test_payload, param_name, payload, payload_type, True))

        # Process POST parameters
        if method.upper() == "POST" and data is not None and not stop_event.is_set():
            for param_name in data:
                if stop_event.is_set():
                    break
                for payload, payload_type in payloads:
                    if stop_event.is_set():
                        break
                    futures.append(executor.submit(test_payload, param_name, payload, payload_type, False))

        # Cancel remaining futures if limit reached
        for future in as_completed(futures):
            if stop_event.is_set():
                future.cancel()
            else:
                future.result()

    return vulnerabilities[:15]
