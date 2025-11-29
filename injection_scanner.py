import requests
import time
import json
import logging
import argparse
import concurrent.futures
import threading
import os
from urllib.parse import urlparse, parse_qs, urlencode

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_FILE = r"G:\Project\Phase 9\Payloads\sql_payloads.txt"

# Define danger words globally
DANGER_WORDS = ["syntax error", "mysql", "unclosed", "unterminated", "query failed"]

def load_payloads(payload_file):
    """Load payloads from external file"""
    payloads = []
    try:
        if not os.path.exists(payload_file):
            logging.error(f"Payload file not found: {payload_file}")
            return payloads
            
        with open(payload_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split(',', 1)
                    if len(parts) == 2:
                        payloads.append((parts[0].strip(), parts[1].strip()))
        logging.debug(f"Loaded {len(payloads)} payloads from {payload_file}")
    except Exception as e:
        logging.error(f"Payload loading failed: {str(e)}")
    return payloads

logging.basicConfig(
    filename='vulnweb_scan.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class BaselineResponse:
    def __init__(self):
        self.time = 0
        self.length = 0
        self.keywords = []
        self.lock = threading.Lock()

    def update(self, time, length, keywords):
        with self.lock:
            self.time = time
            self.length = length
            self.keywords = keywords

BASELINE_RESPONSE = BaselineResponse()

def get_baseline(url):
    """Establish baseline response characteristics"""
    try:
        start = time.time()
        response = requests.get(url, timeout=10)
        response_time = time.time() - start
        
        content = response.text.lower()
        normal_keywords = [word for word in ["error", "sql", "warning", "notice"] if word in content]
        
        BASELINE_RESPONSE.update(response_time, len(response.content), normal_keywords)
        logging.debug(f"Baseline established for {url}")
    except Exception as e:
        logging.error(f"Baseline setup failed: {str(e)}")
        raise

def calculate_confidence(response, payload_type, response_time, original_url):
    """Multi-factor confidence scoring"""
    score = 0
    
    content = response.text.lower()
    matches = sum(1 for word in DANGER_WORDS if word in content)
    
    normal_matches = sum(1 for word in BASELINE_RESPONSE.keywords if word in content)
    score += max(0, (matches - normal_matches) * 15)

    time_threshold = BASELINE_RESPONSE.time * 2
    if response_time > time_threshold:
        score += min(50, (response_time - time_threshold) * 10)

    if response.status_code == 500:
        score += 40
    elif response.status_code in [403, 401]:
        score -= 30

    length_diff = abs(len(response.content) - BASELINE_RESPONSE.length)
    if length_diff > 1000:
        score += 40
    elif length_diff > 500:
        score += 25

    try:
        control_response = requests.get(original_url, timeout=10)
        if response.text != control_response.text:
            score += 30
    except:
        pass

    return min(100, max(0, score))

def validate_finding(test_url, original_url):
    """Enhanced validation with multiple checks"""
    try:
        control = requests.get(original_url, timeout=10)
        variation1 = requests.get(test_url.replace("'", "''"), timeout=10)
        variation2 = requests.get(test_url + " AND '1'='2", timeout=10)
        
        diff1 = abs(len(control.content) - len(variation1.content))
        diff2 = abs(len(control.content) - len(variation2.content))
        
        error_consistency = sum(
            1 for word in ["error", "syntax", "exception"]
            if (word in variation1.text.lower()) != (word in variation2.text.lower())
        )
        
        return (diff1 > 300 or diff2 > 300) and error_consistency < 2
    except:
        return False

def check_sql_injection(target_url):
    """Main SQL injection scanning function"""
    get_baseline(target_url)
    
    payloads = load_payloads(PAYLOAD_FILE)
    if not payloads:
        return []
    
    results = []
    stop_event = threading.Event()
    lock = threading.Lock()
    found_count = 0
    
    def process_payload(payload_data):
        """Process individual payload in a thread"""
        nonlocal found_count
        if stop_event.is_set():
            return None
            
        payload, payload_type = payload_data
        try:
            parsed = urlparse(target_url)
            test_url = f"{target_url}{payload}" if parsed.query else f"{target_url}?id=1{payload}"
            
            start_time = time.time()
            response = requests.get(test_url, timeout=15)
            response_time = time.time() - start_time
            
            confidence = calculate_confidence(response, payload_type, response_time, target_url)
            
            if confidence > 60 and validate_finding(test_url, target_url):
                content = response.text.lower()
                detected_keywords = [w for w in DANGER_WORDS if w in content]
                
                with lock:
                    result = {
                        "type": "SQL Injection",
                        "endpoint": test_url,
                        "payload": payload,
                        "issue": f"Possible {payload_type} SQL injection",
                        "confidence": f"{confidence}%",
                        "severity": "High" if confidence >= 80 else "Medium",
                        "response_snippet": response.text[:200],
                        "indicators": {
                            "response_time": f"{response_time:.2f}s",
                            "status_code": response.status_code,
                            "content_diff": abs(len(response.content) - BASELINE_RESPONSE.length),
                            "danger_keywords": detected_keywords
                        }
                    }
                    results.append(result)
                    found_count += 1
                    logging.debug(f"Found vulnerability #{found_count}: {test_url}")
                    
                    if found_count >= 25:
                        stop_event.set()
                        return result
                    
                return result
            return None
        except Exception as e:
            logging.error(f"Test failed for {payload}: {str(e)}")
            return None
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(process_payload, p) for p in payloads]
        try:
            for future in concurrent.futures.as_completed(futures):
                if stop_event.is_set():
                    for f in futures:
                        f.cancel()
                    break
        except KeyboardInterrupt:
            stop_event.set()
            raise
    
    logging.info(f"Scan terminated early with {len(results)} findings" if stop_event.is_set() else "Scan completed")
    return results[:25]

def main():
    parser = argparse.ArgumentParser(description="Dynamic SQL Injection Scanner")
    parser.add_argument("url", help="Target URL to scan")
    args = parser.parse_args()

    try:
        logging.info(f"Starting scan for {args.url}")
        results = check_sql_injection(args.url)
        print(json.dumps({
            "scan_results": results,
            "total_vulnerabilities": len(results),
            "status": "completed" if len(results) < 25 else "stopped_early"
        }, indent=2))
    except Exception as e:
        logging.error(f"Scan failed: {str(e)}")
        print(json.dumps({"error": str(e), "status": "failed"}))

if __name__ == "__main__":
    main()