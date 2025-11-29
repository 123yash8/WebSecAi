# test_xss_scanner.py
from xss_scanner import check_xss

# Example: Test a vulnerable endpoint (use a safe testing environment)
url = "http://testphp.vulnweb.com/listproducts.php?artist=qq"
method = "GET"  # or "POST"
post_data = {"input_field": "test"}  # Only needed for POST

# Run the scanner
results = check_xss(url, method=method, data=post_data)

# Print results
print(f"Found {len(results)} vulnerabilities:")
for vuln in results:
    print(f"\nType: {vuln['type']}")
    print(f"Payload: {vuln['payload']}")
    print(f"Endpoint: {vuln['endpoint']}")
    print(f"Snippet: {vuln['response_snippet']}\n")