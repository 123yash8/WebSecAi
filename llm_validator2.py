import os
import json
import requests
from tqdm import tqdm
import time

def analyze_vulnerabilities(vulnerabilities_dir, output_dir="analysis_results"):
    """
    Send vulnerability files to LM Studio for analysis and save results.
    
    Args:
        vulnerabilities_dir: Path to directory containing vulnerability text files
        output_dir: Where to save analysis results
    
    Returns:
        Path to summary report
    """
    # LM Studio API configuration
    API_BASE = "http://169.254.83.107:1234/v1"
    API_KEY = "lm-studio"  # Default for local instances
    MODEL = "whiterabbitneo-2.5-qwen-2.5-coder-7b"  # Should match your loaded model
    
    # Create output directories
    os.makedirs(output_dir, exist_ok=True)
    individual_dir = os.path.join(output_dir, "individual_reports")
    os.makedirs(individual_dir, exist_ok=True)
    
    # Prepare analysis prompt
    ANALYSIS_PROMPT = """Analyze this vulnerability report and provide:
1. Validation: Is this a valid vulnerability? (True/False)
2. Summary: Brief technical summary (50 words)
3. Confidence: Confidence score (0-100)
4. Reasoning: Technical rationale for validation decision

Return JSON format only: {
    "validation": bool,
    "summary": str,
    "confidence": int,
    "reasoning": str
}"""

    results = []
    vuln_files = [f for f in os.listdir(vulnerabilities_dir) if f.endswith(".txt")]
    
    for filename in tqdm(vuln_files, desc="Analyzing vulnerabilities"):
        filepath = os.path.join(vulnerabilities_dir, filename)
        
        try:
            # Read vulnerability content
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Create API payload
            payload = {
                "model": MODEL,
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity expert analyzing potential vulnerabilities."},
                    {"role": "user", "content": f"{ANALYSIS_PROMPT}\n\n{content}"}
                ],
                "temperature": 0.2,
                "max_tokens": 400
            }
            
            # Send to LM Studio
            response = requests.post(
                f"{API_BASE}/chat/completions",
                headers={"Authorization": f"Bearer {API_KEY}"},
                json=payload,
                timeout=120
            )
            
            # Parse response
            if response.status_code == 200:
                result = json.loads(response.json()['choices'][0]['message']['content'])
                results.append(result)
                
                # Save individual analysis
                analysis_path = os.path.join(individual_dir, f"analysis_{filename}")
                with open(analysis_path, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2)
                
            else:
                results.append({"error": f"API Error: {response.status_code}"})
            
            # Rate limiting
            time.sleep(1)
            
        except Exception as e:
            results.append({"error": str(e)})
    
    # Generate summary report
    summary_path = os.path.join(output_dir, "summary_report.json")
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump({
            "total_vulnerabilities": len(results),
            "valid_count": sum(1 for r in results if isinstance(r, dict) and r.get('validation')),
            "confidence_avg": sum(r.get('confidence', 0) for r in results if isinstance(r, dict)) / len(results),
            "detailed_results": results
        }, f, indent=2)
    
    return summary_path

# Usage example
if __name__ == "__main__":
    report_dir = "reports/scan_report_2025-04-16_02-32-34_vulnerabilities"
    analysis_report = analyze_vulnerabilities(report_dir)
    print(f"Analysis complete. Results saved to: {analysis_report}")