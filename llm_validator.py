import os
import json
import requests
import time
from tqdm import tqdm
from tenacity import retry, stop_after_attempt, wait_exponential
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QPushButton, QLabel, QFileDialog, QMessageBox,
    QProgressBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from requests.adapters import HTTPAdapter

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=5, max=30))
def process_file(filename, vulnerabilities_dir, individual_dir, ANALYSIS_PROMPT, API_BASE, API_KEY, MODEL):
    """Process files with enhanced error handling and validation"""
    filepath = os.path.join(vulnerabilities_dir, filename)
    session = None  # Initialize outside try block
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return {"error": "Empty file", "filename": filename}

        payload = {
            "model": MODEL,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert analyzing potential vulnerabilities. Return ONLY valid JSON."},
                {"role": "user", "content": f"{ANALYSIS_PROMPT}\n\n{content}"}
            ],
            "temperature": 0.2,
            "max_tokens": 800,  # Increased token limit
            "stream": False
        }

        # Configure session with connection pooling
        session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=15,  # Increased pool size
            pool_maxsize=15,
            max_retries=5
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        response = session.post(
            f"{API_BASE}/chat/completions",
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=(15, 600) ) # Increased timeouts (15s connect, 10min read)
        response.raise_for_status()

        # Handle non-JSON responses
        try:
            response_data = response.json()
        except json.JSONDecodeError:
            return {"error": "Invalid JSON response", "filename": filename}

        # Validate response structure
        if 'choices' not in response_data or not response_data['choices']:
            return {"error": "No choices in response", "filename": filename}
        
        message_content = response_data['choices'][0]['message']['content']
        
        # Handle incomplete JSON responses
        try:
            result = json.loads(message_content)
        except json.JSONDecodeError as e:
            return {
                "error": f"JSON parse error: {str(e)}",
                "filename": filename,
                "raw_response": message_content[:300] + ("..." if len(message_content) > 300 else "")
            }

        # Validate required fields
        required_keys = {"validation", "summary", "confidence", "reasoning"}
        if not all(key in result for key in required_keys):
            return {
                "error": f"Missing required keys: {required_keys - set(result.keys())}",
                "filename": filename,
                "raw_response": result
            }

        analysis_path = os.path.join(individual_dir, f"analysis_{filename}")
        with open(analysis_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2)
        return result

    except Exception as e:
        return {"error": str(e), "filename": filename}
    finally:
        if session:
            session.close()

class AnalysisThread(QThread):
    progress = pyqtSignal(int)
    message = pyqtSignal(str)
    finished = pyqtSignal(str)

    def __init__(self, vulnerabilities_dir):
        super().__init__()
        self.vulnerabilities_dir = vulnerabilities_dir
        self.base_name = os.path.basename(vulnerabilities_dir.rstrip('/'))

    def run(self):
        try:
            output_dir = f"{self.base_name}_analysis"
            individual_dir = os.path.join(output_dir, "individual_reports")
            
            API_BASE = "http://127.0.0.1:1234/v1"
            API_KEY = "lm-studio"
            MODEL = "whiterabbitneo-2.5-qwen-2.5-coder-7b"

            ANALYSIS_PROMPT = """Analyze this vulnerability report and provide:
1. Validation: Is this a valid vulnerability? (True/False)
2. Summary: Brief technical summary (50 words)
3. Confidence: Confidence score (0-100)
4. Reasoning: Technical rationale for validation decision (50 words)

Return JSON format only: {
    "validation": bool,
    "summary": str,
    "confidence": int,
    "reasoning": str
}"""

            # Enhanced server check with model verification
            try:
                session = requests.Session()
                test_response = session.get(f"{API_BASE}/models", timeout=30)
                test_response.raise_for_status()
                
                # Verify model is available
                models = test_response.json().get('data', [])
                if not any(m['id'] == MODEL for m in models):
                    raise RuntimeError(f"Model '{MODEL}' not loaded in LM Studio")
            except Exception as e:
                raise RuntimeError(f"Server check failed: {str(e)}")
            finally:
                if session:
                    session.close()

            vuln_files = [f for f in os.listdir(self.vulnerabilities_dir) if f.endswith(".txt")]
            if not vuln_files:
                raise ValueError("No .txt files found in selected directory")

            os.makedirs(output_dir, exist_ok=True)
            os.makedirs(individual_dir, exist_ok=True)

            results = []
            total_files = len(vuln_files)
            for idx, filename in enumerate(tqdm(vuln_files, desc="Analyzing")):
                result = process_file(
                    filename, self.vulnerabilities_dir, individual_dir,
                    ANALYSIS_PROMPT, API_BASE, API_KEY, MODEL
                )
                results.append(result)
                self.progress.emit(int((idx + 1) / total_files * 100))
                time.sleep(2)  # Reduced request rate

            # Add error logging
            error_files = [r for r in results if 'error' in r]
            if error_files:
                error_log = os.path.join(output_dir, "error_log.txt")
                with open(error_log, 'w') as f:
                    for error in error_files:
                        f.write(f"{error['filename']}: {error['error']}\n")

            # Process results
            valid_results = [r for r in results if isinstance(r, dict) and 'validation' in r]
            confidence_avg = sum(r.get('confidence', 0) for r in valid_results) / len(valid_results) if valid_results else 0

            # Save summary
            summary_path = os.path.join(output_dir, f"{self.base_name}_summary.json")
            with open(summary_path, 'w', encoding='utf-8') as f:
                json.dump({
                    "total_files": len(results),
                    "valid_count": sum(1 for r in valid_results if r.get('validation')),
                    "confidence_avg": round(confidence_avg, 1),
                    "error_count": len(error_files),
                    "detailed_results": results
                }, f, indent=2)

            # Generate HTML report
            html_path = self.generate_html_report(summary_path)
            self.finished.emit(html_path)

        except Exception as e:
            self.message.emit(f"Error: {str(e)}")

    def generate_html_report(self, json_path):
        with open(json_path, 'r') as f:
            data = json.load(f)

        # Enhanced error display
        error_content = ""
        if data['error_count'] > 0:
            error_content = f"""<div class="errors">
                <h3>Error Details ({data['error_count']} files)</h3>
                <ul>
                    {"".join([f'<li><b>{res.get("filename", "Unknown")}</b>: {res["error"]}</li>' 
                    for res in data['detailed_results'] if 'error' in res])}
                </ul>
            </div>"""

        html_content = f"""<html>
        <head>
            <title>Report - {self.base_name}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 2rem; }}
                .header {{ color: #2c3e50; border-bottom: 2px solid #3498db; }}
                .summary {{ background: #f8f9fa; padding: 1.5rem; border-radius: 8px; }}
                .errors {{ background: #fff3cd; padding: 1.5rem; border-radius: 8px; margin-top: 1.5rem; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 1.5rem; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
                tr:hover {{ background-color: #f8f9fa; }}
                .valid {{ color: #28a745; font-weight: 500; }}
                .invalid {{ color: #dc3545; font-weight: 500; }}
                .metric {{ font-size: 1.1rem; margin: 0.5rem 0; }}
                .error-title {{ color: #856404; }}
            </style>
        </head>
        <body>
            <h1 class="header">Vulnerability Analysis</h1>
            <div class="summary">
                <h3>Summary</h3>
                <p class="metric">Total Files: {data['total_files']}</p>
                <p class="metric">Valid Vulnerabilities: <span class="valid">{data['valid_count']}</span></p>
                <p class="metric">Average Confidence: {data['confidence_avg']}%</p>
                <p class="metric">Errors: <span class="error-title">{data['error_count']}</span></p>
            </div>

            {error_content}

            <h3>Detailed Results</h3>
            <table>
                <tr><th>File</th><th>Valid</th><th>Confidence</th><th>Summary</th></tr>
                {"".join([
                    f'<tr><td>{os.path.basename(res.get("filename", ""))}</td>'
                    f'<td class={"valid" if res.get("validation") else "invalid"}>{res.get("validation", "N/A")}</td>'
                    f'<td>{res.get("confidence", "N/A")}%</td>'
                    f'<td>{res.get("summary", "No summary")[:100]}{"..." if len(str(res.get("summary",""))) > 100 else ""}</td></tr>'
                    for res in data['detailed_results'] if isinstance(res, dict) and 'error' not in res
                ])}
            </table>
        </body></html>"""

        html_path = os.path.join(os.path.dirname(json_path), f"{self.base_name}_report.html")
        with open(html_path, 'w') as f:
            f.write(html_content)
        return html_path

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Vulnerability Analyzer')
        self.setGeometry(300, 300, 450, 200)
        
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        layout.addWidget(QLabel("Select folder with vulnerability reports:"))
        self.btn = QPushButton("Choose Folder")
        self.btn.clicked.connect(self.select_folder)
        layout.addWidget(self.btn)
        
        self.progress = QProgressBar()
        self.progress.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.progress)

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Reports Folder")
        if not folder: return
        
        self.btn.setEnabled(False)
        self.progress.setValue(0)
        
        self.worker = AnalysisThread(folder)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.message.connect(self.show_error)
        self.worker.finished.connect(self.analysis_done)
        self.worker.start()

    def show_error(self, msg):
        QMessageBox.critical(self, "Error", msg)
        self.btn.setEnabled(True)

    def analysis_done(self, path):
        self.btn.setEnabled(True)
        self.progress.setValue(100)
        QMessageBox.information(self, "Complete", f"Report saved to:\n{path}")

if __name__ == '__main__':
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec_()