import sys
import os
import json
import tempfile
import traceback
import base64
from io import BytesIO
import matplotlib
matplotlib.use('Agg')  # Set backend before importing pyplot
import matplotlib.pyplot as plt
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox,
    QProgressBar, QCheckBox, QDialog, QScrollArea
)
from PyQt5.QtGui import QFont, QTextCursor, QColor
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import requests


# Import scanners
from injection_scanner import check_sql_injection
from xss_scanner import check_xss
from data_exposure_scanner import check_sensitive_data
from access_control_scanner import check_broken_access
from security_misconfig_scanner import check_security_headers
from host_header_scanner import check_host_header_injection
from cors_scanner import check_cors_misconfig
from csrf_scanner import check_csrf
from authentication_scanner import check_weak_auth
from crawler import generate_sitemap
from report_generator import generate_report

#Importing LLM Vaidator
from llm_validator import MainWindow
from PyQt5.QtWidgets import QApplication


class ScanThread(QThread):
    update_signal = pyqtSignal(str, str)  # (message, category)
    progress_signal = pyqtSignal(int)
    scan_complete_signal = pyqtSignal(str)  # Temp file path

    def __init__(self, url, options, use_sitemap):
        super().__init__()
        self.url = url
        self.options = options
        self.use_sitemap = use_sitemap
        self.temp_file = tempfile.NamedTemporaryFile(
            mode='w+', 
            encoding='utf-8',
            suffix='.jsonl',
            delete=False
        )
        self.endpoints = [url]

    def run(self):
        try:
            self.progress_signal.emit(5)
            
            # Phase 1: Site Discovery
            if self.use_sitemap:
                self.update_status("🕸️ Crawling website structure...")
                try:
                    self.endpoints = generate_sitemap(self.url)
                    self.update_status(f"🔍 Found {len(self.endpoints)} endpoints")
                except Exception as e:
                    self.update_error(f"Sitemap generation failed: {str(e)}")

            # Phase 2: Header Collection
            self.progress_signal.emit(10)
            try:
                headers = requests.get(self.url, timeout=10).headers
            except Exception as e:
                headers = {}
                self.update_error(f"Header collection failed: {str(e)}")

            # Phase 3: Vulnerability Scanning
            total = len(self.endpoints)
            for idx, endpoint in enumerate(self.endpoints):
                self.scan_endpoint(endpoint, headers)
                self.progress_signal.emit(10 + int(80 * (idx + 1) / total))

            # Phase 4: Header-Specific Checks
            self.check_global_issues(headers)
            
            self.update_status("✅ Scan completed")
            self.progress_signal.emit(100)
            
        except Exception as e:
            self.update_error(f"Critical scan failure: {str(e)}")
        finally:
            self.temp_file.close()
            self.scan_complete_signal.emit(self.temp_file.name)

    def scan_endpoint(self, endpoint, headers):
        """Execute all enabled scanners against a single endpoint"""
        scanners = [
            ('sql_injection', lambda: check_sql_injection(endpoint)),
            ('xss', lambda: check_xss(endpoint)),
            ('data_exposure', lambda: check_sensitive_data(endpoint)),
            ('access_control', lambda: check_broken_access(endpoint, self.endpoints)),
            ('csrf', lambda: check_csrf(endpoint))
        ]
        
        for option, scanner in scanners:
            if self.options[option]:
                try:
                    results = scanner()
                    self.process_results(results)
                except Exception as e:
                    self.update_error(f"{option} scan failed on {endpoint}: {str(e)}")

    def check_global_issues(self, headers):
        """Checks requiring only headers"""
        if self.options['security_headers']:
            try:
                if missing := check_security_headers(headers):
                    self.process_results([{
                        'type': 'Security Misconfiguration',
                        'issue': f"Missing headers: {', '.join(missing)}",
                        'endpoint': self.url,
                        'headers': dict(headers),
                        'severity': 'Medium'
                    }])
            except Exception as e:
                self.update_error(f"Header check failed: {str(e)}")

        if self.options['host_header']:
            try:
                self.process_results(check_host_header_injection(self.url))
            except Exception as e:
                self.update_error(f"Host header check failed: {str(e)}")

        if self.options['cors']:
            try:
                self.process_results(check_cors_misconfig(self.url))
            except Exception as e:
                self.update_error(f"CORS check failed: {str(e)}")

        if self.options['authentication']:
            try:
                if result := check_weak_auth(headers):
                    self.process_results([result])
            except Exception as e:
                self.update_error(f"Auth check failed: {str(e)}")

    def process_results(self, results):
        """Standardize and store results"""
        if not results:
            return
            
        for result in results:
            json.dump(result, self.temp_file, ensure_ascii=False)
            self.temp_file.write('\n')
            self.temp_file.flush()
            
            self.update_vulnerability(
                result.get('type', 'Finding'),
                result.get('endpoint', self.url),
                result.get('payload'),
                result.get('issue'),
                result.get('severity', 'Medium'),
                result.get('response_snippet', '')
            )

    def update_status(self, message):
        self.update_signal.emit(message, "status")

    def update_error(self, message):
        self.update_signal.emit(f"❌ {message}", "error")

    def update_vulnerability(self, vuln_type, endpoint, payload, issue, severity, response_snippet):
        message = [
            f"🚨 {severity.upper()} {vuln_type}",
            f"Location: {endpoint}",
            f"Payload: {payload}" if payload else "",
            f"Issue: {issue}" if issue else "",
            f"Response snippet: {response_snippet[:100]}..." if response_snippet else ""
        ]
        self.update_signal.emit('\n'.join(filter(None, message)), "vuln")

class VulnerabilityScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.temp_file_path = None
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("OWASP Vulnerability Scanner v2.1")
        self.setGeometry(100, 100, 1000, 800)
        
        # Central Widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        # Header
        header = QLabel("OWASP Top 10 Vulnerability Scanner")
        header.setFont(QFont("Arial", 16, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        
        # URL Input
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter target URL (e.g., https://example.com)")
        self.url_input.setStyleSheet("padding: 8px; font-size: 14px;")
        
        # Checkboxes Layout
        options_box = QWidget()
        options_layout = QHBoxLayout(options_box)
        
        col1 = QVBoxLayout()
        col2 = QVBoxLayout()
        
        # Vulnerability Checkboxes
        self.cb_sitemap = QCheckBox("Generate Sitemap (Crawl website)")
        self.cb_sql = QCheckBox("SQL Injection")
        self.cb_xss = QCheckBox("Cross-Site Scripting (XSS)")
        self.cb_data = QCheckBox("Sensitive Data Exposure")
        self.cb_access = QCheckBox("Broken Access Control")
        self.cb_security = QCheckBox("Security Misconfiguration")
        self.cb_host = QCheckBox("Host Header Injection")
        self.cb_cors = QCheckBox("CORS Misconfiguration")
        self.cb_csrf = QCheckBox("CSRF Issues")
        self.cb_auth = QCheckBox("Authentication Issues")
        self.cb_ssti = QCheckBox("Server-Side Template Injection (SSTI)")
        self.cb_smuggling = QCheckBox("HTTP Request Smuggling")
        # Set default checks
        for cb in [self.cb_sitemap, self.cb_sql, self.cb_xss, 
                  self.cb_data, self.cb_access, self.cb_security,
                  self.cb_host, self.cb_cors, self.cb_csrf]:
            cb.setChecked(True)

        col1.addWidget(self.cb_sitemap)
        col1.addWidget(self.cb_sql)
        col1.addWidget(self.cb_xss)
        col1.addWidget(self.cb_data)
        col1.addWidget(self.cb_ssti)
        col2.addWidget(self.cb_smuggling)
        
        col2.addWidget(self.cb_access)
        col2.addWidget(self.cb_security)
        col2.addWidget(self.cb_host)
        col2.addWidget(self.cb_cors)
        col2.addWidget(self.cb_csrf)
        col2.addWidget(self.cb_auth)
        
        options_layout.addLayout(col1)
        options_layout.addLayout(col2)
        
        # Action Buttons
        btn_box = QWidget()
        btn_layout = QHBoxLayout(btn_box)
        
        self.btn_scan = QPushButton("Start Scan")
        self.btn_report = QPushButton("Generate Report")
        self.btn_chart = QPushButton("View Statistics")
        self.btn_sitemap = QPushButton("Show Endpoints")
        self.btn_LLMCheck = QPushButton("LLM Validation")
        
        btn_layout.addWidget(self.btn_scan)
        btn_layout.addWidget(self.btn_report)
        btn_layout.addWidget(self.btn_chart)
        btn_layout.addWidget(self.btn_sitemap)
        btn_layout.addWidget(self.btn_LLMCheck)
        
        # Results Display
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self.results_area = QTextEdit()
        self.results_area.setReadOnly(True)
        self.results_area.setStyleSheet("""
            font-family: Consolas, monospace;
            font-size: 12px;
            background-color: #f8f9fa;
            padding: 10px;
        """)
        scroll.setWidget(self.results_area)
        
        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setStyleSheet("""
            QProgressBar {
                height: 20px;
                text-align: center;
                border: 1px solid #ccc;
                border-radius: 5px;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                width: 10px;
            }
        """)
        
        # Assemble Layout
        layout.addWidget(header)
        layout.addWidget(self.url_input)
        layout.addWidget(options_box)
        layout.addWidget(btn_box)
        layout.addWidget(scroll)
        layout.addWidget(self.progress)
        
        # Connections
        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_report.clicked.connect(self.generate_report)
        self.btn_chart.clicked.connect(self.view_statistics )
        self.btn_sitemap.clicked.connect(self.show_endpoints)
        self.btn_LLMCheck.clicked.connect(self.run_gui)
        
        # Initial State
        self.btn_report.setEnabled(False)
        self.btn_chart.setEnabled(False)
        self.btn_sitemap.setEnabled(False)

    def start_scan(self):
        url = self.url_input.text().strip()
        if not (url.startswith('http://') or url.startswith('https://')):
            QMessageBox.warning(self, "Invalid URL", "URL must start with http:// or https://")
            return

        # Reset UI
        self.results_area.clear()
        self.progress.setValue(0)
        self.temp_file_path = None
        self.btn_report.setEnabled(False)
        self.btn_chart.setEnabled(False)
        
        # Configure scan options
        options = {
            'sql_injection': self.cb_sql.isChecked(),
            'xss': self.cb_xss.isChecked(),
            'data_exposure': self.cb_data.isChecked(),
            'access_control': self.cb_access.isChecked(),
            'security_headers': self.cb_security.isChecked(),
            'authentication': self.cb_auth.isChecked(),
            'host_header': self.cb_host.isChecked(),
            'cors': self.cb_cors.isChecked(),
            'csrf': self.cb_csrf.isChecked(),
            'ssti': self.cb_ssti.isChecked(),
            'http_smuggling': self.cb_smuggling.isChecked()
        }

        # Start scan thread
        self.scan_thread = ScanThread(
            url, 
            options,
            self.cb_sitemap.isChecked()
        )
        self.scan_thread.update_signal.connect(self.update_display)
        self.scan_thread.progress_signal.connect(self.progress.setValue)
        self.scan_thread.scan_complete_signal.connect(self.scan_finished)
        self.scan_thread.start()

    def update_display(self, message, category):
        cursor = self.results_area.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        format_map = {
            'status': (QColor('#28a745'), QFont.Bold),  # Green
            'error': (QColor('#dc3545'), QFont.Bold),    # Red
            'vuln': (QColor('#6f42c1'), QFont.Normal)    # Purple
        }
        
        color, weight = format_map.get(category, (QColor('#000000'), QFont.Normal))
        self.results_area.setTextColor(color)
        self.results_area.setFontWeight(weight)
        
        try:
            safe_msg = message.encode('utf-8', 'replace').decode('utf-8')
            cursor.insertText(safe_msg + '\n')
            
            if len(self.results_area.toPlainText()) > 10000:
                self.results_area.clear()
                self.results_area.setTextColor(QColor('#6c757d'))
                self.results_area.append("[Output truncated for performance]")
        except Exception as e:
            print(f"Display error: {str(e)}")

        self.results_area.ensureCursorVisible()

    def scan_finished(self, temp_file_path):
        self.temp_file_path = temp_file_path
        self.btn_report.setEnabled(True)
        self.btn_chart.setEnabled(True)
        self.btn_sitemap.setEnabled(True)
        
        try:
            with open(temp_file_path, 'r', encoding='utf-8') as f:
                count = sum(1 for _ in f)
            self.update_display(f"ℹ️ Scan complete. Found {count} vulnerabilities.", "status")
        except Exception as e:
            self.update_display(f"❌ Could not count results: {str(e)}", "error")

    def generate_report(self):
        if not self.temp_file_path:
            QMessageBox.warning(self, "No Data", "Run a scan first")
            return

        try:
            # Collect and structure data from temp file
            findings = {}
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            category_counts = {}

            with open(self.temp_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    item = json.loads(line)
                    vuln_type = item.get('type', 'Other')
                    
                    if vuln_type not in findings:
                        findings[vuln_type] = []
                        category_counts[vuln_type] = 0
                    
                    severity = item.get('severity', 'medium').lower()
                    severity_counts[severity] += 1
                    category_counts[vuln_type] += 1
                    
                    findings[vuln_type].append(item)

            # Generate charts
            pie_chart = self.generate_pie_chart(category_counts)
            bar_chart = self.generate_bar_chart(severity_counts)

            # Generate the report
            report_path = generate_report(
                findings,
                self.url_input.text(),
                severity_counts,
                category_counts,
                pie_chart,
                bar_chart
            )
            
            QMessageBox.information(
                self, 
                "Report Generated",
                f"Report saved to:\n{os.path.abspath(report_path)}"
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Report Failed",
                f"Error generating report:\n{str(e)}"
            )

    def generate_pie_chart(self, category_counts):
        """Generate pie chart as base64 image"""
        fig = plt.figure(figsize=(6, 6))
        plt.pie(
            category_counts.values(),
            labels=category_counts.keys(),
            autopct='%1.1f%%',
            startangle=90
        )
        plt.title("Vulnerability Type Distribution")
        buf = BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        plt.close(fig)
        return base64.b64encode(buf.getvalue()).decode('utf-8')

    def generate_bar_chart(self, severity_counts):
        """Generate bar chart as base64 image"""
        fig = plt.figure(figsize=(6, 6))
        colors = ['#e74c3c', '#f39c12', '#f1c40f', '#2ecc71']
        plt.bar(
            severity_counts.keys(),
            severity_counts.values(),
            color=colors
        )
        plt.title("Severity Distribution")
        plt.ylabel("Count")
        buf = BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        plt.close(fig)
        return base64.b64encode(buf.getvalue()).decode('utf-8')

    def view_statistics(self):
        if not self.temp_file_path:
            return

        try:
            # Create a new figure manager for Qt
            from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
            from matplotlib.figure import Figure
        
            # Create a dialog window
            stats_dialog = QDialog(self)
            stats_dialog.setWindowTitle("Scan Statistics")
            stats_dialog.resize(900, 500)
        
            # Create matplotlib figure and canvas
            fig = Figure(figsize=(9, 5))
            canvas = FigureCanvasQTAgg(fig)
        
            # Parse the data
            vuln_types = {}
            severities = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
            with open(self.temp_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    vuln = json.loads(line)
                    vuln_types[vuln.get('type', 'Other')] = vuln_types.get(vuln.get('type', 'Other'), 0) + 1
                    severity = vuln.get('severity', 'Medium').capitalize()
                    severities[severity] += 1

            # Create the plots
            ax1 = fig.add_subplot(1, 2, 1)
            ax1.pie(
                vuln_types.values(),
                labels=vuln_types.keys(),
                autopct='%1.1f%%',
                startangle=90
            )
            ax1.set_title("Vulnerability Types")
        
            ax2 = fig.add_subplot(1, 2, 2)
            colors = ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
            ax2.bar(
                severities.keys(),
                severities.values(),
                color=colors
            )
            ax2.set_title("Severity Distribution")
            ax2.set_ylabel("Count")
        
            fig.tight_layout()
        
            # Add the canvas to the dialog
            layout = QVBoxLayout()
            layout.addWidget(canvas)
            stats_dialog.setLayout(layout)
        
            # Show the dialog
            stats_dialog.exec_()
        
        except Exception as e:
            QMessageBox.warning(
                self,
                "Statistics Error",
                f"Could not generate charts:\n{str(e)}"
            )

    def show_endpoints(self):
        if not hasattr(self, 'scan_thread') or not hasattr(self.scan_thread, 'endpoints'):
            QMessageBox.warning(self, "No Data", "No endpoints discovered")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Discovered Endpoints")
        dialog.resize(800, 600)
        
        layout = QVBoxLayout()
        text = QTextEdit()
        text.setReadOnly(True)
        text.setLineWrapMode(QTextEdit.NoWrap)
        text.setStyleSheet("font-family: monospace;")
        
        endpoints = sorted(self.scan_thread.endpoints)
        text.setPlainText("\n".join(endpoints))
        
        layout.addWidget(text)
        dialog.setLayout(layout)
        dialog.exec_()
        
    def run_gui(self, checked=False):
        """Show a new window using the existing QApplication"""
        # Create and show window
        self.new_window = MainWindow()  # Store as instance variable if needed later
        self.new_window.show()
    
    # No need to create new QApplication or exec_()
    # The existing event loop from your main application will handle this
    def closeEvent(self, event):
        if hasattr(self, 'temp_file_path') and self.temp_file_path:
            try:
                os.unlink(self.temp_file_path)
            except:
                pass
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    font = QFont()
    font.setFamily("Segoe UI")
    font.setPointSize(10)
    app.setFont(font)
    
    scanner = VulnerabilityScannerApp()
    scanner.show()
    sys.exit(app.exec_())