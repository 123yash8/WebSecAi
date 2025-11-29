import os
import base64
import matplotlib.pyplot as plt
from datetime import datetime
from jinja2 import Template
from markupsafe import escape
from io import BytesIO

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report - {{ timestamp }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f9f9f9;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 25px;
            text-align: center;
            margin-bottom: 30px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .summary-card {
            background-color: white;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 0 5px 5px 0;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .vulnerability {
            border: 1px solid #e0e0e0;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 25px;
            background-color: white;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }
        .critical { border-left: 4px solid #e74c3c; }
        .high { border-left: 4px solid #f39c12; }
        .medium { border-left: 4px solid #f1c40f; }
        .low { border-left: 4px solid #2ecc71; }
        .chart-container {
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            margin: 30px 0;
            gap: 20px;
        }
        .chart {
            flex: 1;
            min-width: 300px;
            background: white;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .chart img {
            width: 100%;
            height: auto;
            border-radius: 3px;
        }
        pre {
            background-color: #f5f5f5;
            padding: 12px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Consolas', monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .severity-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 15px;
            font-weight: bold;
            font-size: 0.8em;
            color: white;
            margin-right: 8px;
        }
        .badge-critical { background-color: #e74c3c; }
        .badge-high { background-color: #f39c12; }
        .badge-medium { background-color: #f1c40f; color: #333; }
        .badge-low { background-color: #2ecc71; }
        .vuln-title {
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }
        .vuln-count {
            background-color: #3498db;
            color: white;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.8em;
            margin-left: 10px;
        }
        .response-sample {
            max-height: 200px;
            overflow-y: auto;
        }
        h2 {
            color: #2c3e50;
            border-bottom: 2px solid #eee;
            padding-bottom: 8px;
        }
        .collapsible {
            background-color: #f8f9fa;
            color: #2c3e50;
            cursor: pointer;
            padding: 8px 12px;
            width: 100%;
            border: 1px solid #ddd;
            text-align: left;
            outline: none;
            font-size: 14px;
            margin: 5px 0;
            border-radius: 4px;
        }
        .active, .collapsible:hover {
            background-color: #e9ecef;
        }
        .collapsible:after {
            content: '\\002B';
            color: #2c3e50;
            font-weight: bold;
            float: right;
            margin-left: 5px;
        }
        .active:after {
            content: "\\2212";
        }
        .collapsible-content {
            padding: 0 12px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.2s ease-out;
            background-color: #f5f5f5;
            border-radius: 0 0 4px 4px;
        }
        .response-toggle {
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Scan Report</h1>
        <p>Generated on {{ timestamp }} for {{ target_url }}</p>
    </div>

    <div class="summary-card">
        <h2>Scan Summary</h2>
        <p><strong>Target URL:</strong> {{ target_url }}</p>
        <p><strong>Scan Date:</strong> {{ timestamp }}</p>
        <p><strong>Total Vulnerabilities Found:</strong> {{ total_vulns }}</p>
        <div style="display: flex; gap: 20px; margin-top: 15px;">
            <div>
                <p><strong>Severity Breakdown:</strong></p>
                <p><span class="severity-badge badge-critical">Critical</span> {{ severity_counts.critical }}</p>
                <p><span class="severity-badge badge-high">High</span> {{ severity_counts.high }}</p>
                <p><span class="severity-badge badge-medium">Medium</span> {{ severity_counts.medium }}</p>
                <p><span class="severity-badge badge-low">Low</span> {{ severity_counts.low }}</p>
            </div>
            <div>
                <p><strong>Vulnerability Types:</strong></p>
                <ul style="margin-top: 0; padding-left: 20px;">
                    {% for category, count in category_counts.items() if count > 0 %}
                    <li>{{ category }}: {{ count }}</li>
                    {% endfor %}
                </ul>
            </div>
        </div>
    </div>

    <div class="chart-container">
        <div class="chart">
            <h3>Vulnerability Type Distribution</h3>
            <img src="{{ pie_chart_data }}" alt="Vulnerability Pie Chart">
        </div>
        <div class="chart">
            <h3>Severity Level Distribution</h3>
            <img src="{{ bar_chart_data }}" alt="Severity Bar Chart">
        </div>
    </div>

    <h2>Detailed Findings</h2>
    {% set ns = namespace(counter=1) %}
    {% for category, items in findings.items() if items %}
    <div class="vulnerability">
        <div class="vuln-title">
            <h3>{{ category }}</h3>
            <span class="vuln-count">{{ items|length }} findings</span>
        </div>
        {% for item in items %}
        <div class="{{ item.severity }}" style="margin-bottom: 20px; padding-bottom: 20px; border-bottom: 1px dashed #eee;">
            <p>
                <span class="severity-badge badge-{{ item.severity }}">
                    {{ item.severity|upper }}
                </span>
                <strong>Vulnerability #{{ ns.counter }}</strong>
                <strong>Endpoint:</strong> {{ item.endpoint|e }}
            </p>
            {% if item.type %}<p><strong>Type:</strong> {{ item.type|e }}</p>{% endif %}
            {% if item.payload %}<p><strong>Payload:</strong> <code>{{ item.payload|e }}</code></p>{% endif %}
            {% if item.issue %}<p><strong>Issue:</strong> {{ item.issue|e }}</p>{% endif %}
            {% if item.sample %}
            <p><strong>Found:</strong> 
                {{ item.sample|join(', ')|e if item.sample is iterable and not item.sample is string else item.sample|e }}
            </p>
            {% endif %}
            
            {% if item.response_snippet %}
            <div class="response-toggle">
                <button type="button" class="collapsible">Show Full Response Evidence</button>
                <div class="collapsible-content">
                    <pre>{{ item.response_snippet|e }}</pre>
                </div>
            </div>
            {% endif %}
            
            {% if item.headers %}
            <p><strong>Headers:</strong></p>
            <pre>{% for k,v in item.headers.items() %}{{ k|e }}: {{ v|e }}
{% endfor %}</pre>
            {% endif %}
            
            {% if item.html_snippet %}
            <div class="response-toggle">
                <button type="button" class="collapsible">Show Full HTML Context</button>
                <div class="collapsible-content">
                    <pre>{{ item.html_snippet|e }}</pre>
                </div>
            </div>
            {% endif %}
            
            {% if item.recommendation %}
            <p><strong>Recommendation:</strong> {{ item.recommendation|e }}</p>
            {% endif %}
        </div>
        {% set ns.counter = ns.counter + 1 %}
        {% endfor %}
    </div>
    {% endfor %}

    <script>
        document.querySelectorAll('.collapsible').forEach(button => {
            button.addEventListener('click', function() {
                this.classList.toggle('active');
                const content = this.nextElementSibling;
                if (content.style.maxHeight) {
                    content.style.maxHeight = null;
                } else {
                    content.style.maxHeight = content.scrollHeight + 'px';
                } 
            });
        });
    </script>
</body>
</html>
"""
def export_vulnerabilities_to_txt(findings, output_dir="reports/vulnerabilities"):
    """Export vulnerability data from findings to individual text files."""
    os.makedirs(output_dir, exist_ok=True)
    counter = 1
    for category, items in findings.items():
        for item in items:
            filename = f"vuln_{counter:03d}.txt"
            filepath = os.path.join(output_dir, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                content = []
                content.append(f"Category: {category}")
                content.append(f"Severity: {item.get('severity', 'N/A')}")
                content.append(f"Endpoint: {item.get('endpoint', 'N/A')}")
                
                if 'type' in item:
                    content.append(f"Type: {item['type']}")
                if 'payload' in item:
                    content.append(f"Payload: {item['payload']}")
                if 'issue' in item:
                    content.append(f"Issue: {item['issue']}")
                if 'sample' in item:
                    sample = item['sample']
                    if isinstance(sample, (list, tuple)):
                        sample = ', '.join(map(str, sample))
                    content.append(f"Sample: {sample}")
                if 'response_snippet' in item:
                    content.append("Response Snippet:\n" + item['response_snippet'])
                if 'headers' in item:
                    content.append("Headers:")
                    for key, value in item['headers'].items():
                        content.append(f"  {key}: {value}")
                if 'html_snippet' in item:
                    content.append("HTML Snippet:\n" + item['html_snippet'])
                if 'recommendation' in item:
                    content.append(f"Recommendation: {item['recommendation']}")
                
                f.write('\n'.join(content))
            counter += 1
    return os.path.abspath(output_dir)

def generate_report(
    findings,
    target_url,
    severity_counts,
    category_counts,
    pie_chart_data,
    bar_chart_data,
    output_dir="reports",
    export_txt=True
):
    """Generate HTML report and optionally export vulnerabilities to TXT files"""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"scan_report_{timestamp}.html"
    report_base_name = f"scan_report_{timestamp}"

    # Generate HTML report
    report_path = os.path.join(output_dir, report_filename)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(Template(REPORT_TEMPLATE).render(
            timestamp=timestamp.replace('_', ' '),
            target_url=target_url,
            total_vulns=sum(len(v) for v in findings.values()),
            severity_counts=severity_counts,
            category_counts=category_counts,
            findings=findings,
            pie_chart_data=f"data:image/png;base64,{pie_chart_data}",
            bar_chart_data=f"data:image/png;base64,{bar_chart_data}"
        ))

    # Automatically export vulnerabilities to TXT in matching folder
    if export_txt:
        vuln_dir_name = f"{report_base_name}_vulnerabilities"
        txt_output_dir = os.path.join(output_dir, vuln_dir_name)
        export_vulnerabilities_to_txt(findings, txt_output_dir)

    return os.path.abspath(report_path)

def determine_severity(category, item=None):
    """Determine severity level based on vulnerability category and context"""
    severity_map = {
        "SQL Injection": "critical",
        "XSS": "high",
        "Data Exposure": lambda i: "high" if "credentials" in str(i.get('type', '')).lower() else "medium",
        "Access Control": "medium",
        "Security Misconfig": "medium",
        "Authentication Issues": "low",
        "Host Header Injection": lambda i: "high" if i.get('type') == 'Redirect Hijacking' else "medium",
        "CORS Misconfig": lambda i: "critical" if i.get('severity') == 'Critical' else "high",
        "CSRF Issues": "medium",
        "File Inclusion": "high",
        "SSRF": "critical",
        "XXE": "critical",
        "Command Injection": "critical",
        "Path Traversal": "high",
        "Sensitive Data Exposure": "high",
        "Insecure Deserialization": "critical",
        "Server-Side Request Forgery": "critical",
        "SSTI": "critical",
        "HTTP Smuggling": "high"
    }
    
    severity_rule = severity_map.get(category, "medium")
    if callable(severity_rule):
        return severity_rule(item)
    return severity_rule

def generate_pie_chart(category_counts):
    """Generate pie chart of vulnerability types"""
    if not category_counts:
        return ""
        
    plt.figure(figsize=(6, 6))
    plt.pie(
        category_counts.values(),
        labels=category_counts.keys(),
        autopct='%1.1f%%',
        startangle=90
    )
    plt.title("Vulnerability Type Distribution")
    buf = BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    plt.close()
    return base64.b64encode(buf.getvalue()).decode('utf-8')

def generate_bar_chart(severity_counts):
    """Generate bar chart of severity levels"""
    if not severity_counts:
        return ""
        
    plt.figure(figsize=(6, 6))
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
    plt.close()
    return base64.b64encode(buf.getvalue()).decode('utf-8')
