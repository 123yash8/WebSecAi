import os
import base64
import matplotlib.pyplot as plt
from datetime import datetime
from jinja2 import Template
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
                <strong>Endpoint:</strong> {{ item.endpoint }}
            </p>
            {% if item.type %}<p><strong>Type:</strong> {{ item.type }}</p>{% endif %}
            {% if item.payload %}<p><strong>Payload:</strong> <code>{{ item.payload }}</code></p>{% endif %}
            {% if item.issue %}<p><strong>Issue:</strong> {{ item.issue }}</p>{% endif %}
            {% if item.sample %}
            <p><strong>Found:</strong> 
                {{ item.sample|join(', ') if item.sample is iterable and not item.sample is string else item.sample }}
            </p>
            {% endif %}
            {% if item.response_snippet %}
            <p><strong>Response Evidence:</strong></p>
            <div class="response-sample">
                <pre>{{ item.response_snippet }}</pre>
            </div>
            {% endif %}
            {% if item.headers %}
            <p><strong>Headers:</strong></p>
            <pre>{% for k,v in item.headers.items() %}{{ k }}: {{ v }}
{% endfor %}</pre>
            {% endif %}
            {% if item.html_snippet %}
            <p><strong>HTML Context:</strong></p>
            <pre>{{ item.html_snippet }}</pre>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    {% endfor %}
</body>
</html>
"""

def generate_report(vuln_data, target_url, output_dir="reports"):
    """Generate a comprehensive HTML vulnerability report with embedded charts"""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Prepare findings data with severity
    findings = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    category_counts = {}
    
    for category, items in vuln_data.items():
        if items:  # Only process categories with findings
            findings[category] = []
            category_counts[category] = len(items)
            for item in items:
                severity = determine_severity(category, item)
                severity_counts[severity] += 1
                item["severity"] = severity
                findings[category].append(item)

    # Generate charts as base64 embedded images
    pie_chart_data = generate_pie_chart(findings)
    bar_chart_data = generate_bar_chart(severity_counts)

    # Render HTML report
    report_path = os.path.join(output_dir, f"scan_report_{timestamp.replace(':', '-')}.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(Template(REPORT_TEMPLATE).render(
            timestamp=timestamp,
            target_url=target_url,
            total_vulns=sum(len(v) for v in findings.values()),
            severity_counts=severity_counts,
            category_counts=category_counts,
            findings=findings,
            pie_chart_data=pie_chart_data,
            bar_chart_data=bar_chart_data
        ))
    
    return os.path.abspath(report_path)

def generate_pie_chart(findings):
    """Generate pie chart as base64 encoded image"""
    labels = []
    sizes = []
    colors = ['#e74c3c', '#f39c12', '#f1c40f', '#2ecc71', '#3498db', '#9b59b6', '#1abc9c', '#e67e22']
    
    for category, items in findings.items():
        if items:
            labels.append(f"{category} ({len(items)})")
            sizes.append(len(items))
    
    if not sizes:  # Handle case with no vulnerabilities found
        sizes = [1]
        labels = ["No vulnerabilities found"]
        colors = ['#95a5a6']
    
    plt.figure(figsize=(8, 8))
    plt.pie(sizes, labels=labels, autopct=lambda p: f'{p:.1f}%' if p > 5 else '',
            startangle=140, colors=colors[:len(labels)], textprops={'fontsize': 10})
    plt.title('Vulnerability Type Distribution', pad=20, fontsize=12)
    
    # Save to buffer
    buf = BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=100)
    plt.close()
    return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode('utf-8')}"

def generate_bar_chart(severity_counts):
    """Generate bar chart as base64 encoded image"""
    labels = ["Critical", "High", "Medium", "Low"]
    counts = [
        severity_counts["critical"],
        severity_counts["high"],
        severity_counts["medium"],
        severity_counts["low"]
    ]
    colors = ['#e74c3c', '#f39c12', '#f1c40f', '#2ecc71']
    
    plt.figure(figsize=(8, 5))
    bars = plt.bar(labels, counts, color=colors)
    plt.title('Vulnerability Severity Levels', pad=20, fontsize=12)
    plt.xlabel('Severity Level', fontsize=10)
    plt.ylabel('Number of Findings', fontsize=10)
    plt.xticks(fontsize=9)
    plt.yticks(fontsize=9)
    
    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        if height > 0:
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}', ha='center', va='bottom', fontsize=10)
    
    # Save to buffer
    buf = BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=100)
    plt.close()
    return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode('utf-8')}"

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
        "CSRF Issues": "medium"
    }
    
    severity_rule = severity_map.get(category, "medium")
    if callable(severity_rule):
        return severity_rule(item)
    return severity_rule