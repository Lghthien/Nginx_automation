import os
from jinja2 import Template

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>NGINX CIS Benchmark Report - {{ host }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .pass { color: green; }
        .fail { color: red; }
        .error { color: orange; }
        .skipped { color: gray; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>NGINX CIS Benchmark Report</h1>
    <div class="summary">
        <h2>Summary - {{ summary.host }}</h2>
        <p><strong>Compliance Rate:</strong> {{ "%.1f"|format(summary.pass_rate) }}%</p>
        <p><strong>Total Checks:</strong> {{ summary.total }}</p>
        <p><strong>Passed:</strong> <span class="pass">{{ summary.pass }}</span></p>
        <p><strong>Failed:</strong> <span class="fail">{{ summary.fail }}</span></p>
        <p><strong>Errors:</strong> <span class="error">{{ summary.error }}</span></p>
        <p><strong>Skipped:</strong> <span class="skipped">{{ summary.skipped }}</span></p>
        <p><strong>Duration:</strong> {{ "%.2f"|format(summary.duration) }} seconds</p>
    </div>
    
    <h2>Detailed Results</h2>
    <table>
        <thead>
            <tr>
                <th>Check ID</th>
                <th>Description</th>
                <th>Status</th>
                <th>Level</th>
                <th>Message</th>
                <th>Module</th>
            </tr>
        </thead>
        <tbody>
            {% for result in results %}
            <tr>
                <td>{{ result.check_id }}</td>
                <td>{{ result.description }}</td>
                <td class="{{ result.status|lower }}">{{ result.status }}</td>
                <td>Level {{ result.level }}</td>
                <td>{{ result.message }}</td>
                <td>{{ result.module }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
"""

def generate_report(result_manager, output_file):
    """Generate HTML report"""
    summary = result_manager.get_summary()
    results = [result.__dict__ for result in result_manager.results]
    
    template = Template(HTML_TEMPLATE)
    html_content = template.render(
        host=result_manager.host,
        summary=summary,
        results=results
    )
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

def generate_consolidated_report(all_results, output_file):
    """Generate consolidated report for all hosts"""
    # Implementation for multi-host consolidated report
    pass