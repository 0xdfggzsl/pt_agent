from jinja2 import Environment, FileSystemLoader
from typing import Dict, List
from datetime import datetime
import os

class ReportGenerator:
    def __init__(self, template_dir: str = None):
        if template_dir is None:
            template_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')
        self.template_dir = template_dir
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def generate_html_report(self, target_url: str, findings: List[Dict], scan_duration: float, output_path: str):
        summary = self._calculate_summary(findings)
        
        template = self.env.get_template('report.html')
        
        html_content = template.render(
            target_url=target_url,
            findings=findings,
            summary=summary,
            scan_duration=scan_duration,
            scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            severity_levels=['high', 'medium', 'low']
        )
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path

    def _calculate_summary(self, findings: List[Dict]) -> Dict:
        return {
            'total': len(findings),
            'high': len([f for f in findings if f.get('severity') == 'high']),
            'medium': len([f for f in findings if f.get('severity') == 'medium']),
            'low': len([f for f in findings if f.get('severity') == 'low']),
        }

    def get_severity_color(self, severity: str) -> str:
        colors = {
            'high': '#dc3545',
            'medium': '#ffc107',
            'low': '#17a2b8'
        }
        return colors.get(severity, '#6c757d')

    def get_severity_label(self, severity: str) -> str:
        labels = {
            'high': '高危',
            'medium': '中危',
            'low': '低危'
        }
        return labels.get(severity, '未知')
