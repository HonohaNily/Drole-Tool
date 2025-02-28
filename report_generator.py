"""
Report generation module for MineScan
Generates detailed security reports with vulnerability analysis
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from jinja2 import Environment, FileSystemLoader

class ReportGenerator:
    """Generates detailed security reports"""

    def __init__(self, vulnerabilities, scan_target="Unknown"):
        self.vulnerabilities = vulnerabilities
        self.scan_target = scan_target
        self.timestamp = datetime.now()

        # Initialize Jinja2 environment
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        if not os.path.exists(template_dir):
            os.makedirs(template_dir)

        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=True
        )

    def generate_report(self, output_file: str):
        """Generate a security report with detailed vulnerability analysis"""
        try:
            # Create output directory if it doesn't exist
            output_dir = os.path.dirname(output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)

            # Generate report based on file extension
            ext = os.path.splitext(output_file)[1].lower()
            if ext == '.md':
                # Write markdown report directly
                with open(output_file, 'w') as f:
                    f.write(self._generate_markdown_content())
            elif ext == '.json':
                self._generate_json_report(output_file)
            else:
                raise ValueError(f"Unsupported report format: {ext}")

        except Exception as e:
            print(f"Error generating report: {str(e)}")
            raise

    def _generate_markdown_content(self) -> str:
        """Generate markdown report content"""
        sections = []

        # Add header
        sections.append(f"# Minecraft Server Security Assessment Report")
        sections.append(f"Generated: {self.timestamp.strftime('%B %d, %Y')}")
        sections.append(f"Target: {self.scan_target}")
        sections.append("")

        # Add executive summary
        sections.append("## Executive Summary")
        sections.append("A comprehensive security assessment has identified several critical vulnerabilities that require immediate administrator attention. Below is a detailed analysis of each vulnerability, including exploitation risks and mitigation steps.")
        sections.append("")

        # Add vulnerability details
        for i, vuln in enumerate(self.vulnerabilities, 1):
            sections.append(f"## {i}. {vuln.get('name', 'Unknown Vulnerability')} ({vuln.get('severity', 'UNKNOWN')})")

            # What is the vulnerability
            sections.append("### What is the Vulnerability")
            sections.append(vuln.get('description', 'No description available'))
            if 'technical_details' in vuln:
                for key, value in vuln['technical_details'].items():
                    sections.append(f"- {key}: {value}")
            sections.append("")

            # Exploitation methods
            sections.append("### Potential Exploitation Methods")
            if 'exploitation_methods' in vuln:
                for method in vuln['exploitation_methods']:
                    sections.append(f"- {method}")
            sections.append("")

            # Mitigation steps
            sections.append("### How to Fix")
            if 'mitigation_steps' in vuln:
                for step in vuln['mitigation_steps']:
                    sections.append(f"1. {step}")
            if 'configuration' in vuln:
                sections.append("```yaml")
                sections.append(vuln['configuration'])
                sections.append("```")
            sections.append("")

        # Add general recommendations
        sections.append("## General Security Recommendations")
        sections.append("""
1. Keep Software Updated:
   - Update all server software regularly
   - Monitor for security patches
   - Maintain plugin compatibility

2. Security Configuration:
   - Enable all recommended security features
   - Implement access controls
   - Use secure communication channels

3. Monitoring and Logging:
   - Enable comprehensive logging
   - Monitor for suspicious activity
   - Regular security audits

4. Backup and Recovery:
   - Regular backup schedule
   - Test backup restoration
   - Document recovery procedures
""")

        # Add disclaimer
        sections.append("---")
        sections.append("Note: This report contains sensitive security information. Handle with appropriate confidentiality.")

        return "\n".join(sections)

    def _generate_json_report(self, output_file: str):
        """Generate a detailed JSON security report"""
        report_data = {
            'timestamp': self.timestamp.isoformat(),
            'scan_target': self.scan_target,
            'vulnerability_count': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'severity_summary': self._get_severity_summary(),
            'recommendations': self._generate_recommendations()
        }

        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)

    def _get_severity_summary(self) -> Dict[str, int]:
        """Get summary of vulnerabilities by severity"""
        summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'MEDIUM')
            summary[severity] += 1
        return summary

    def _generate_recommendations(self) -> List[Dict]:
        """Generate detailed security recommendations"""
        recommendations = []

        for vuln in self.vulnerabilities:
            recommendation = {
                'vulnerability': vuln.get('name', 'Unknown'),
                'severity': vuln.get('severity', 'MEDIUM'),
                'immediate_actions': [
                    'Update affected software to latest version',
                    'Apply security patches',
                    'Enable security features'
                ],
                'monitoring_steps': [
                    'Enable detailed logging',
                    'Monitor for unusual activity',
                    'Regular security audits'
                ],
                'long_term_fixes': [
                    'Implement proper access controls',
                    'Regular security assessments',
                    'Staff security training'
                ]
            }
            recommendations.append(recommendation)

        return recommendations