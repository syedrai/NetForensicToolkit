"""Professional reporting module for NetForensicToolkit."""

import json
import base64
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
import matplotlib.pyplot as plt
import pandas as pd
from io import BytesIO

from .utils import setup_logging, format_bytes

logger = setup_logging()

class ReportGenerator:
    """Generate professional forensic reports in multiple formats."""
    
    def __init__(self, analysis_results: Dict[str, Any]):
        self.analysis = analysis_results
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
    
    def generate_html_report(self, output_file: str = None) -> str:
        """Generate comprehensive HTML forensic report."""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.reports_dir / f"forensic_report_{timestamp}.html"
        
        # Generate charts
        protocol_chart = self._generate_protocol_chart()
        timeline_chart = self._generate_timeline_chart()
        talkers_chart = self._generate_talkers_chart()
        
        html_content = self._build_html_template(
            protocol_chart, timeline_chart, talkers_chart
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_file}")
        return str(output_file)
    
    def generate_json_report(self, output_file: str = None) -> str:
        """Generate structured JSON report."""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.reports_dir / f"forensic_report_{timestamp}.json"
        
        # Prepare JSON data
        json_data = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool_version': '1.0.0',
                'analysis_duration': self.analysis['summary'].get('duration', 0)
            },
            'summary': self.analysis['summary'],
            'protocol_statistics': dict(self.analysis['protocol_stats']),
            'top_talkers': self.analysis['top_talkers'][:5],
            'suspicious_activities': self.analysis['suspicious_activities'],
            'ioc_hits': self.analysis['ioc_hits'],
            'timeline_sample': self.analysis['timeline_data'][:100]  # First 100 packets
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, default=str)
        
        logger.info(f"JSON report generated: {output_file}")
        return str(output_file)
    
    def _generate_protocol_chart(self) -> str:
        """Generate protocol distribution chart as base64."""
        try:
            protocols = list(self.analysis['protocol_stats'].keys())
            counts = list(self.analysis['protocol_stats'].values())
            
            plt.figure(figsize=(10, 6))
            plt.bar(protocols, counts, color='skyblue')
            plt.title('Protocol Distribution')
            plt.xlabel('Protocols')
            plt.ylabel('Packet Count')
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            buffer = BytesIO()
            plt.savefig(buffer, format='png', dpi=150)
            buffer.seek(0)
            
            image_base64 = base64.b64encode(buffer.read()).decode()
            plt.close()
            
            return image_base64
        except Exception as e:
            logger.error(f"Error generating protocol chart: {e}")
            return ""
    
    def _generate_timeline_chart(self) -> str:
        """Generate packet timeline chart as base64."""
        try:
            if not self.analysis['timeline_data']:
                return ""
            
            df = pd.DataFrame(self.analysis['timeline_data'])
            df['time_seconds'] = (df['timestamp'] - df['timestamp'].min()).dt.total_seconds()
            
            # Sample for performance
            if len(df) > 1000:
                df = df.sample(1000)
            
            plt.figure(figsize=(12, 6))
            
            # Color by protocol
            protocols = df['protocol'].unique()
            colors = plt.cm.Set3(range(len(protocols)))
            
            for i, protocol in enumerate(protocols):
                protocol_data = df[df['protocol'] == protocol]
                plt.scatter(protocol_data['time_seconds'], 
                           protocol_data['size'], 
                           c=[colors[i]], label=protocol, alpha=0.6)
            
            plt.title('Packet Timeline by Protocol and Size')
            plt.xlabel('Time (seconds from start)')
            plt.ylabel('Packet Size (bytes)')
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            
            buffer = BytesIO()
            plt.savefig(buffer, format='png', dpi=150)
            buffer.seek(0)
            
            image_base64 = base64.b64encode(buffer.read()).decode()
            plt.close()
            
            return image_base64
        except Exception as e:
            logger.error(f"Error generating timeline chart: {e}")
            return ""
    
    def _generate_talkers_chart(self) -> str:
        """Generate top talkers chart as base64."""
        try:
            talkers = self.analysis['top_talkers'][:8]  # Top 8
            
            if not talkers:
                return ""
            
            ips = [t['ip'] for t in talkers]
            packets = [t['total_packets'] for t in talkers]
            
            plt.figure(figsize=(10, 6))
            bars = plt.bar(ips, packets, color='lightcoral')
            plt.title('Top Talkers - Total Packets')
            plt.xlabel('IP Address')
            plt.ylabel('Total Packets')
            plt.xticks(rotation=45, ha='right')
            
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2., height,
                        f'{int(height)}', ha='center', va='bottom')
            
            plt.tight_layout()
            
            buffer = BytesIO()
            plt.savefig(buffer, format='png', dpi=150)
            buffer.seek(0)
            
            image_base64 = base64.b64encode(buffer.read()).decode()
            plt.close()
            
            return image_base64
        except Exception as e:
            logger.error(f"Error generating talkers chart: {e}")
            return ""
    
    def _build_html_template(self, protocol_chart: str, 
                           timeline_chart: str, talkers_chart: str) -> str:
        """Build comprehensive HTML report template."""
        
        # Build suspicious activities table
        suspicious_html = ""
        for activity in self.analysis['suspicious_activities']:
            suspicious_html += f"""
            <tr class="{'table-warning' if activity['severity'] == 'HIGH' else 'table-info'}">
                <td>{activity['type']}</td>
                <td>{activity.get('source_ip', 'N/A')}</td>
                <td>{activity.get('description', 'N/A')}</td>
                <td><span class="badge {'bg-danger' if activity['severity'] == 'HIGH' else 'bg-warning'}">{activity['severity']}</span></td>
            </tr>
            """
        
        # Build IOC hits table
        ioc_html = ""
        for ioc in self.analysis['ioc_hits']:
            ioc_html += f"""
            <tr class="table-danger">
                <td>{ioc['timestamp']}</td>
                <td>{ioc['source_ip']}</td>
                <td>{ioc['dest_ip']}</td>
                <td>{ioc['protocol']}</td>
                <td>{ioc['ioc_type']}</td>
            </tr>
            """
        
        # Build top talkers table
        talkers_html = ""
        for talker in self.analysis['top_talkers'][:10]:
            talkers_html += f"""
            <tr>
                <td>{talker['ip']}</td>
                <td>{talker['hostname'] or 'N/A'}</td>
                <td>{talker['packets_sent']}</td>
                <td>{talker['packets_received']}</td>
                <td>{talker['total_packets']}</td>
                <td>{format_bytes(talker['bytes_sent'])}</td>
                <td>{'Yes' if talker['is_private'] else 'No'}</td>
            </tr>
            """
        
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>NetForensic Toolkit Report</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                .card {{ margin-bottom: 1rem; }}
                .chart-img {{ max-width: 100%; height: auto; }}
                .table th {{ background-color: #343a40; color: white; }}
            </style>
        </head>
        <body>
            <div class="container-fluid">
                <div class="row my-4">
                    <div class="col">
                        <h1 class="text-center">NetForensic Toolkit Report</h1>
                        <p class="text-center text-muted">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                </div>

                <!-- Summary Card -->
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h5>Analysis Summary</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-4">
                                <strong>Total Packets:</strong> {self.analysis['summary'].get('total_packets', 0)}
                            </div>
                            <div class="col-md-4">
                                <strong>Capture Duration:</strong> {self.analysis['summary'].get('duration', 0):.2f} seconds
                            </div>
                            <div class="col-md-4">
                                <strong>File:</strong> {self.analysis['summary'].get('filename', 'N/A')}
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Charts Row -->
                <div class="row">
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-header">
                                <h6>Protocol Distribution</h6>
                            </div>
                            <div class="card-body">
                                <img src="data:image/png;base64,{protocol_chart}" class="chart-img" alt="Protocol Distribution">
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-header">
                                <h6>Packet Timeline</h6>
                            </div>
                            <div class="card-body">
                                <img src="data:image/png;base64,{timeline_chart}" class="chart-img" alt="Packet Timeline">
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-header">
                                <h6>Top Talkers</h6>
                            </div>
                            <div class="card-body">
                                <img src="data:image/png;base64,{talkers_chart}" class="chart-img" alt="Top Talkers">
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Suspicious Activities -->
                <div class="card">
                    <div class="card-header bg-warning">
                        <h5>Suspicious Activities Detected</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Type</th>
                                        <th>Source IP</th>
                                        <th>Description</th>
                                        <th>Severity</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {suspicious_html if suspicious_html else '<tr><td colspan="4" class="text-center">No suspicious activities detected</td></tr>'}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- IOC Hits -->
                <div class="card">
                    <div class="card-header bg-danger text-white">
                        <h5>IOC Matches</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Timestamp</th>
                                        <th>Source IP</th>
                                        <th>Destination IP</th>
                                        <th>Protocol</th>
                                        <th>IOC Type</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {ioc_html if ioc_html else '<tr><td colspan="5" class="text-center">No IOC matches found</td></tr>'}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Top Talkers Table -->
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h5>Top Talkers Detailed</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>IP Address</th>
                                        <th>Hostname</th>
                                        <th>Packets Sent</th>
                                        <th>Packets Received</th>
                                        <th>Total Packets</th>
                                        <th>Bytes Sent</th>
                                        <th>Private IP</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {talkers_html}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Footer -->
                <div class="row mt-4">
                    <div class="col text-center text-muted">
                        <p>Generated by NetForensicToolkit v1.0.0</p>
                        <p class="small">Legal Notice: This report is for authorized forensic analysis only.</p>
                    </div>
                </div>
            </div>

            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
        """
        
        return html_template