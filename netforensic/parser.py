"""ROBUST PCAP parsing and forensic analysis module."""

import dpkt
import pandas as pd
from collections import defaultdict
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime
import socket
import struct

from .utils import resolve_ip, is_private_ip, format_bytes, load_iocs, setup_logging, print_section_header
from .animations import CartoonAnimations, CartoonColors, FunMessages

logger = setup_logging()

class PCAPAnalyzer:
    """ROBUST PCAP analysis engine with comprehensive error handling."""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.analysis_results = {}
        self.iocs = load_iocs()
        
    def parse(self) -> Dict[str, Any]:
        """ROBUST PCAP parsing with comprehensive error handling."""
        
        # Show analysis start
        analysis_msg = FunMessages.get_random_message('ANALYSIS_START')
        CartoonAnimations.typing_effect(f"\n{CartoonColors.ICONS['detective']} {analysis_msg}")
        
        print_section_header("FORENSIC ANALYSIS IN PROGRESS", "🔍")
        
        # Verify file exists and is readable
        if not Path(self.pcap_file).exists():
            raise Exception(f"PCAP file not found: {self.pcap_file}")
        
        if Path(self.pcap_file).stat().st_size == 0:
            raise Exception(f"PCAP file is empty: {self.pcap_file}")
        
        try:
            with open(self.pcap_file, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                analysis = {
                    'summary': self._generate_summary(),
                    'protocol_stats': defaultdict(int),
                    'suspicious_activities': [],
                    'timeline_data': [],
                    'top_talkers': defaultdict(lambda: {'packets_sent': 0, 'packets_received': 0, 'bytes_sent': 0}),
                    'ioc_hits': []
                }
                
                packet_count = 0
                start_time = None
                total_size = Path(self.pcap_file).stat().st_size
                
                for timestamp, buf in pcap:
                    packet_count += 1
                    
                    # Show progress
                    if packet_count % 100 == 0:
                        progress = min(packet_count / 1000, 1.0)  # Simple progress
                        filled = int(progress * 30)
                        bar = '🟩' * filled + '⬜' * (30 - filled)
                        percent = f"{progress * 100:.1f}"
                        print(f'\r{CartoonColors.ICONS["analysis"]} Analyzing packets |{bar}| {percent}%', end='', flush=True)
                    
                    if start_time is None:
                        start_time = timestamp
                    
                    try:
                        packet_info = self._process_packet_safe(buf, timestamp, analysis)
                        if packet_info:
                            analysis['timeline_data'].append(packet_info)
                    except Exception as e:
                        continue  # Skip malformed packets
                
                # Complete progress bar
                print(f'\r{CartoonColors.ICONS["success"]} Analysis complete |{"🟩" * 30}| 100.0%')
                
                # Post-processing
                analysis['summary']['total_packets'] = packet_count
                analysis['summary']['duration'] = timestamp - start_time if start_time else 0
                analysis['top_talkers'] = self._calculate_top_talkers(analysis['top_talkers'])
                analysis['suspicious_activities'].extend(self._detect_anomalies(analysis))
                
                self.analysis_results = analysis
                self._print_analysis_summary(analysis)
                
                return analysis
                
        except (dpkt.dpkt.NeedData, struct.error, ValueError) as e:
            raise Exception(f"Invalid or corrupted PCAP file: {e}")
    
    def _process_packet_safe(self, buf: bytes, timestamp: float, analysis: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Safely process packet with comprehensive error handling."""
        try:
            # Handle different PCAP formats
            if len(buf) < 14:  # Minimum Ethernet frame size
                return None
                
            # Try Ethernet first
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not hasattr(eth, 'data') or not isinstance(eth.data, dpkt.ip.IP):
                    return None
                ip = eth.data
            except:
                # Try Linux cooked capture
                try:
                    eth = dpkt.sll.SLL(buf)
                    if not hasattr(eth, 'data') or not isinstance(eth.data, dpkt.ip.IP):
                        return None
                    ip = eth.data
                except:
                    return None
            
            # Extract IP information safely
            try:
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
            except:
                return None
            
            # Update statistics
            analysis['top_talkers'][src_ip]['packets_sent'] += 1
            analysis['top_talkers'][src_ip]['bytes_sent'] += ip.len
            analysis['top_talkers'][dst_ip]['packets_received'] += 1
            
            protocol = self._get_protocol_name(ip.p)
            analysis['protocol_stats'][protocol] += 1
            
            # IOC checking
            if src_ip in self.iocs or dst_ip in self.iocs:
                analysis['ioc_hits'].append({
                    'timestamp': datetime.fromtimestamp(timestamp),
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'protocol': protocol,
                    'ioc_type': 'BLACKLISTED_IP'
                })
            
            # Build packet info
            packet_info = {
                'timestamp': datetime.fromtimestamp(timestamp),
                'source_ip': src_ip,
                'dest_ip': dst_ip,
                'protocol': protocol,
                'size': ip.len,
                'flags': {}
            }
            
            # Extract port information if available
            if hasattr(ip, 'data'):
                try:
                    if hasattr(ip.data, 'sport'):
                        packet_info['src_port'] = ip.data.sport
                    if hasattr(ip.data, 'dport'):
                        packet_info['dst_port'] = ip.data.dport
                except:
                    pass
            
            return packet_info
            
        except Exception:
            return None  # Skip any packet that causes errors
    
    def _get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to name."""
        protocol_map = {
            1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP',
            41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH'
        }
        return protocol_map.get(protocol_num, f'UNKNOWN_{protocol_num}')
    
    def _print_analysis_summary(self, analysis: Dict[str, Any]):
        """Print analysis summary."""
        print_section_header("ANALYSIS RESULTS", "📊")
        
        total_packets = analysis['summary'].get('total_packets', 0)
        print(f"{CartoonColors.ICONS['package']} {CartoonColors.colorize('Total Packets:', 'bold')} {CartoonColors.colorize(str(total_packets), 'green')}")
        
        duration = analysis['summary'].get('duration', 0)
        duration_str = f"{duration:.2f}s"
        print(f"{CartoonColors.ICONS['stopwatch']} {CartoonColors.colorize('Duration:', 'bold')} {CartoonColors.colorize(duration_str, 'yellow')}")
        
        protocols = list(analysis['protocol_stats'].keys())
        if protocols:
            protocols_str = ", ".join(protocols[:5])  # Show first 5
            print(f"{CartoonColors.ICONS['network']} {CartoonColors.colorize('Protocols:', 'bold')} {CartoonColors.colorize(protocols_str, 'cyan')}")
        
        suspicious_count = len(analysis['suspicious_activities'])
        if suspicious_count > 0:
            print(f"{CartoonColors.ICONS['alert']} {CartoonColors.colorize('Suspicious Activities:', 'bold')} {CartoonColors.colorize(str(suspicious_count), 'red')}")
        
        ioc_count = len(analysis['ioc_hits'])
        if ioc_count > 0:
            print(f"{CartoonColors.ICONS['fire']} {CartoonColors.colorize('IOC Matches:', 'bold')} {CartoonColors.colorize(str(ioc_count), 'red')}")
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate PCAP file summary."""
        file_path = Path(self.pcap_file)
        if file_path.exists():
            return {
                'filename': self.pcap_file,
                'file_size': format_bytes(file_path.stat().st_size),
                'modified_time': datetime.fromtimestamp(file_path.stat().st_mtime)
            }
        return {
            'filename': self.pcap_file,
            'file_size': 'Unknown',
            'modified_time': 'Unknown'
        }
    
    def _calculate_top_talkers(self, talkers_data: Dict) -> List[Dict]:
        """Calculate and rank top talkers."""
        ranked_talkers = []
        for ip, data in talkers_data.items():
            total_packets = data['packets_sent'] + data['packets_received']
            if total_packets > 0:
                ranked_talkers.append({
                    'ip': ip,
                    'hostname': resolve_ip(ip),
                    'packets_sent': data['packets_sent'],
                    'packets_received': data['packets_received'],
                    'total_packets': total_packets,
                    'bytes_sent': data['bytes_sent'],
                    'is_private': is_private_ip(ip)
                })
        
        return sorted(ranked_talkers, key=lambda x: x['total_packets'], reverse=True)[:10]
    
    def _detect_anomalies(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect suspicious patterns."""
        anomalies = []
        timeline = analysis['timeline_data']
        
        if len(timeline) < 10:  # Need minimum packets
            return anomalies
        
        # Simple port scan detection
        syn_packets = [p for p in timeline if p.get('flags', {}).get('syn')]
        syn_by_source = defaultdict(list)
        
        for packet in syn_packets:
            syn_by_source[packet['source_ip']].append(packet)
        
        for src_ip, packets in syn_by_source.items():
            unique_ports = len(set(p.get('dst_port', 0) for p in packets))
            if unique_ports > 10:
                anomalies.append({
                    'type': 'PORT_SCAN',
                    'source_ip': src_ip,
                    'unique_ports': unique_ports,
                    'severity': 'HIGH'
                })
        
        return anomalies
    
    def to_dataframe(self) -> pd.DataFrame:
        """Convert analysis results to pandas DataFrame."""
        if not self.analysis_results:
            self.parse()
        return pd.DataFrame(self.analysis_results['timeline_data'])
