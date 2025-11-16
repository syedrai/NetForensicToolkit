"""PCAP parsing and forensic analysis module with cartoon style."""

import dpkt
import pandas as pd
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime
import socket
import struct

from .utils import resolve_ip, is_private_ip, format_bytes, load_iocs, setup_logging, print_section_header
from .animations import CartoonAnimations, CartoonColors, FunMessages

logger = setup_logging()

class PCAPAnalyzer:
    """Professional PCAP analysis engine with forensic capabilities and cartoon style."""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.packets = []
        self.analysis_results = {}
        self.iocs = load_iocs()
        
    def parse(self) -> Dict[str, Any]:
        """Parse PCAP file and extract comprehensive forensic data with fun animations."""
        
        # Show analysis start
        analysis_msg = FunMessages.get_random_message('ANALYSIS_START')
        CartoonAnimations.typing_effect(f"\n{CartoonColors.ICONS['detective']} {analysis_msg}")
        
        print_section_header("FORENSIC ANALYSIS IN PROGRESS", "🔍")
        
        logger.info(f"Parsing PCAP file: {self.pcap_file}")
        
        try:
            with open(self.pcap_file, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                analysis = {
                    'summary': self._generate_summary(),
                    'protocol_stats': defaultdict(int),
                    'conversations': [],
                    'suspicious_activities': [],
                    'timeline_data': [],
                    'top_talkers': defaultdict(lambda: {'packets_sent': 0, 'packets_received': 0, 'bytes_sent': 0}),
                    'ioc_hits': []
                }
                
                packet_count = 0
                start_time = None
                
                # Get total packets estimate for progress bar
                file_size = Path(self.pcap_file).stat().st_size
                estimated_packets = max(100, file_size // 1000)  # Rough estimate
                
                for timestamp, buf in pcap:
                    packet_count += 1
                    
                    # Show progress every 100 packets
                    if packet_count % 100 == 0:
                        progress = min(packet_count / estimated_packets, 1.0)
                        filled = int(progress * 30)
                        bar = '🟩' * filled + '⬜' * (30 - filled)
                        percent = f"{progress * 100:.1f}"
                        print(f'\r{CartoonColors.ICONS["analysis"]} Analyzing packets |{bar}| {percent}%', end='', flush=True)
                    
                    # Record start time
                    if start_time is None:
                        start_time = timestamp
                    
                    try:
                        # Handle both Ethernet and Linux cooked capture
                        if buf[0:2] == b'\x00\x00':  # Linux cooked capture
                            eth = dpkt.sll.SLL(buf)
                        else:
                            eth = dpkt.ethernet.Ethernet(buf)
                            
                        if not hasattr(eth, 'data') or not isinstance(eth.data, dpkt.ip.IP):
                            continue
                            
                        ip = eth.data
                        packet_info = self._process_packet(ip, timestamp, analysis)
                        analysis['timeline_data'].append(packet_info)
                        
                    except Exception as e:
                        logger.debug(f"Error processing packet {packet_count}: {e}")
                        continue
                
                # Complete progress bar
                print(f'\r{CartoonColors.ICONS["success"]} Analysis complete |{"🟩" * 30}| 100.0%')
                
                # Post-processing
                analysis['summary']['total_packets'] = packet_count
                analysis['summary']['duration'] = timestamp - start_time if start_time else 0
                analysis['top_talkers'] = self._calculate_top_talkers(analysis['top_talkers'])
                analysis['suspicious_activities'].extend(self._detect_anomalies(analysis))
                
                self.analysis_results = analysis
                
                # Show analysis results
                self._print_analysis_summary(analysis)
                
                return analysis
                
        except FileNotFoundError:
            logger.error(f"PCAP file not found: {self.pcap_file}")
            raise
        except (dpkt.dpkt.NeedData, struct.error):
            logger.error(f"Invalid or corrupted PCAP file: {self.pcap_file}")
            raise
    
    def _print_analysis_summary(self, analysis: Dict[str, Any]):
        """Print a fun analysis summary."""
        print_section_header("ANALYSIS RESULTS", "📊")
        
        total_packets = analysis['summary'].get('total_packets', 0)
        print(f"{CartoonColors.ICONS['package']} {CartoonColors.colorize('Total Packets:', 'bold')} {CartoonColors.colorize(str(total_packets), 'green')}")
        
        duration = analysis['summary'].get('duration', 0)
        duration_str = f"{duration:.2f}s"
        print(f"{CartoonColors.ICONS['stopwatch']} {CartoonColors.colorize('Duration:', 'bold')} {CartoonColors.colorize(duration_str, 'yellow')}")
        
        protocols = list(analysis['protocol_stats'].keys())
        if protocols:
            protocols_str = ", ".join(protocols)
            print(f"{CartoonColors.ICONS['network']} {CartoonColors.colorize('Protocols Found:', 'bold')} {CartoonColors.colorize(protocols_str, 'cyan')}")
        
        suspicious_count = len(analysis['suspicious_activities'])
        if suspicious_count > 0:
            emoji = "🚨" if any(a.get('severity') == 'HIGH' for a in analysis['suspicious_activities']) else "⚠️"
            print(f"{emoji} {CartoonColors.colorize('Suspicious Activities:', 'bold')} {CartoonColors.colorize(str(suspicious_count), 'red')}")
        
        ioc_count = len(analysis['ioc_hits'])
        if ioc_count > 0:
            print(f"{CartoonColors.ICONS['fire']} {CartoonColors.colorize('IOC Matches:', 'bold')} {CartoonColors.colorize(str(ioc_count), 'red')}")
    
    def _process_packet(self, ip: dpkt.ip.IP, timestamp: float, 
                       analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Process individual packet and update analysis."""
        try:
            src_ip = socket.inet_ntoa(ip.src) if hasattr(ip, 'src') else "Unknown"
            dst_ip = socket.inet_ntoa(ip.dst) if hasattr(ip, 'dst') else "Unknown"
        except:
            src_ip = "Invalid"
            dst_ip = "Invalid"
        
        # Update top talkers
        analysis['top_talkers'][src_ip]['packets_sent'] += 1
        analysis['top_talkers'][src_ip]['bytes_sent'] += ip.len
        analysis['top_talkers'][dst_ip]['packets_received'] += 1
        
        # Protocol analysis
        protocol = self._get_protocol_name(ip.p)
        analysis['protocol_stats'][protocol] += 1
        
        # IOC checking
        if src_ip in self.iocs or dst_ip in self.iocs:
            ioc_hit = {
                'timestamp': datetime.fromtimestamp(timestamp),
                'source_ip': src_ip,
                'dest_ip': dst_ip,
                'protocol': protocol,
                'ioc_type': 'BLACKLISTED_IP'
            }
            analysis['ioc_hits'].append(ioc_hit)
        
        # Build packet info for timeline
        packet_info = {
            'timestamp': datetime.fromtimestamp(timestamp),
            'source_ip': src_ip,
            'dest_ip': dst_ip,
            'protocol': protocol,
            'size': ip.len,
            'flags': self._extract_flags(ip)
        }
        
        # Port information for TCP/UDP
        if hasattr(ip, 'data'):
            packet_info.update(self._extract_port_info(ip.data))
        
        return packet_info
    
    def _get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to name."""
        protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            2: 'IGMP',
            41: 'IPv6',
            47: 'GRE',
            50: 'ESP',
            51: 'AH'
        }
        return protocol_map.get(protocol_num, f'UNKNOWN_{protocol_num}')
    
    def _extract_flags(self, ip: dpkt.ip.IP) -> Dict[str, Any]:
        """Extract TCP flags and other protocol-specific information."""
        flags = {}
        
        if hasattr(ip, 'data') and hasattr(ip.data, 'flags'):
            try:
                tcp_flags = ip.data.flags
                flags.update({
                    'syn': bool(tcp_flags & dpkt.tcp.TH_SYN),
                    'ack': bool(tcp_flags & dpkt.tcp.TH_ACK),
                    'fin': bool(tcp_flags & dpkt.tcp.TH_FIN),
                    'rst': bool(tcp_flags & dpkt.tcp.TH_RST),
                    'psh': bool(tcp_flags & dpkt.tcp.TH_PUSH),
                    'urg': bool(tcp_flags & dpkt.tcp.TH_URG)
                })
            except:
                pass
        
        return flags
    
    def _extract_port_info(self, transport_layer) -> Dict[str, Any]:
        """Extract port information from transport layer."""
        port_info = {}
        
        try:
            if hasattr(transport_layer, 'sport'):
                port_info['src_port'] = transport_layer.sport
            if hasattr(transport_layer, 'dport'):
                port_info['dst_port'] = transport_layer.dport
        except:
            pass
            
        return port_info
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate PCAP file summary."""
        file_path = Path(self.pcap_file)
        if file_path.exists():
            return {
                'filename': self.pcap_file,
                'file_size': format_bytes(file_path.stat().st_size),
                'modified_time': datetime.fromtimestamp(file_path.stat().st_mtime)
            }
        else:
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
            if total_packets > 0:  # Only include active talkers
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
        """Detect suspicious patterns and anomalies."""
        anomalies = []
        timeline = analysis['timeline_data']
        
        if not timeline:
            return anomalies
        
        # Detect port scanning (multiple SYN packets to different ports)
        syn_packets = [p for p in timeline if p.get('flags', {}).get('syn') and not p.get('flags', {}).get('ack')]
        syn_by_source = defaultdict(list)
        
        for packet in syn_packets:
            syn_by_source[packet['source_ip']].append(packet)
        
        for src_ip, packets in syn_by_source.items():
            unique_ports = len(set(p.get('dst_port', 0) for p in packets))
            if unique_ports > 10 and len(packets) > 20:  # Threshold for port scan
                anomalies.append({
                    'type': 'PORT_SCAN',
                    'source_ip': src_ip,
                    'unique_ports_targeted': unique_ports,
                    'packet_count': len(packets),
                    'severity': 'HIGH'
                })
        
        # Detect large data transfers
        data_transfers = [p for p in timeline if p['size'] > 1500]  # MTU-sized packets
        transfer_by_source = defaultdict(int)
        
        for packet in data_transfers:
            transfer_by_source[packet['source_ip']] += packet['size']
        
        for src_ip, total_size in transfer_by_source.items():
            if total_size > 10 * 1024 * 1024:  # 10 MB threshold
                anomalies.append({
                    'type': 'LARGE_DATA_TRANSFER',
                    'source_ip': src_ip,
                    'total_bytes': total_size,
                    'severity': 'MEDIUM'
                })
        
        # Detect potential beaconing (regular intervals)
        if len(timeline) > 100:
            try:
                time_diffs = []
                for i in range(1, min(100, len(timeline))):
                    diff = (timeline[i]['timestamp'] - timeline[i-1]['timestamp']).total_seconds()
                    time_diffs.append(diff)
                
                # Simple beaconing detection (regular timing patterns)
                if len(set(round(diff, 1) for diff in time_diffs[:20])) < 5:
                    anomalies.append({
                        'type': 'POSSIBLE_BEACONING',
                        'description': 'Regular timing patterns detected',
                        'severity': 'LOW'
                    })
            except:
                pass
        
        return anomalies
    
    def to_dataframe(self) -> pd.DataFrame:
        """Convert analysis results to pandas DataFrame."""
        if not self.analysis_results:
            self.parse()
        
        return pd.DataFrame(self.analysis_results['timeline_data'])
