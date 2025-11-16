"""PCAP parsing module."""
import dpkt
from collections import defaultdict
from pathlib import Path
from datetime import datetime
import socket

from .utils import setup_logging, print_section_header
from .animations import CartoonAnimations, CartoonColors, FunMessages

logger = setup_logging()

class PCAPAnalyzer:
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file

    def parse(self):
        analysis_msg = FunMessages.get_random_message('ANALYSIS_START')
        CartoonAnimations.typing_effect(f"\n{CartoonColors.ICONS['detective']} {analysis_msg}")
        
        print_section_header("ANALYSIS STARTING", "🔍")
        
        if not Path(self.pcap_file).exists():
            raise Exception(f"PCAP file not found: {self.pcap_file}")

        try:
            with open(self.pcap_file, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                analysis = {
                    'summary': {},
                    'protocol_stats': defaultdict(int),
                    'timeline_data': []
                }
                
                packet_count = 0
                
                for timestamp, buf in pcap:
                    packet_count += 1
                    
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if not isinstance(eth.data, dpkt.ip.IP):
                            continue
                            
                        ip = eth.data
                        src_ip = socket.inet_ntoa(ip.src)
                        dst_ip = socket.inet_ntoa(ip.dst)
                        
                        protocol = self._get_protocol_name(ip.p)
                        analysis['protocol_stats'][protocol] += 1
                        
                        packet_info = {
                            'timestamp': datetime.fromtimestamp(timestamp),
                            'source_ip': src_ip,
                            'dest_ip': dst_ip,
                            'protocol': protocol,
                            'size': ip.len
                        }
                        analysis['timeline_data'].append(packet_info)
                        
                    except Exception:
                        continue
                
                analysis['summary']['total_packets'] = packet_count
                
                print_section_header("ANALYSIS RESULTS", "📊")
                print(f"{CartoonColors.ICONS['package']} Total Packets: {packet_count}")
                
                protocols = list(analysis['protocol_stats'].keys())
                if protocols:
                    print(f"{CartoonColors.ICONS['network']} Protocols: {', '.join(protocols)}")
                
                return analysis
                
        except Exception as e:
            raise Exception(f"Analysis failed: {e}")

    def _get_protocol_name(self, protocol_num: int) -> str:
        protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        return protocol_map.get(protocol_num, f'UNKNOWN_{protocol_num}')
