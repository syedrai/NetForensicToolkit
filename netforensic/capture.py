"""Live packet capture module for NetForensicToolkit with cartoon style."""

import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.utils import wrpcap
from pathlib import Path
from typing import Optional, List, Callable
import threading
from datetime import datetime

from .utils import load_iocs, setup_logging, print_section_header, celebrate_success
from .animations import CartoonAnimations, CartoonColors, FunMessages

logger = setup_logging()

class PacketCapture:
    """Professional packet capture engine with real-time analysis and cartoon style."""
    
    def __init__(self):
        self.captured_packets = []
        self.iocs = load_iocs()
        self.suspicious_activity = []
        self.is_capturing = False
        self.packet_count = 0
        
    def packet_handler(self, packet) -> None:
        """Handle captured packets with real-time IOC checking and fun alerts."""
        if not packet.haslayer(IP):
            return
            
        self.captured_packets.append(packet)
        self.packet_count += 1
        
        # Show packet counter animation
        if self.packet_count % 50 == 0:
            packets_emoji = "📦" * min(self.packet_count // 50, 5)
            print(f"\r{packets_emoji} Packets captured: {self.packet_count}", end="", flush=True)
        
        # Real-time IOC detection
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if src_ip in self.iocs or dst_ip in self.iocs:
            alert_msg = f"IOC MATCH: {src_ip} -> {dst_ip}"
            # Fun alert message
            fun_alert = FunMessages.get_random_message('SUSPICIOUS_FOUND')
            print(f"\n{CartoonColors.ICONS['alert']} {CartoonColors.colorize(fun_alert, 'red')}")
            print(f"   {CartoonColors.colorize(alert_msg, 'bold')}")
            
            self.suspicious_activity.append({
                'timestamp': datetime.now(),
                'type': 'IOC_MATCH',
                'source_ip': src_ip,
                'dest_ip': dst_ip,
                'protocol': self._get_protocol(packet),
                'alert': alert_msg
            })
            
        # Detect suspicious patterns
        self._detect_suspicious_patterns(packet)
    
    def _get_protocol(self, packet) -> str:
        """Extract protocol from packet."""
        if packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        else:
            return "OTHER"
    
    def _detect_suspicious_patterns(self, packet) -> None:
        """Detect various suspicious network patterns."""
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            
            # SYN flood detection
            if tcp_layer.flags == 'S':  # SYN packet
                self._check_syn_scan(packet)
            
            # Failed connection attempts (RST packets)
            if tcp_layer.flags == 'R':
                self._check_failed_connections(packet)
    
    def _check_syn_scan(self, packet) -> None:
        """Detect SYN scan patterns."""
        # Implementation would track SYN packet frequency
        pass
    
    def _check_failed_connections(self, packet) -> None:
        """Detect failed connection attempts."""
        # Implementation would track RST packets
        pass
    
    def capture(self, interface: str, duration: int = 60, 
                packet_count: int = 0, output_file: Optional[str] = None) -> str:
        """Start packet capture with professional configuration and cartoon style."""
        
        # Show awesome banner
        CartoonColors.print_banner()
        
        # Fun startup message
        startup_msg = FunMessages.get_random_message('CAPTURE_START')
        CartoonAnimations.typing_effect(f"\n{CartoonColors.ICONS['rocket']} {startup_msg}")
        
        print_section_header("CAPTURE CONFIGURATION", "⚙️")
        print(f"{CartoonColors.ICONS['computer']} Interface: {CartoonColors.colorize(interface, 'cyan')}")
        print(f"{CartoonColors.ICONS['stopwatch']} Duration: {CartoonColors.colorize(str(duration), 'yellow')} seconds")
        print(f"{CartoonColors.ICONS['target']} Mode: {'Count-based' if packet_count else 'Time-based'}")
        
        # Show network scanning animation
        CartoonAnimations.detective_scan()
        
        logger.info(f"Starting capture on interface {interface} for {duration} seconds")
        
        # Ensure captures directory exists
        captures_dir = Path("captures")
        captures_dir.mkdir(exist_ok=True)
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = captures_dir / f"capture_{timestamp}.pcap"
        
        self.is_capturing = True
        self.captured_packets = []
        self.packet_count = 0
        
        try:
            # Show packet capture animation
            print(f"\n{CartoonColors.ICONS['network']} Starting packet capture...")
            CartoonAnimations.packet_capture_animation()
            
            # Start capture with Scapy
            packets = sniff(
                iface=interface,
                timeout=duration,
                count=packet_count,
                prn=self.packet_handler,
                store=True
            )
            
            # Save to file
            wrpcap(str(output_file), packets)
            
            # Celebration and summary
            print_section_header("CAPTURE COMPLETE", "🎉")
            print(f"{CartoonColors.ICONS['success']} Packets captured: {CartoonColors.colorize(str(len(packets)), 'green')}")
            print(f"{CartoonColors.ICONS['package']} File saved: {CartoonColors.colorize(str(output_file), 'cyan')}")
            
            if self.suspicious_activity:
                print(f"{CartoonColors.ICONS['alert']} Suspicious activities: {CartoonColors.colorize(str(len(self.suspicious_activity)), 'red')}")
            
            celebrate_success(f"Capture completed successfully!")
            
            return str(output_file)
            
        except Exception as e:
            from .utils import show_error
            show_error(f"Capture failed: {e}")
            raise
        finally:
            self.is_capturing = False

def start_capture(interface: str, duration: int = 60, alert_mode: bool = True) -> str:
    """Convenience function to start packet capture."""
    capture_engine = PacketCapture()
    return capture_engine.capture(interface, duration)