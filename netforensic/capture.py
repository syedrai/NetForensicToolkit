"""Live packet capture module for NetForensicToolkit with cartoon style."""

import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
from scapy.utils import wrpcap
from pathlib import Path
from typing import Optional, List, Callable
import threading
from datetime import datetime
import subprocess
import os

from .utils import load_iocs, setup_logging, print_section_header, celebrate_success, show_error
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
            
            # Configure Scapy for better performance
            conf.verb = 0  # Reduce verbosity
            
            # Start capture with Scapy - robust error handling
            print(f"\r{CartoonColors.ICONS['search']} Initializing capture on {interface}...", end="", flush=True)
            
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
            show_error(f"Capture failed: {str(e)}")
            # Fallback to tcpdump
            return self._fallback_capture(interface, duration, output_file)
        finally:
            self.is_capturing = False

    def _fallback_capture(self, interface: str, duration: int, output_file: str) -> str:
        """Fallback to tcpdump if Scapy fails."""
        print(f"\n{CartoonColors.ICONS['warning']} Falling back to tcpdump...")
        
        try:
            # Use tcpdump for reliable capture
            cmd = [
                'tcpdump', '-i', interface,
                '-w', output_file,
                '-c', '1000',  # Limit packets
                '-s', '0',     # Full packet capture
                '-n'           # No name resolution
            ]
            
            # Start tcpdump with timeout
            process = subprocess.Popen(cmd)
            time.sleep(duration)
            process.terminate()
            process.wait()
            
            # Verify capture worked
            if Path(output_file).exists() and Path(output_file).stat().st_size > 0:
                print(f"{CartoonColors.ICONS['success']} Fallback capture successful!")
                return output_file
            else:
                raise Exception("Fallback capture failed")
                
        except Exception as e:
            show_error(f"Fallback capture also failed: {str(e)}")
            raise

def start_capture(interface: str, duration: int = 60, alert_mode: bool = True) -> str:
    """Convenience function to start packet capture."""
    capture_engine = PacketCapture()
    return capture_engine.capture(interface, duration)
