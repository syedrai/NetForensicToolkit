"""RELIABLE packet capture module for NetForensicToolkit."""

import time
import subprocess
import os
from pathlib import Path
from datetime import datetime
from typing import Optional

from .utils import load_iocs, setup_logging, print_section_header, celebrate_success, show_error
from .animations import CartoonAnimations, CartoonColors, FunMessages

logger = setup_logging()

class PacketCapture:
    """RELIABLE packet capture engine with multiple fallback methods."""
    
    def __init__(self):
        self.captured_packets = []
        self.iocs = load_iocs()
        self.suspicious_activity = []
        
    def capture_tcpdump(self, interface: str, duration: int, output_file: str) -> bool:
        """Use tcpdump for reliable packet capture."""
        try:
            # Build tcpdump command
            cmd = [
                'timeout', str(duration),
                'tcpdump', '-i', interface,
                '-w', output_file,
                '-s', '0',      # Full packet capture
                '-n',           # No name resolution
                '-U',           # Unbuffered output
                '-q'            # Quiet mode
            ]
            
            print(f"{CartoonColors.ICONS['search']} Starting tcpdump capture...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0 or result.returncode == 124:  # 124 = timeout
                return True
            else:
                logger.error(f"tcpdump failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"tcpdump exception: {e}")
            return False
    
    def capture_tshark(self, interface: str, duration: int, output_file: str) -> bool:
        """Fallback to tshark if tcpdump fails."""
        try:
            cmd = [
                'timeout', str(duration),
                'tshark', '-i', interface,
                '-w', output_file,
                '-F', 'pcap',
                '-q'
            ]
            
            print(f"{CartoonColors.ICONS['search']} Trying tshark capture...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode in [0, 124]
            
        except Exception as e:
            logger.error(f"tshark exception: {e}")
            return False
    
    def capture_dumpcap(self, interface: str, duration: int, output_file: str) -> bool:
        """Use dumpcap (most reliable)."""
        try:
            cmd = [
                'timeout', str(duration),
                'dumpcap', '-i', interface,
                '-w', output_file,
                '-P',  # Use pcap format
                '-q'
            ]
            
            print(f"{CartoonColors.ICONS['search']} Trying dumpcap capture...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode in [0, 124]
            
        except Exception as e:
            logger.error(f"dumpcap exception: {e}")
            return False
    
    def check_interface(self, interface: str) -> bool:
        """Check if interface exists and is accessible."""
        try:
            # Check if interface exists
            result = subprocess.run(['ip', 'link', 'show', interface], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def get_available_interfaces(self) -> list:
        """Get list of available network interfaces."""
        try:
            result = subprocess.run(['ip', 'link', 'show'], 
                                  capture_output=True, text=True)
            interfaces = []
            for line in result.stdout.split('\n'):
                if 'state UP' in line and 'LOOPBACK' not in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        iface = parts[1].strip()
                        if iface and iface != 'lo':
                            interfaces.append(iface)
            return interfaces
        except:
            return ['eth0', 'wlan0', 'enp0s3']  # Common fallbacks
    
    def capture(self, interface: str, duration: int = 60, 
                output_file: Optional[str] = None) -> str:
        """RELIABLE packet capture with multiple fallback methods."""
        
        # Show awesome banner
        CartoonColors.print_banner()
        
        # Fun startup message
        startup_msg = FunMessages.get_random_message('CAPTURE_START')
        CartoonAnimations.typing_effect(f"\n{CartoonColors.ICONS['rocket']} {startup_msg}")
        
        print_section_header("CAPTURE CONFIGURATION", "⚙️")
        print(f"{CartoonColors.ICONS['computer']} Interface: {CartoonColors.colorize(interface, 'cyan')}")
        print(f"{CartoonColors.ICONS['stopwatch']} Duration: {CartoonColors.colorize(str(duration), 'yellow')} seconds")
        
        # Check interface
        if not self.check_interface(interface):
            show_error(f"Interface {interface} not found or not accessible!")
            available = self.get_available_interfaces()
            if available:
                print(f"{CartoonColors.ICONS['info']} Available interfaces: {', '.join(available)}")
            raise Exception(f"Interface {interface} not available")
        
        # Ensure captures directory exists
        captures_dir = Path("captures")
        captures_dir.mkdir(exist_ok=True)
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = captures_dir / f"capture_{timestamp}.pcap"
        
        # Show network scanning animation
        CartoonAnimations.detective_scan()
        
        print(f"\n{CartoonColors.ICONS['network']} Starting reliable packet capture...")
        
        # Try multiple capture methods
        capture_methods = [
            ("tcpdump", self.capture_tcpdump),
            ("dumpcap", self.capture_dumpcap),
            ("tshark", self.capture_tshark),
        ]
        
        success = False
        method_used = None
        
        for method_name, method_func in capture_methods:
            print(f"{CartoonColors.ICONS['search']} Trying {method_name}...")
            
            if method_func(interface, duration, str(output_file)):
                success = True
                method_used = method_name
                break
            else:
                print(f"{CartoonColors.ICONS['warning']} {method_name} failed, trying next method...")
        
        if not success:
            show_error("All capture methods failed! Check interface permissions.")
            raise Exception("Packet capture failed - no working method found")
        
        # Verify capture worked
        if not Path(output_file).exists() or Path(output_file).stat().st_size == 0:
            show_error("Capture completed but file is empty or missing!")
            raise Exception("No packets captured")
        
        # Celebration and summary
        file_size = Path(output_file).stat().st_size
        print_section_header("CAPTURE COMPLETE", "🎉")
        print(f"{CartoonColors.ICONS['success']} Method used: {CartoonColors.colorize(method_used, 'green')}")
        print(f"{CartoonColors.ICONS['package']} File saved: {CartoonColors.colorize(str(output_file), 'cyan')}")
        print(f"{CartoonColors.ICONS['chart']} File size: {CartoonColors.colorize(self.format_bytes(file_size), 'yellow')}")
        
        celebrate_success(f"Capture completed using {method_used}!")
        
        return str(output_file)
    
    def format_bytes(self, size: int) -> str:
        """Format bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

def start_capture(interface: str, duration: int = 60) -> str:
    """Convenience function to start reliable packet capture."""
    capture_engine = PacketCapture()
    return capture_engine.capture(interface, duration)
