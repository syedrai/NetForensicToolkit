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
    """RELIABLE packet capture engine."""
    
    def __init__(self):
        self.iocs = load_iocs()
        self.suspicious_activity = []
        
    def capture_tcpdump(self, interface: str, duration: int, output_file: str) -> bool:
        """Use tcpdump for reliable packet capture."""
        try:
            cmd = [
                'timeout', str(duration),
                'tcpdump', '-i', interface,
                '-w', output_file,
                '-s', '0', '-n', '-U', '-q'
            ]
            
            print(f"{CartoonColors.ICONS['search']} Starting tcpdump capture...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return result.returncode in [0, 124]
                
        except Exception as e:
            logger.error(f"tcpdump exception: {e}")
            return False
    
    def check_interface(self, interface: str) -> bool:
        """Check if interface exists and is accessible."""
        try:
            result = subprocess.run(['ip', 'link', 'show', interface], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def capture(self, interface: str, duration: int = 60, 
                output_file: Optional[str] = None) -> str:
        """RELIABLE packet capture."""
        
        CartoonColors.print_banner()
        startup_msg = FunMessages.get_random_message('CAPTURE_START')
        CartoonAnimations.typing_effect(f"\n{CartoonColors.ICONS['rocket']} {startup_msg}")
        
        print_section_header("CAPTURE CONFIGURATION", "⚙️")
        print(f"{CartoonColors.ICONS['computer']} Interface: {CartoonColors.colorize(interface, 'cyan')}")
        print(f"{CartoonColors.ICONS['stopwatch']} Duration: {CartoonColors.colorize(str(duration), 'yellow')} seconds")
        
        # Check interface
        if not self.check_interface(interface):
            show_error(f"Interface {interface} not found!")
            raise Exception(f"Interface {interface} not available")
        
        # Ensure captures directory exists
        captures_dir = Path("captures")
        captures_dir.mkdir(exist_ok=True)
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = captures_dir / f"capture_{timestamp}.pcap"
        
        CartoonAnimations.detective_scan()
        print(f"\n{CartoonColors.ICONS['network']} Starting reliable packet capture...")
        
        # Use tcpdump for reliable capture
        if self.capture_tcpdump(interface, duration, str(output_file)):
            # Verify capture worked - FIXED THE TYPO HERE
            if Path(output_file).exists() and Path(output_file).stat().st_size > 0:
                file_size = Path(output_file).stat().st_size
                print_section_header("CAPTURE COMPLETE", "🎉")
                print(f"{CartoonColors.ICONS['success']} Method used: {CartoonColors.colorize('tcpdump', 'green')}")
                print(f"{CartoonColors.ICONS['package']} File saved: {CartoonColors.colorize(str(output_file), 'cyan')}")
                print(f"{CartoonColors.ICONS['chart']} File size: {CartoonColors.colorize(self.format_bytes(file_size), 'yellow')}")
                celebrate_success("Capture completed successfully!")
                return str(output_file)
            else:
                show_error("Capture completed but file is empty!")
                raise Exception("No packets captured")
        
        show_error("Capture failed! Check interface permissions.")
        raise Exception("Packet capture failed")

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
