"""RELIABLE packet capture module."""
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

from .utils import setup_logging, print_section_header, celebrate_success, show_error
from .animations import CartoonAnimations, CartoonColors, FunMessages

logger = setup_logging()

class PacketCapture:
    def capture_tcpdump(self, interface: str, duration: int, output_file: str) -> bool:
        try:
            cmd = ['timeout', str(duration), 'tcpdump', '-i', interface, '-w', output_file, '-s', '0', '-n', '-q']
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode in [0, 124]
        except Exception as e:
            return False

    def check_interface(self, interface: str) -> bool:
        try:
            result = subprocess.run(['ip', 'link', 'show', interface], capture_output=True)
            return result.returncode == 0
        except:
            return False

    def capture(self, interface: str, duration: int = 60, output_file: Optional[str] = None) -> str:
        CartoonColors.print_banner()
        startup_msg = FunMessages.get_random_message('CAPTURE_START')
        CartoonAnimations.typing_effect(f"\n{CartoonColors.ICONS['rocket']} {startup_msg}")
        
        print_section_header("CAPTURE CONFIGURATION", "⚙️")
        print(f"{CartoonColors.ICONS['computer']} Interface: {CartoonColors.colorize(interface, 'cyan')}")
        print(f"{CartoonColors.ICONS['stopwatch']} Duration: {CartoonColors.colorize(str(duration), 'yellow')} seconds")
        
        if not self.check_interface(interface):
            show_error(f"Interface {interface} not found!")
            raise Exception(f"Interface {interface} not available")
        
        captures_dir = Path("captures")
        captures_dir.mkdir(exist_ok=True)
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = captures_dir / f"capture_{timestamp}.pcap"
        
        CartoonAnimations.detective_scan()
        print(f"\n{CartoonColors.ICONS['network']} Starting reliable packet capture...")
        
        if self.capture_tcpdump(interface, duration, str(output_file)):
            if Path(output_file).exists():
                file_size = Path(output_file).stat().st_size
                print_section_header("CAPTURE COMPLETE", "🎉")
                print(f"{CartoonColors.ICONS['success']} Method used: tcpdump")
                print(f"{CartoonColors.ICONS['package']} File saved: {output_file}")
                print(f"{CartoonColors.ICONS['chart']} File size: {self.format_bytes(file_size)}")
                celebrate_success("Capture completed successfully!")
                return str(output_file)
        
        show_error("Capture failed!")
        raise Exception("Packet capture failed")

    def format_bytes(self, size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

def start_capture(interface: str, duration: int = 60) -> str:
    capture_engine = PacketCapture()
    return capture_engine.capture(interface, duration)
