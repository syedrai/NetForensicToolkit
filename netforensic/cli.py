"""Command Line Interface."""
import argparse
import sys
from pathlib import Path

from .capture import start_capture
from .parser import PCAPAnalyzer
from .utils import setup_logging, show_error
from .animations import CartoonColors

logger = setup_logging()

def main():
    CartoonColors.print_banner()
    
    parser = argparse.ArgumentParser(description="🎭 NetForensicToolkit")
    subparsers = parser.add_subparsers(dest='command')
    
    capture_parser = subparsers.add_parser('capture', help='Capture packets')
    capture_parser.add_argument('interface', help='Network interface')
    capture_parser.add_argument('--duration', type=int, default=60, help='Duration in seconds')
    
    analyze_parser = subparsers.add_parser('analyze', help='Analyze PCAP file')
    analyze_parser.add_argument('pcap', help='PCAP file to analyze')
    
    report_parser = subparsers.add_parser('report', help='Generate report')
    report_parser.add_argument('pcap', help='PCAP file to analyze')
    report_parser.add_argument('--format', choices=['html', 'json'], default='html')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.command == 'capture':
            result = start_capture(args.interface, args.duration)
            print(f"Capture saved: {result}")
            
        elif args.command == 'analyze':
            analyzer = PCAPAnalyzer(args.pcap)
            analyzer.parse()
            
        elif args.command == 'report':
            print(f"Would generate {args.format} report for {args.pcap}")
            
    except Exception as e:
        show_error(str(e))
        sys.exit(1)

if __name__ == '__main__':
    main()
