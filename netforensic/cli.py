"""Command Line Interface for NetForensicToolkit with cartoon style."""

import argparse
import sys
from pathlib import Path

from .capture import start_capture
from .parser import PCAPAnalyzer
from .report import ReportGenerator
from .utils import setup_logging, print_section_header, celebrate_success, show_error
from .animations import CartoonColors, CartoonAnimations, FunMessages

logger = setup_logging()

def main():
    """Main CLI entry point with cartoon style."""
    
    # Show awesome banner
    CartoonColors.print_banner()
    
    parser = argparse.ArgumentParser(
        description="🎭 NetForensicToolkit - Professional Network Forensic Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=CartoonColors.colorize("""
Examples:
  🎯 netforensic capture eth0 --duration 30
  🔍 netforensic analyze capture.pcap  
  📊 netforensic report capture.pcap --format html

Need help? Try: netforensic --help
        """, 'cyan')
    )
    
    subparsers = parser.add_subparsers(dest='command', help='🎪 Command to execute')
    
    # Capture command
    capture_parser = subparsers.add_parser('capture', 
                                         help='🎬 Capture network packets')
    capture_parser.add_argument('interface', help='📡 Network interface to capture on')
    capture_parser.add_argument('--duration', type=int, default=60, 
                               help='⏱️ Capture duration in seconds (default: 60)')
    capture_parser.add_argument('--output', help='💾 Output PCAP file path')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', 
                                         help='🔍 Analyze PCAP file')
    analyze_parser.add_argument('pcap', help='📦 PCAP file to analyze')
    analyze_parser.add_argument('--output', help='📄 Output analysis file')
    
    # Report command
    report_parser = subparsers.add_parser('report', 
                                        help='📊 Generate forensic report')
    report_parser.add_argument('pcap', help='📦 PCAP file to analyze')
    report_parser.add_argument('--format', choices=['html', 'json', 'both'], 
                              default='html', help='🎨 Report format (default: html)')
    report_parser.add_argument('--output', help='📁 Output directory for reports')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        CartoonAnimations.typing_effect(f"\n{CartoonColors.ICONS['thinking']} Which command shall we execute today?")
        sys.exit(1)
    
    try:
        if args.command == 'capture':
            capture(args)
        elif args.command == 'analyze':
            analyze(args)
        elif args.command == 'report':
            report(args)
            
    except KeyboardInterrupt:
        CartoonAnimations.typing_effect(f"\n{CartoonColors.ICONS['warning']} Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        show_error(f"Operation failed: {e}")
        sys.exit(1)

def capture(args):
    """Handle capture command with cartoon style."""
    CartoonAnimations.typing_effect(f"\n{CartoonColors.ICONS['rocket']} Launching packet capture mission!")
    
    print_section_header("CAPTURE SETUP", "⚙️")
    print(f"{CartoonColors.ICONS['computer']} Interface: {CartoonColors.colorize(args.interface, 'cyan')}")
    print(f"{CartoonColors.ICONS['stopwatch']} Duration: {CartoonColors.colorize(str(args.duration), 'yellow')} seconds")
    
    if args.output:
        print(f"{CartoonColors.ICONS['save']} Output: {CartoonColors.colorize(args.output, 'green')}")
    
    output_file = start_capture(
        interface=args.interface,
        duration=args.duration
    )
    
    celebrate_success(f"Capture saved to: {output_file}")

def analyze(args):
    """Handle analyze command with cartoon style."""
    if not Path(args.pcap).exists():
        show_error(f"PCAP file not found: {args.pcap}")
        sys.exit(1)
    
    CartoonAnimations.typing_effect(f"\n{CartoonColors.ICONS['detective']} Time for some digital detective work!")
    
    print_section_header("ANALYSIS STARTING", "🔍")
    print(f"{CartoonColors.ICONS['package']} Analyzing: {CartoonColors.colorize(args.pcap, 'cyan')}")
    
    analyzer = PCAPAnalyzer(args.pcap)
    analysis = analyzer.parse()
    
    # Fun summary display
    print_section_header("QUICK SUMMARY", "📈")
    
    if analysis['suspicious_activities']:
        high_severity = [a for a in analysis['suspicious_activities'] if a['severity'] == 'HIGH']
        if high_severity:
            print(f"{CartoonColors.ICONS['alert']} {CartoonColors.colorize('HIGH SEVERITY FINDINGS:', 'red')}")
            for activity in high_severity:
                print(f"   🚨 {activity['type']} from {activity.get('source_ip', 'Unknown')}")

def report(args):
    """Handle report command with cartoon style."""
    if not Path(args.pcap).exists():
        show_error(f"PCAP file not found: {args.pcap}")
        sys.exit(1)
    
    report_msg = FunMessages.get_random_message('REPORT_GENERATION')
    CartoonAnimations.typing_effect(f"\n{CartoonColors.ICONS['report']} {report_msg}")
    
    print_section_header("REPORT GENERATION", "📊")
    print(f"{CartoonColors.ICONS['package']} Source: {CartoonColors.colorize(args.pcap, 'cyan')}")
    print(f"{CartoonColors.ICONS['format']} Format: {CartoonColors.colorize(args.format, 'yellow')}")
    
    # Show loading animation
    CartoonAnimations.loading_animation("Preparing forensic report", 2)
    
    analyzer = PCAPAnalyzer(args.pcap)
    analysis = analyzer.parse()
    
    report_gen = ReportGenerator(analysis)
    
    reports_generated = []
    
    if args.format in ['html', 'both']:
        html_report = report_gen.generate_html_report()
        reports_generated.append(('HTML', html_report))
        print(f"{CartoonColors.ICONS['success']} {CartoonColors.colorize('HTML Report:', 'green')} {html_report}")
    
    if args.format in ['json', 'both']:
        json_report = report_gen.generate_json_report()
        reports_generated.append(('JSON', json_report))
        print(f"{CartoonColors.ICONS['success']} {CartoonColors.colorize('JSON Report:', 'green')} {json_report}")
    
    celebrate_success(f"Generated {len(reports_generated)} report(s) successfully!")
    
    # Show file locations
    print_section_header("REPORT LOCATIONS", "📁")
    for report_type, report_path in reports_generated:
        print(f"{CartoonColors.ICONS['file']} {report_type}: {CartoonColors.colorize(report_path, 'cyan')}")

if __name__ == '__main__':
    main()