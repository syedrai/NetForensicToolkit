"""Utility functions for NetForensicToolkit with cartoon style."""

import ipaddress
import socket
from typing import Optional, List, Dict, Any
import logging
from .animations import CartoonColors, CartoonAnimations, FunMessages

def setup_logging(level: str = "INFO") -> logging.Logger:
    """Set up professional logging with cartoon style."""
    logger = logging.getLogger("netforensic")
    
    # Create colorful formatter
    class CartoonFormatter(logging.Formatter):
        def format(self, record):
            emoji = "📝"
            if record.levelno >= logging.ERROR:
                emoji = "❌"
            elif record.levelno >= logging.WARNING:
                emoji = "⚠️"
            elif record.levelno >= logging.INFO:
                emoji = "ℹ️"
            
            record.emoji = emoji
            return super().format(record)
    
    handler = logging.StreamHandler()
    formatter = CartoonFormatter(
        '%(emoji)s %(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper()))
    return logger

def print_section_header(title: str, emoji: str = "🔹"):
    """Print a colorful section header."""
    print(f"\n{CartoonColors.colorize('═' * 60, 'cyan')}")
    print(f"{emoji} {CartoonColors.colorize(title, 'bold')}")
    print(f"{CartoonColors.colorize('═' * 60, 'cyan')}")

def celebrate_success(message: str):
    """Celebrate successful operations."""
    print(f"\n{CartoonColors.ICONS['tada']} {CartoonColors.colorize('SUCCESS!', 'green')} {message}")
    print(f"{CartoonColors.ICONS['magic']} {CartoonColors.colorize('Operation completed successfully!', 'yellow')}")

def warn_user(message: str):
    """Show warning in a fun way."""
    print(f"\n{CartoonColors.ICONS['warning']} {CartoonColors.colorize('HEADS UP!', 'yellow')} {message}")

def show_error(message: str):
    """Show error in a cartoonish way."""
    print(f"\n{CartoonColors.ICONS['error']} {CartoonColors.colorize('OOPS!', 'red')} {message}")
    print(f"{CartoonColors.ICONS['thinking']} {CartoonColors.colorize('Let me think about how to fix this...', 'blue')}")

# Keep existing utility functions...
def resolve_ip(ip: str) -> Optional[str]:
    """Resolve IP address to hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None

def is_private_ip(ip: str) -> bool:
    """Check if IP is in private range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def load_iocs(ioc_file: str = "iocs.txt") -> List[str]:
    """Load Indicators of Compromise from file."""
    try:
        with open(ioc_file, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        return []

def format_bytes(size: int) -> str:
    """Format bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"