"""Utility functions for NetForensicToolkit."""
import ipaddress
import socket
import logging
from typing import Optional, List
from pathlib import Path

def setup_logging(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("netforensic")
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper()))
    return logger

def resolve_ip(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def load_iocs(ioc_file: str = "iocs.txt") -> List[str]:
    try:
        with open(ioc_file, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        return []

def format_bytes(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"

def print_section_header(title: str, emoji: str = "🔹"):
    print(f"\n{'═' * 60}")
    print(f"{emoji} {title}")
    print(f"{'═' * 60}")

def celebrate_success(message: str):
    print(f"\n🎉 SUCCESS! {message}")

def show_error(message: str):
    print(f"\n❌ OOPS! {message}")
