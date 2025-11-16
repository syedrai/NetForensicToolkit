"""Cartoonish animations and visual effects for NetForensicToolkit."""

import time
import sys
import random
from typing import List

class CartoonAnimations:
    """Fun animations for the CLI interface."""
    
    @staticmethod
    def typing_effect(text: str, delay: float = 0.03):
        """Simulate typing effect."""
        for char in text:
            print(char, end='', flush=True)
            time.sleep(delay)
        print()
    
    @staticmethod
    def loading_animation(text: str = "Loading", duration: int = 3):
        """Show a fun loading animation."""
        frames = ["⡿", "⣟", "⣯", "⣷", "⣾", "⣽", "⣻", "⢿"]
        end_time = time.time() + duration
        
        while time.time() < end_time:
            for frame in frames:
                print(f"\r{text} {frame} ", end="", flush=True)
                time.sleep(0.1)
        print(f"\r{text} ✅")
    
    @staticmethod
    def packet_capture_animation():
        """Show packet capture animation."""
        packets = ["📦", "📫", "📭", "🧩", "🎁"]
        for i in range(10):
            packet = random.choice(packets)
            print(f"\rCapturing packets {packet} {'.' * (i % 4)}", end="", flush=True)
            time.sleep(0.2)
        print("\rCapturing packets 📦 📦 📦 Ready! ")
    
    @staticmethod
    def detective_scan():
        """Show detective scanning animation."""
        print("\n🔍 Detective Mode Activated!")
        frames = [
            "🔍 Scanning.  ",
            "🔍 Scanning.. ",
            "🔍 Scanning...",
            "🕵️‍♂️ Found clues!",
        ]
        for frame in frames:
            print(f"\r{frame}", end="", flush=True)
            time.sleep(0.5)
        print()
    
    @staticmethod
    def progress_bar(iteration: int, total: int, prefix: str = '', suffix: str = '', length: int = 30):
        """Create a colorful progress bar."""
        filled_length = int(length * iteration // total)
        bar = '🟩' * filled_length + '⬜' * (length - filled_length)
        percent = f"{100 * (iteration / float(total)):.1f}"
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
        if iteration == total:
            print()

class CartoonColors:
    """Fun color codes for terminal output."""
    
    # Emoji icons
    ICONS = {
        'info': 'ℹ️',
        'success': '✅',
        'warning': '⚠️',
        'error': '❌',
        'detective': '🕵️‍♂️',
        'packet': '📦',
        'network': '🌐',
        'alert': '🚨',
        'report': '📊',
        'analysis': '🔍',
        'search': '🔎',
        'lock': '🔒',
        'key': '🔑',
        'flag': '🚩',
        'fire': '🔥',
        'rocket': '🚀',
        'computer': '💻',
        'server': '🖥️',
        'signal': '📡',
        'hourglass': '⏳',
        'stopwatch': '⏱️',
        'magic': '✨',
        'tada': '🎉',
        'thinking': '🤔',
        'idea': '💡',
    }
    
    # Color codes
    COLORS = {
        'header': '\033[95m',
        'blue': '\033[94m',
        'cyan': '\033[96m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'red': '\033[91m',
        'bold': '\033[1m',
        'underline': '\033[4m',
        'end': '\033[0m',
    }
    
    @classmethod
    def colorize(cls, text: str, color: str) -> str:
        """Add color to text."""
        return f"{cls.COLORS.get(color, '')}{text}{cls.COLORS['end']}"
    
    @classmethod
    def icon_text(cls, icon: str, text: str, color: str = None) -> str:
        """Combine icon with colored text."""
        icon_str = cls.ICONS.get(icon, '')
        if color:
            return f"{icon_str} {cls.colorize(text, color)}"
        return f"{icon_str} {text}"
    
    @classmethod
    def print_banner(cls):
        """Print the awesome cartoon banner."""
        banner = f"""
{cls.COLORS['cyan']}
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║  {cls.COLORS['yellow']}🎭 {cls.COLORS['bold']}NETFORENSIC TOOLKIT {cls.COLORS['end']}{cls.COLORS['yellow']}🎭{cls.COLORS['cyan']}                      ║
    ║                                                              ║
    ║  {cls.COLORS['green']}🕵️‍♂️  Network Detective | 📦 Packet Sniffer {cls.COLORS['cyan']}         ║
    ║  {cls.COLORS['blue']}🔍  Forensic Analyst  | 📊 Report Generator {cls.COLORS['cyan']}         ║
    ║                                                              ║
    ║              {cls.COLORS['red']}"Unmasking digital mysteries!"{cls.COLORS['cyan']}              ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
{cls.COLORS['end']}
        """
        print(banner)

class FunMessages:
    """Collection of fun, cartoonish messages."""
    
    CAPTURE_START = [
        "🎬 Lights, camera, PACKET ACTION! Starting capture...",
        "📡 Beaming up packets from the network void...",
        "🎣 Casting our packet fishing net into the digital sea...",
        "🕸️ Weaving our web to catch those sneaky packets...",
    ]
    
    ANALYSIS_START = [
        "🔍 Putting on our detective hat for some serious sleuthing...",
        "🧩 Time to solve the packet puzzle!",
        "🔎 Magnifying glass ready for forensic inspection...",
        "🕵️‍♂️ Investigating the digital crime scene...",
    ]
    
    REPORT_GENERATION = [
        "📊 Cooking up a delicious forensic report...",
        "🎨 Painting the digital masterpiece...",
        "📝 Writing the network mystery novel...",
        "✨ Magically conjuring your report...",
    ]
    
    SUSPICIOUS_FOUND = [
        "🚨 RED ALERT! We've got a live one!",
        "🎯 BULLSEYE! Suspicious activity detected!",
        "🔥 FIRE IN THE HOLE! IOC match found!",
        "🎪 Center stage for our suspicious packet!",
    ]
    
    @classmethod
    def get_random_message(cls, category: str) -> str:
        """Get a random fun message from a category."""
        messages = getattr(cls, category.upper(), ["Ready!"])
        return random.choice(messages)