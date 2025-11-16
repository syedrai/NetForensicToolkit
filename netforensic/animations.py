"""Animations and visual effects for NetForensicToolkit."""
import time
import random

class CartoonAnimations:
    @staticmethod
    def typing_effect(text: str, delay: float = 0.03):
        for char in text:
            print(char, end='', flush=True)
            time.sleep(delay)
        print()
    
    @staticmethod
    def loading_animation(text: str = "Loading", duration: int = 3):
        frames = ["⡿", "⣟", "⣯", "⣷", "⣾", "⣽", "⣻", "⢿"]
        end_time = time.time() + duration
        while time.time() < end_time:
            for frame in frames:
                print(f"\r{text} {frame} ", end="", flush=True)
                time.sleep(0.1)
        print(f"\r{text} ✅")
    
    @staticmethod
    def detective_scan():
        print("\n🔍 Detective Mode Activated!")
        frames = ["🔍 Scanning.  ", "🔍 Scanning.. ", "🔍 Scanning...", "🕵️‍♂️ Found clues!"]
        for frame in frames:
            print(f"\r{frame}", end="", flush=True)
            time.sleep(0.5)
        print()

class CartoonColors:
    ICONS = {
        'info': 'ℹ️', 'success': '✅', 'warning': '⚠️', 'error': '❌',
        'detective': '🕵️‍♂️', 'package': '📦', 'network': '🌐', 'alert': '🚨',
        'report': '📊', 'analysis': '🔍', 'search': '🔎', 'rocket': '🚀',
        'computer': '💻', 'stopwatch': '⏱️', 'chart': '📈'
    }
    
    COLORS = {
        'blue': '\033[94m', 'cyan': '\033[96m', 'green': '\033[92m',
        'yellow': '\033[93m', 'red': '\033[91m', 'bold': '\033[1m',
        'end': '\033[0m'
    }
    
    @classmethod
    def colorize(cls, text: str, color: str) -> str:
        return f"{cls.COLORS.get(color, '')}{text}{cls.COLORS['end']}"
    
    @classmethod
    def icon_text(cls, icon: str, text: str, color: str = None) -> str:
        icon_str = cls.ICONS.get(icon, '')
        if color:
            return f"{icon_str} {cls.colorize(text, color)}"
        return f"{icon_str} {text}"
    
    @classmethod
    def print_banner(cls):
        banner = f"""
{cls.COLORS['cyan']}
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║  🎭 NETFORENSIC TOOLKIT 🎭                      ║
    ║                                                              ║
    ║  🕵️‍♂️  Network Detective | 📦 Packet Sniffer          ║
    ║  🔍  Forensic Analyst  | 📊 Report Generator          ║
    ║                                                              ║
    ║              "Unmasking digital mysteries!"              ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
{cls.COLORS['end']}
        """
        print(banner)

class FunMessages:
    CAPTURE_START = [
        "🎬 Lights, camera, PACKET ACTION! Starting capture...",
        "📡 Beaming up packets from the network void...",
        "🎣 Casting our packet fishing net into the digital sea...",
        "🕸️ Weaving our web to catch those sneaky packets...",
    ]
    
    @classmethod
    def get_random_message(cls, category: str) -> str:
        messages = getattr(cls, category.upper(), ["Ready!"])
        return random.choice(messages)
