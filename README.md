# 🎭 NetForensicToolkit

<div align="center">

![NetForensic Toolkit](https://img.shields.io/badge/NetForensic-Toolkit-ff69b4?style=for-the-badge&logo=detective&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white)

**"Unmasking digital mysteries with style! 🕵️‍♂️✨"**

*A professional, cartoonish network forensic analysis toolkit that makes packet analysis fun!*

[![GitHub stars](https://img.shields.io/github/stars/syedrai/NetForensicToolkit?style=social)](https://github.com/syedrai/NetForensicToolkit)
[![GitHub forks](https://img.shields.io/github/forks/syedrai/NetForensicToolkit?style=social)](https://github.com/syedrai/NetForensicToolkit)

</div>

## 📖 Table of Contents

- [🎯 Overview](#-overview)
- [✨ Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [🎪 Installation](#-installation)
- [🕹️ Usage](#️-usage)
- [🔍 Detection Capabilities](#-detection-capabilities)
- [📊 Real Output](#-real-output)
- [🏗️ Project Structure](#️-project-structure)
- [🤝 Contributing](#-contributing)
- [⚖️ Legal Disclaimer](#️-legal-disclaimer)
- [📄 License](#-license)

## 🎯 Overview

NetForensicToolkit is not your average network analysis tool! We've taken powerful forensic capabilities and wrapped them in a delightful, cartoonish interface that makes network analysis feel like a detective game. Under the colorful exterior lies a serious, industry-grade tool capable of professional network forensics.

> **Why be boring when you can solve mysteries in style?** 🎩✨

## ✨ Features

### 🎨 Cartoonish Interface
- **Colorful ASCII Art** banners and headers
- **Animated Loading** sequences with fun emojis
- **Typing Effects** for dramatic reveals
- **Progress Bars** that tell a story
- **Random Fun Messages** for every operation

### 🔧 Professional Capabilities
- **📡 Live Packet Capture** using reliable tcpdump backend
- **🔍 Forensic PCAP Analysis** with deep packet inspection
- **🚨 Suspicious Activity Detection** (port scans, data exfiltration)
- **📊 Basic Reporting** capabilities
- **🎯 IOC Matching** with alert system

### 🕵️‍♂️ Detective Features
- **Real-time Progress** with fun animations
- **Smart Pattern Recognition** for common attack vectors
- **Protocol Analysis** with visual breakdown
- **Network Interface Detection** with automatic fallbacks

## 🚀 Quick Start

### Prerequisites
- **Python 3.10+** 🐍
- **Root/Admin privileges** for packet capture
- **Network interface** to monitor
- **tcpdump** installed on system

### ⚡ Super Quick Start
```bash
# Clone and play!
git clone https://github.com/syedrai/NetForensicToolkit.git
cd NetForensicToolkit

# Install the toolkit
pip install -e .

# Become a network detective! 🕵️‍♂️
sudo /path/to/netforensic_env/bin/netforensic capture eth0 --duration 30
```

## 🎪 Installation

### Method 1: From Source (Recommended)
```bash
# Clone the repository
git clone https://github.com/syedrai/NetForensicToolkit.git
cd NetForensicToolkit

# Install system dependencies (Debian/Ubuntu/Parrot)
sudo apt update
sudo apt install python3 python3-pip python3-venv tcpdump

# Create virtual environment and install
python3 -m venv netforensic_env
source netforensic_env/bin/activate
pip install -e .

# Test your installation
netforensic --help
```

### Method 2: Manual Installation
```bash
# Install Python dependencies
pip install scapy dpkt pandas matplotlib colorama

# Install the toolkit
pip install -e .
```

### Dependencies
The toolkit uses:
- `scapy` - Network packet manipulation 🧙‍♂️
- `dpkt` - PCAP parsing power 🔧
- `pandas` - Data analysis magic 📈
- `matplotlib` - Beautiful charts 🎨
- `colorama` - Cross-platform colors 🌈
- `tcpdump` - Reliable packet capture 📡

## 🕹️ Usage

### 🎬 Capture Network Traffic
```bash
# Basic capture (30 seconds of fun!)
sudo /path/to/netforensic_env/bin/netforensic capture enp0s3 --duration 30

# Or create a helper script for easier use:
echo 'sudo /home/$(whoami)/Desktop/NetForensicToolkit/netforensic_env/bin/netforensic "$@"' > netforensic-sudo.sh
chmod +x netforensic-sudo.sh
./netforensic-sudo.sh capture enp0s3 --duration 30
```

### 🔍 Analyze PCAP Files
```bash
# Analyze with detective mode activated! (no sudo needed)
netforensic analyze captures/capture_*.pcap

# Analyze any PCAP file
netforensic analyze suspicious_traffic.pcap
```

### 📊 Generate Reports
```bash
# Basic report generation
netforensic report capture.pcap --format html
```

### 🚨 Alert Mode with IOC Detection
Create `iocs.txt` in your working directory:
```txt
# Suspicious IPs for real-time detection
# Format: One IP per line, comments start with #

8.8.8.8         # Example: Google DNS (for testing)
1.1.1.1         # Example: Cloudflare DNS
192.168.1.100   # Internal suspicious host
```

## 🔍 Detection Capabilities

### 🎯 What We Detect
| Suspicious Activity | Emoji | Description |
|---------------------|-------|-------------|
| **Port Scanning** | 🎯 | Multiple SYN packets to different ports |
| **Large Data Transfers** | 📤 | Unusually large outbound data flows |
| **IOC Matches** | 🚨 | Communications with blacklisted IPs |
| **Protocol Analysis** | 🔍 | TCP, UDP, ICMP protocol breakdown |

### 🎪 Alert System
```
🚨 RED ALERT! We've got a live one!
   IOC MATCH: 192.168.1.100 → 8.8.8.8
   TYPE: SUSPICIOUS_COMMUNICATION
```

## 📊 Real Output

### 🎨 Actual Capture Session
```bash
🎭 NETFORENSIC TOOLKIT 🎭

🕵️‍♂️  Network Detective | 📦 Packet Sniffer 
🔍  Forensic Analyst  | 📊 Report Generator 

"Unmasking digital mysteries!"

🚀 📡 Beaming up packets from the network void...

════════════════════════════════════════════════════════════
⚙️ CAPTURE CONFIGURATION
════════════════════════════════════════════════════════════
💻 Interface: enp0s3
⏱️ Duration: 30 seconds

🔍 Detective Mode Activated!
🕵️‍♂️ Found clues!

🌐 Starting reliable packet capture...

════════════════════════════════════════════════════════════
🎉 CAPTURE COMPLETE
════════════════════════════════════════════════════════════
✅ Method used: tcpdump
📦 File saved: captures/capture_20251116_062012.pcap
📈 File size: 296.00 B

🎉 SUCCESS! Capture completed successfully!
```

### 🔍 Actual Analysis Results
```bash
🎭 NETFORENSIC TOOLKIT 🎭

🕵️‍♂️ Ready!

════════════════════════════════════════════════════════════
🔍 ANALYSIS STARTING
════════════════════════════════════════════════════════════

════════════════════════════════════════════════════════════
📊 ANALYSIS RESULTS
════════════════════════════════════════════════════════════
📦 Total Packets: 10
🌐 Protocols: TCP, UDP
```

## 🏗️ Project Structure

```
NetForensicToolkit/ 🎭
│
├── netforensic/ 🎪
│   ├── __init__.py
│   ├── cli.py 🎮 # Cartoonish command-line interface
│   ├── capture.py 📡 # Reliable packet capture engine
│   ├── parser.py 🔍 # Forensic analysis engine
│   ├── report.py 📊 # Report generation
│   ├── utils.py ⚙️ # Utility functions
│   └── animations.py 🎬 # Fun animations & effects
│
├── tests/ 🧪
│   ├── test_capture.py
│   ├── test_parser.py
│   └── test_report.py
│
├── captures/ 📦 # Generated PCAP files
├── reports/ 📁 # Generated reports
├── iocs.txt 🚨 # Indicators of Compromise
├── requirements.txt 📋
├── setup.py ⚡
├── install_dependencies.sh 🔧
├── install.sh 🛠️
├── quick_start.sh 🚀
└── README.md 📖
```

## 🎯 Command Reference

### Capture Command
```bash
netforensic capture <interface> [--duration 60] [--output file.pcap]

Options:
  interface    Network interface to monitor (enp0s3, wlan0, eth0, etc.)
  --duration   Capture duration in seconds (default: 60)
  --output     Custom output filename
```

### Analyze Command
```bash
netforensic analyze <pcap>

Options:
  pcap         PCAP file to analyze (supports full paths)
```

### Report Command
```bash
netforensic report <pcap> [--format html]

Options:
  pcap         PCAP file to analyze
  --format     Output format (html)
```

## 🤝 Contributing

We love contributors! Want to add more emojis? Create cooler animations? Improve detection algorithms? Join our detective agency! 🕵️‍♀️

### Contribution Steps:
1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-detective-feature`
3. **Commit** your changes: `git commit -m 'Add some amazing detective feature'`
4. **Push** to the branch: `git push origin feature/amazing-detective-feature`
5. **Open** a Pull Request

### 🎨 Want to Add New Animations?
Check out `animations.py` to add your own cartoonish effects!

### 🚨 Want to Improve Detection?
Extend the analysis methods in `parser.py` to find new suspicious patterns.

## ⚖️ Legal Disclaimer

<div align="center">

**🛑 IMPORTANT: READ THIS BEFORE USING 🛑**

</div>

### 🎯 Authorized Use Only
This tool is designed for:
- ✅ **Authorized** network forensic analysis
- ✅ **Security research** and education  
- ✅ **Incident response** on networks you own
- ✅ **Penetration testing** with explicit permission
- ✅ **Academic research** and learning

### 🚫 Strictly Prohibited
- ❌ **Unauthorized** network monitoring
- ❌ **Network snooping** without explicit consent
- ❌ **Illegal surveillance** activities
- ❌ **Any activity** violating local laws

### 🔒 Your Responsibility
**You are solely responsible for:**
- Ensuring you have proper authorization
- Complying with local laws and regulations
- Respecting privacy and legal boundaries
- Using this tool ethically and responsibly

> **Warning:** Unauthorized use may violate laws and result in serious legal consequences. The developers assume no liability for misuse.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License - Feel free to use, modify, and share!
Just don't blame us if you get caught being naughty 😉
```

## 🆘 Support & Community

### 🐛 Found a Bug?
Open an issue on GitHub and we'll investigate! 🔍

### 💡 Have an Idea?
Suggest new features or improvements!

### 🎉 Want to Show Off?
Share your forensic findings with us!

---

<div align="center">

**Made with ❤️ and too many emojis by Syed Rai**

*"Solving digital mysteries, one packet at a time!"* 🕵️‍♂️📦✨

**[⭐ Star this repo on GitHub](https://github.com/syedrai/NetForensicToolkit)**

</div>

## 🎊 Final Words

Remember: With great packet power comes great responsibility! Use this tool to make the digital world safer, more secure, and a little more fun! 🎉

**Happy detecting!** 🕵️‍♂️🔍✨

---

*P.S. If you enjoy this tool, give it a ⭐ on GitHub! It makes our emojis happy! 😊*

---

<div align="center">

### 🔮 Future Enhancements

We're constantly improving! Upcoming features:
- 🎯 Advanced behavioral analysis
- 📈 Real-time dashboard
- 🔔 Smart alert system
- 🌐 Web interface version

**Stay tuned for more detective adventures!** 🕵️‍♂️✨

</div>
