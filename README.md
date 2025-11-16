# 🎭 NetForensicToolkit

<div align="center">

![NetForensic Toolkit](https://img.shields.io/badge/NetForensic-Toolkit-ff69b4?style=for-the-badge&logo=detective&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white)

**"Unmasking digital mysteries with style! 🕵️‍♂️✨"**

*A professional, cartoonish network forensic analysis toolkit that makes packet analysis fun!*

</div>

## 📖 Table of Contents

- [🎯 Overview](#-overview)
- [✨ Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [🎪 Installation](#-installation)
- [🕹️ Usage](#️-usage)
- [🔍 Detection Capabilities](#-detection-capabilities)
- [📊 Sample Output](#-sample-output)
- 🏗️ [Project Structure](#️-project-structure)
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
- **📡 Live Packet Capture** with real-time IOC detection
- **🔍 Forensic PCAP Analysis** with deep packet inspection
- **🚨 Suspicious Activity Detection** (port scans, data exfiltration, beaconing)
- **📊 Professional Reporting** in HTML and JSON formats
- **🎯 IOC Matching** with real-time alerts

### 🕵️‍♂️ Detective Features
- **Real-time Alerts** with fun animations
- **Smart Pattern Recognition** for common attack vectors
- **Timeline Reconstruction** of network events
- **Top Talker Analysis** with visual rankings
- **Protocol Breakdown** with colorful charts

## 🚀 Quick Start

### Prerequisites
- **Python 3.10+** 🐍
- **Root/Admin privileges** for packet capture
- **Network interface** to monitor

### ⚡ Super Quick Start
```bash
# Clone and play!
git clone https://github.com/your-org/NetForensicToolkit.git
cd NetForensicToolkit
pip install -e .

# Become a network detective! 🕵️‍♂️
sudo netforensic capture eth0 --duration 30
```

## 🎪 Installation

### Method 1: PIP Installation (Recommended)
```bash
pip install netforensic-toolkit
```

### Method 2: From Source
```bash
# Clone the repository
git clone https://github.com/your-org/NetForensicToolkit.git
cd NetForensicToolkit

# Install with all the cartoonish goodness
pip install -r requirements.txt
pip install -e .

# Test your installation
netforensic --help
```

### Dependencies
The toolkit automatically installs:
- `scapy` - Packet capture wizardry 🧙‍♂️
- `dpkt` - PCAP parsing power 🔧
- `pandas` - Data analysis magic 📈
- `matplotlib` - Beautiful charts 🎨
- `colorama` - Windows color support 🌈

## 🕹️ Usage

### 🎬 Capture Network Traffic
```bash
# Basic capture (30 seconds of fun!)
sudo netforensic capture eth0 --duration 30

# Capture with custom output
sudo netforensic capture wlan0 --duration 60 --output my_mystery_capture.pcap

# Watch the magic happen! ✨
```

### 🔍 Analyze PCAP Files
```bash
# Analyze with detective mode activated!
netforensic analyze suspicious_traffic.pcap

# Get the full story with custom output
netforensic analyze mystery.pcap --output case_analysis.json
```

### 📊 Generate Forensic Reports
```bash
# HTML report with beautiful charts
netforensic report capture.pcap --format html

# JSON report for your forensic tools
netforensic report capture.pcap --format json

# Both reports because why choose?
netforensic report capture.pcap --format both

# Custom output directory
netforensic report capture.pcap --format html --output ./reports/
```

### 🚨 Alert Mode with IOC Detection
Create `iocs.txt` in your working directory:
```txt
# Suspicious IPs for real-time detection
# Format: One IP per line, comments start with #

93.184.216.34    # Known malicious IP
192.168.1.100    # Internal threat
10.0.0.50        # Suspicious server
```

When capturing, the toolkit will alert you in real-time! 🚨

## 🔍 Detection Capabilities

### 🎯 What We Detect
| Suspicious Activity | Emoji | Description |
|---------------------|-------|-------------|
| **Port Scanning** | 🎯 | Multiple SYN packets to different ports |
| **Large Data Transfers** | 📤 | Unusually large outbound data flows |
| **Beaconing Patterns** | ⏰ | Regular communication intervals |
| **IOC Matches** | 🚨 | Communications with blacklisted IPs |
| **Protocol Anomalies** | 🤔 | Unusual protocol usage patterns |
| **Failed Connections** | ❌ | Multiple RST packets and failed attempts |

### 🎪 Alert System
```
🚨 RED ALERT! We've got a live one!
   IOC MATCH: 192.168.1.100 → 8.8.8.8
   TYPE: PORT_SCAN | SEVERITY: HIGH 🎯
```

## 📊 Sample Output

### 🎨 Capture Session
```bash
🎭 NETFORENSIC TOOLKIT 🎭

🕵️‍♂️  Network Detective | 📦 Packet Sniffer 
🔍  Forensic Analyst  | 📊 Report Generator 

"Unmasking digital mysteries!"

🎬 Lights, camera, PACKET ACTION! Starting capture...

⚙️ CAPTURE CONFIGURATION
📡 Interface: eth0
⏱️ Duration: 30 seconds
🎯 Mode: Time-based

🔍 Detective Mode Activated!
📦 Capturing packets... 📦 📦 📦 Ready!

🚨 RED ALERT! We've got a live one!
   IOC MATCH: 192.168.1.100 → 8.8.8.8

🎉 CAPTURE COMPLETE
✅ Packets captured: 1,247
📦 File saved: captures/capture_20231201_143022.pcap

🎉 SUCCESS! Capture completed successfully!
✨ Operation completed successfully!
```

### 🔍 Analysis Results
```bash
🔍 Putting on our detective hat for some serious sleuthing...

🔍 FORENSIC ANALYSIS IN PROGRESS
🕵️‍♂️ Analyzing packets |🟩🟩🟩🟩🟩🟩🟩⬜⬜⬜| 70.0% 

📊 ANALYSIS RESULTS
📦 Total Packets: 1,247
⏱️ Duration: 12.45s
🌐 Protocols Found: TCP, UDP, ICMP
🚨 Suspicious Activities: 3
🔥 IOC Matches: 1

🚨 HIGH SEVERITY FINDINGS:
   🚨 PORT_SCAN from 192.168.1.100
```

## 🏗️ Project Structure

```
NetForensicToolkit/ 🎭
│
├── netforensic/ 🎪
│   ├── __init__.py
│   ├── cli.py 🎮 # Cartoonish command-line interface
│   ├── capture.py 📡 # Packet capture with animations
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
└── README.md 📖
```

## 🎯 Command Reference

### Capture Command
```bash
netforensic capture <interface> [--duration 60] [--output file.pcap]

Options:
  interface    Network interface to monitor (eth0, wlan0, etc.)
  --duration   Capture duration in seconds (default: 60)
  --output     Custom output filename
```

### Analyze Command
```bash
netforensic analyze <pcap> [--output analysis.json]

Options:
  pcap         PCAP file to analyze
  --output     Save analysis results to JSON file
```

### Report Command
```bash
netforensic report <pcap> [--format html|json|both] [--output dir]

Options:
  pcap         PCAP file to analyze
  --format     Output format (default: html)
  --output     Custom output directory
```

## 🤝 Contributing

We love contributors! Want to add more emojis? Create cooler animations? Improve detection algorithms? Join our detective agency! 🕵️‍♀️

### Contribution Steps:
1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-detective-feature`
3. **Commit** your changes: `git commit -m 'Add some amazing detective feature'`
4. **Push** to the branch: `git push origin feature/amazing-detective-feature`
5. **Open** a Pull Request

### 🎨 Adding New Animations
Check out `animations.py` to add your own cartoonish effects!

### 🚨 Adding New Detections
Extend the `_detect_anomalies()` method in `parser.py` to find new suspicious patterns.

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

**Made with ❤️ and too many emojis by the NetForensic Detective Agency**

*"Solving digital mysteries, one packet at a time!"* 🕵️‍♂️📦✨

</div>

## 🎊 Final Words

Remember: With great packet power comes great responsibility! Use this tool to make the digital world safer, more secure, and a little more fun! 🎉

**Happy detecting!** 🕵️‍♂️🔍✨

---

*P.S. If you enjoy this tool, give it a ⭐ on GitHub! It makes our emojis happy! 😊*