#!/bin/bash
echo "🔧 Installing NetForensicToolkit system dependencies..."

# Update system
sudo apt update

# Install Python and pip
sudo apt install -y python3 python3-pip python3-venv

# Install network capture dependencies
sudo apt install -y libpcap-dev tcpdump tshark wireshark-common

# Install additional useful tools
sudo apt install -y git curl wget

echo "✅ System dependencies installed!"
