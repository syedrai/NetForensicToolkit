#!/bin/bash
echo "🚀 NetForensicToolkit Quick Start"

# Activate environment
source netforensic_env/bin/activate

# Find interfaces
echo "🔍 Available interfaces:"
ip link show | grep -E '^[0-9]+:' | cut -d: -f2

# Start capture
echo "🎬 Starting capture on enp0s3 for 30 seconds..."
sudo -E netforensic capture enp0s3 --duration 30

echo "✅ Check the captures/ folder for your PCAP file!"
