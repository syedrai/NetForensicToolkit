#!/bin/bash
echo "🎭 Installing NetForensicToolkit..."

# Create virtual environment
python3 -m venv netforensic_env
source netforensic_env/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install Python dependencies
pip install scapy dpkt pandas matplotlib colorama

# Install the package
pip install -e .

echo "✅ NetForensicToolkit installed successfully!"
echo "🚀 Usage: source netforensic_env/bin/activate && netforensic --help"
