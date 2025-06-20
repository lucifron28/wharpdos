#!/usr/bin/env bash

set -e

echo "Setting up the environment..."

if [ ! -f wharpdos.py ]; then
  echo "Error: Run this script from the project root directory (where wharpdos.py is located)."
  exit 1
fi

if ! command -v python3 &>/dev/null; then
  echo "Python3 is not installed. Please install Python3 and try again."
  exit 1
fi

if [ ! -d venv ]; then
  python3 -m venv venv || {
    echo "Failed to create virtual environment. Please check your Python installation."
    exit 1
  }
  echo "Virtual environment created."
fi

source venv/bin/activate
echo "Virtual environment activated."

pip install --upgrade pip

if [ ! -f requirements.txt ]; then
  cat > requirements.txt <<EOF
scapy
rich
prompt_toolkit
colorama
netifaces
pyfiglet
EOF
  echo "requirements.txt created."
fi

pip install -r requirements.txt
echo "Requirements installed."

chmod +x wharpdos.py

echo "Setup complete."
echo "To run: sudo ./wharpdos.py <interface>"
echo "To activate the virtual environment later: source venv/bin/activate"_