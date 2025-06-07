#!/usr/bin/bash

# This script sets up the environment for the project

echo "Setting up the environment..."

if ! command -v python3 &>/dev/null; then
  echo "Python3 is not installed. Please install Python3 and try again."
  exit 1
fi

python3 -m venv venv || {
  echo "Failed to create virtual environment. Please check your Python installation."
  exit 1
}
echo "Virtual environment created."
source venv/bin/activate
echo "Virtual environment activated."

# Upgrade pip and install requirements
pip install --upgrade pip
if [ ! -f requirements.txt ]; then
  echo "requirements.txt not found. Please ensure you are in the project root directory."
  exit 1
else
  pip install -r requirements.txt
  echo "Requirements installed."
fi

if [ -f wharpdos.py ]; then
  chmod +x wharpdos.py
else
  echo "wharpdos.py not found. Please ensure you are in the project root directory."
  exit 1
fi

echo "Setup complete. You can now run the project using 'sudo ./wharpdos.py <interface>'."
echo "To activte the virtual environment in the future, run 'source venv/bin/activate'."
# Note: Make sure to run this script from the root directory of the project.
