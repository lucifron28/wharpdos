#!usr/bin/bash

# This script sets up the environment for the project
echo "Setting up the environment..."
python3 -m venv venv
echo "Virtual environment created."
source venv/bin/activate
echo "Virtual environment activated."

# Upgrade pip and install requirements
pip install --upgrade pip
pip install -r requirements.txt
echo "Requirements installed."

chmod +x wharpdos.py

echo "Setup complete. You can now run the project using 'sudo ./wharpdos.py <interface>'."
# Note: Make sure to run this script from the root directory of the project.
