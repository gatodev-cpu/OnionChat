#!/bin/bash
set -e

echo "[*] Updating system and installing Tor and network dependencies..."
sudo apt update && sudo apt install -y tor python3 python3-pip python3-full

echo "[*] Starting and enabling local Tor service..."
sudo systemctl start tor
sudo systemctl enable tor

echo "[*] Installing Python dependencies (Cryptography, Rich, PySocks)..."
# Use --break-system-packages if your Linux distro blocks global pip installs
if pip3 install --help | grep -q "break-system-packages"; then
    pip3 install --user cryptography rich PySocks --break-system-packages
else
    pip3 install --user cryptography rich PySocks
fi

echo "[*] Creating downloads directory..."
mkdir -p downloads

echo ""
echo "=========================================="
echo " Client configured successfully!"
echo "=========================================="
echo "Make sure Tor is running (port 9050):"
echo "  sudo systemctl status tor"
echo ""
echo "To connect to the .onion server, run:"
echo "  python3 client.py your_server.onion"
echo "=========================================="