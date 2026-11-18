#!/bin/bash
set -e

echo "[*] Updating system and installing Tor and dependencies..."
sudo apt update && sudo apt install -y tor python3 python3-pip python3-full

echo "[*] Creating directory structure for logs..."
mkdir -p logs

echo "[*] Configuring Tor hidden service..."
TORRC="/etc/tor/torrc"
HIDDEN_CFG="
# OnionChat Hidden Service Configuration
HiddenServiceDir /var/lib/tor/onionchat/
HiddenServicePort 5000 127.0.0.1:5000
"

# Check if already configured to prevent duplicates
if ! grep -q "OnionChat Hidden Service" "$TORRC"; then
    echo "$HIDDEN_CFG" | sudo tee -a "$TORRC" > /dev/null
    echo "[+] Configuration added to $TORRC"
else
    echo "[*] Tor configuration already exists in $TORRC"
fi

echo "[*] Restarting Tor service..."
sudo systemctl restart tor
sudo systemctl enable tor

echo ""
echo "=========================================="
echo " Server configured successfully!"
echo "=========================================="
echo "To get your .onion address, run:"
echo "  sudo cat /var/lib/tor/onionchat/hostname"
echo ""
echo "To start the server, run:"
echo "  python3 server.py"
echo "=========================================="