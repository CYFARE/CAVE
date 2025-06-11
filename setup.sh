#!/bin/bash
# Exit immediately if a command exits with a non-zero status.
set -e

echo "[*] Installing Python dependencies via pip..."
if command -v pip &> /dev/null; then
    pip install -r requirements.txt
elif command -v pip3 &> /dev/null; then
    pip3 install -r requirements.txt
else
    echo "[!] pip/pip3 not found. Please install Python pip."
    exit 1
fi

echo "[*] Checking for MinGW-w64 cross-compiler..."
# Check for both C and C++ compilers
if command -v x86_64-w64-mingw32-gcc &> /dev/null && command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo "[+] MinGW-w64 is already installed."
else
    echo "[*] Attempting to install MinGW-w64..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y mingw-w64
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y mingw64-gcc-c++ mingw64-gcc
    elif command -v pacman &> /dev/null; then # Corrected 'pacman &' to 'pacman &> /dev/null;'
        sudo pacman -S --noconfirm mingw-w64-gcc
    else
        echo "[!] Unsupported package manager. Please install MinGW-w64 (x86_64-w64-mingw32-gcc/g++) manually."
        exit 1
    fi
fi

echo ""
echo "[SUCCESS] Setup is complete. You are ready to use CAVE."
chmod +x setup.sh