Payloads

## Evasion Payloads


### meterpreterShell - 

basic meterperer shelll with basic evasion

### Meterprer-6layer-v2 - 
  XOR Layer 1 - Random XOR key (changes each build)
  ROL (Rotate Left) - Bit rotation (random 1-7 bits)
  ADD Encoding - Addition cipher (random key)
  Byte Swapping - Swap adjacent bytes
  XOR Layer 2 - Second random XOR key
  Junk Insertion - Insert marker bytes (0xAA) before each real byte
  AES-256-GCM - Final encryption layer
