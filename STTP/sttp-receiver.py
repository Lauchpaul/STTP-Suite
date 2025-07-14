"""
Note1: This Script detects only the Ethertype 0x88B5 so if you use the other Expiremantal Types it won't work! 
The script just recives things...
"""
import socket

# Configuration
INTERFACE = "en0s31f6"  # Change Interface here lol!!! <-------------------------------------------------------------
STTP_ETHERTYPE = b'\x88\xb5'

# Create raw socket for Layer 2
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
sock.bind((INTERFACE, 0))

print(f"[*] Listening on interface '{INTERFACE}' for STTP frames...")

while True:
    frame = sock.recv(65535)  # receive full frame
    ethertype = frame[12:14] 
    
    if ethertype != STTP_ETHERTYPE:
        continue  # skip non-STTP frames

    src_mac = ":".join(f"{b:02x}" for b in frame[6:12])
    payload = frame[14:]  # everything after the ethernet Header...

    try:
        message = payload.rstrip(b'\x00').decode("utf-8")
    except UnicodeDecodeError:
        message = "<Invalid UTF-8>" # If UTF-8 isn't readable but it should.

    print(f"\nSTTP Message received from {src_mac}:\n{message}")
