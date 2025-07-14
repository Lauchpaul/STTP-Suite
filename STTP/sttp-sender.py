import socket

# STTP Experimental EtherType im gonna use Fromhex because i'm kinda scared that it wont work 
ethertype = bytes.fromhex("88b5")

# Destination and source MAC (change dest_mac to real target if needed or just Broadcast it)
destination_mac = bytes.fromhex("ff ff ff ff ff ff") # Fuck me but im gonna broadcast this lol 
source_mac = bytes.fromhex("b0 0b 1e 69 69 69") # I'm gonna spoof this shit i guess lol like why should i use my real MAC?????

# Get user input and encode as UTF-8
message = input("Enter your STTP message: ")
payload = message.encode("utf-8")

# Max payload size (Ethernet = 1500 - 14 bytes header (Ethernet Header))
MAX_PAYLOAD = 1500 - 14
if len(payload) > MAX_PAYLOAD:
    raise ValueError("Payload too large for one Ethernet frame (max ~1486 bytes).")

# Pad if necessary
if len(payload) < 46:
    payload += b'\x00' * (46 - len(payload))

# Build full Ethernet frame
frame = destination_mac + source_mac + ethertype + payload

# Create Layer-2 raw socket
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
sock.bind(("eth0", 0))  # <- replace 'eth0' with your actual interface or it won't work 

# Send the frame
sock.send(frame)

print("STTP frame sent.")
