"""
    This is a Theoretical Test Version of the Script without the "sender-function" Its just for testing purposes.
    Note0: This was my first Script of the STTP-Protocol-Suite-Project.
    Note1: The Preambel with SFD and the FCS is made by the NIC itself. So don't fucking kill me for that lol.
    Note2: I'm not a great coder so don't expect the code to be fucking great or smth... 
    Note3: You can send about 1000 characters per Frame. I won't defragment it yet because i'm too shit to know how to lol.
    Note4: Forgot to mention that script in the README.md bruh.
"""

import socket

# Destination and source MAC addresses (6 bytes each)
destination_mac = bytes.fromhex("de ad be ef 00 01")
source_mac = bytes.fromhex("de ad be ef 00 02")

# EtherType for STTP: 0x88B5 (experimental)
ethertype = bytes.fromhex("88b5")

"""
Note5: I'm using the experimental EtherType 0x88B5. According to the IEEE/IANA registry,
the range 0x88B0-0x88BF is reserved for local/experimental use and should not conflict
with any globally assigned protocol. (At least... that's the plan)

https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
"""

# Get message from user input and encode as UTF-8
message = input("Enter your STTP message: ")
payload = message.encode("utf-8")

# Checks if the Message is bigger than 1486 Bytes (Ethernet Frame Limit (Well... Jumbo frames can be bigger but we'll Ignore that lol))
MAX_PAYLOAD = 1500 - 14  # 1486 bytes

if len(payload) > MAX_PAYLOAD:
    raise ValueError("Payload too large for one Ethernet frame (max ~1486 bytes).")

# Pad payload if it's smaller than Ethernet minimum (46 bytes)
if len(payload) < 46:
    payload += b'\x00' * (46 - len(payload))

# Build the Ethernet frame
frame = destination_mac + source_mac + ethertype + payload

# Print frame info
print("UTF-8 encoded payload:", payload)
print("Final Ethernet frame (hex):", frame.hex())
