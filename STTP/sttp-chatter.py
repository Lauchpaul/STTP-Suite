import socket
import threading

# ========== Configuration ==========
INTERFACE = "en0s31f6"  # Set your network interface name here
DEST_MAC = bytes.fromhex("ff ff ff ff ff ff")  # Broadcast target (I'm too lazy to type the Dest-MAC. It's Point to Point so don't worry my bro)
SRC_MAC = bytes.fromhex("de ad be ef 00 02")  # Spoofed source MAC ig?
STTP_ETHERTYPE = bytes.fromhex("88b5")
MAX_PAYLOAD = 1500 - 14  # Ethernet max payload
MIN_PAYLOAD = 46         # Minimum Ethernet payload to avoid drop

# ========== Setup Raw Socket ==========
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
sock.bind((INTERFACE, 0))

# ========== Receiving Thread ==========
def receive_messages():
    print("[*] Listening for STTP messages...\n")
    while True:
        frame = sock.recv(65535)
        ethertype = frame[12:14]
        if ethertype != STTP_ETHERTYPE:
            continue  # Not an STTP frame (We don't wanna read IPv4 Packets or smth else lol)

        src_mac = ":".join(f"{b:02x}" for b in frame[6:12])
        payload = frame[14:]

        try:
            message = payload.rstrip(b'\x00').decode("utf-8")
        except UnicodeDecodeError:
            message = "<Invalid UTF-8>"

        print(f"\n {src_mac} says:\n{message}\n> ", end="")

# ========== Sending Thread ==========
def send_messages():
    while True:
        try:
            text = input("> ")
            payload = text.encode("utf-8")

            if len(payload) > MAX_PAYLOAD:
                print("Message too long. Limit is ~1486 bytes.")
                continue

            if len(payload) < MIN_PAYLOAD:
                payload += b'\x00' * (MIN_PAYLOAD - len(payload)) # Adding Padding if Neccesary, I don't know if the NIC adds Padding by itself so i just go sure.

            frame = DEST_MAC + SRC_MAC + STTP_ETHERTYPE + payload
            sock.send(frame)

        except KeyboardInterrupt:
            print("\n[!] Exiting chat...")
            break

# ========== Start Chat Threads ==========
if __name__ == "__main__":
    print("=== STTP Layer-2 Chat CLI ===")
    print(f"Using interface: {INTERFACE}")
    print("Press Ctrl+C to exit.\n")

    # Start receiver thread
    receiver_thread = threading.Thread(target=receive_messages, daemon=True)
    receiver_thread.start()

    # Start sender in main thread
    send_messages()
