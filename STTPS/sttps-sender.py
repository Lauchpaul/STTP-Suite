"""
STTPS Protocol - Secure Text Transfer Protocol Secure

THIS IS JUST THE SENDER SCRIPT!!!!

This protocol is designed for encrypted peer-to-peer communication over Ethernet (Layer 2),
using a minimal frame format and a hybrid cryptographic model (RSA + AES).

------------------------------------------------------
Frame Structure
------------------------------------------------------
Each Ethernet frame using STTPS contains:

  [1 Byte]  Message Type (msg_type)
  [N Bytes] Payload (varies by type ofcourse lol bruv)

------------------------------------------------------
Key Exchange Flow
------------------------------------------------------

1. REQ (0x01) - Request Public Key
   Sent by the sender when the script starts or when rekeying is required.

2. KEY (0x02) - Send Public Key
   The receiver responds with their RSA public key (PEM-encoded, UTF-8).

3. AES (0x03) - Send AES Session Key
   The sender generates a 256-bit AES key, encrypts it using the received public key,
   and sends it to the receiver. The receiver decrypts it with their private key
   and stores it for message decryption.

4. ACK (0x05) - Acknowledge AES Key
   Sent by the receiver to confirm successful AES key reception.

Short: REQ -> KEY -> AES -> ACK -> MES

------------------------------------------------------
Messaging Phase
------------------------------------------------------

5. MES (0x04) - Encrypted Message
   After key exchange, messages are encrypted with AES (e.g. AES-256-CBC) and sent
   with this type. The receiver uses the shared AES key to decrypt and display them.

6. PLA (0x07) - Plaintext Message
   Unencrypted message. Only used for debugging or test purposes. Or if you're funny and wanna get your weird-ass message get read by someone like wth :skull:

------------------------------------------------------
Re-Keying
------------------------------------------------------

- After 10 encrypted messages (MES), the -> sender <- automatically initiates a new key exchange by sending REQ again.
- The receiver keeps the same RSA key pair and simply responds with KEY again.
- This ensures forward secrecy and limits exposure in case of key compromise.

------------------------------------------------------
Notes
------------------------------------------------------

- Message Types are defined by the first byte of the payload. (By the sender ofcourse bru?)
- Minimum padding is handled manually to meet Ethernet minimum frame size. Or the IEEE 802.3 Comitee gonna kill me :sob:
- THE ETHERNET FRAME ITSELF IS NOT ENCRYPTED!!!!!!
- The user of the pile of dogshit who wrote the code dosen't know what he is doing!!!! SO DONT FUCK ME BRO :skull: 
- If u send a rude DM the author of this code will be veri sad and cry for days. Please don't
- Enjoy or smth like that...
- I could add more Message Type but i didn't even bother with this lol

------------------------------------------------------
Frame-Strcure (In the Ethernet Payload)
------------------------------------------------------
EPOK FRAME:

| Type | Payload | 

------------------------------------------------------
Comment from the Crazy ass dude who wrote this shit
------------------------------------------------------

Go watch Girls und Panzer! It's quite good or smth 

https://www.youtube.com/watch?v=53UXAffRPkg

Mika best gal smh

------------------------------------------------------
Useful shit for you <3
------------------------------------------------------
What the helly is a Frame:
https://en.wikipedia.org/wiki/Ethernet_frame

What the helly is a EtherType:
https://en.wikipedia.org/wiki/EtherType

Funny Defcon thingy about EtherTypes: 
https://www.youtube.com/watch?v=1lTcuNHMOcs&t
"""

import socket
import os
import threading
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

INTERFACE = "eth0" # !CHANGE INTERFACE HERE! <- - - - - - - - - - - - - 
DEST_MAC = bytes.fromhex("ff ff ff ff ff ff")
SRC_MAC = bytes.fromhex("de ad be 42 00 69")
ETHERTYPE_STTP = b'\x88\xb5'
MAX_MESSAGES_BEFORE_REKEY = 10
MAX_STTPS_PAYLOAD = 1400  # <- Max Payload in Bytes

aes_key = None
rsa_public_key = None
message_counter = 0
awaiting_ack = False

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
sock.bind((INTERFACE, 0))

def encrypt_aes(plaintext, key):
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def send_frame(msg_type, payload):
    frame = DEST_MAC + SRC_MAC + ETHERTYPE_STTP
    full_payload = bytes([msg_type]) + payload
    if len(full_payload) < 46:
        full_payload += b'\x00' * (46 - len(full_payload))
    frame += full_payload
    sock.send(frame)

def receive_loop():
    global rsa_public_key, aes_key, awaiting_ack
    while True:
        frame = sock.recv(65535)
        if ETHERTYPE_STTP not in [frame[12:14], frame[14:16], frame[16:18]]:
            continue

        payload = frame[14:]
        if len(payload) < 1:
            continue

        msg_type = payload[0]
        body = payload[1:]

        if msg_type == 0x02:  # KEY
            print("[*] KEY received. Loading public key...")
            try:
                rsa_public_key = serialization.load_pem_public_key(body)
                print("[+] Public key loaded. Generating AES session key...")
                aes_key = os.urandom(32)
                encrypted_key = rsa_public_key.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                send_frame(0x03, encrypted_key)
                print("[*] AES key encrypted and sent.")
                awaiting_ack = True
            except Exception:
                print("[!] Failed to load public key.")
                continue

        elif msg_type == 0x05:  # ACK
            print("[+] ACK received. Encryption ready.")
            awaiting_ack = False

def send_encrypted_message(msg):
    global message_counter, aes_key
    if not aes_key:
        print("[!] No AES key established.")
        return

    if len(msg.encode("utf-8")) > MAX_STTPS_PAYLOAD:
        print(f"[!] Message too long. Max allowed is {MAX_STTPS_PAYLOAD} bytes.")
        return

    ciphertext = encrypt_aes(msg, aes_key)
    send_frame(0x04, ciphertext)
    message_counter += 1
    print(f"[#] Encrypted message sent ({message_counter}/10 before rekey)")

    if message_counter >= MAX_MESSAGES_BEFORE_REKEY:
        print("[*] Re-key threshold reached. Sending REQ...")
        message_counter = 0
        initiate_key_exchange()

def send_plaintext_message(msg):
    encoded = msg.encode("utf-8")
    if len(encoded) > MAX_STTPS_PAYLOAD:
        print("[!] PLA message too long. Max allowed is", MAX_STTPS_PAYLOAD, "bytes.")
        return
    send_frame(0x07, encoded)

def initiate_key_exchange():
    global rsa_public_key, aes_key, awaiting_ack, message_counter
    rsa_public_key = None
    aes_key = None
    awaiting_ack = False
    message_counter = 0
    send_frame(0x01, b"")
    print("[REQ] Public key requested.")

if __name__ == "__main__":
    print("=== STTPS Sender ===")
    print("use !help for commands")
    threading.Thread(target=receive_loop, daemon=True).start()
    initiate_key_exchange()

    try:
        while True:
            msg = input("> ").strip()
            if not msg:
                continue

            if awaiting_ack:
                print("[!] Waiting for ACK. Try again later.")
                continue

            if msg.lower() == "!rekey":
                initiate_key_exchange()
            elif msg.lower() == "!help":
                print("""
STTPS Sender Help:
------------------
!rekey       - Initiates new RSA/AES key exchange
!pla <text>  - Sends plaintext (unencrypted) STTP message (It will have a special Header-Type 0x07)
!help        - Shows this help message
<message>    - Sends encrypted message (if key is established)
""")
            elif msg.lower().startswith("!pla"):
                send_plaintext_message(msg[4:].strip())
            else:
                send_encrypted_message(msg)
    except KeyboardInterrupt:
        print("\nExiting...")
