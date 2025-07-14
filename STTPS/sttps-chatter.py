"""
STTPS Protocol - Secure Text Transfer Protocol Secure

THIS IS THE FULL CHATTER SCRIPT (Sender + Receiver in one!!! Crazy right? I definitly didn't vibecode this piece of dogshit AHEM AHEM)

This protocol enables encrypted peer-to-peer messaging over Ethernet (Layer 2),
using raw sockets, a minimalist custom EtherType, and a hybrid crypto scheme (RSA + AES).
This version includes the entire handshake and messaging logic in one fat Python file.

------------------------------------------------------
Frame Structure
------------------------------------------------------
Each Ethernet frame using STTPS contains:

  [1 Byte]  Message Type (msg_type)
  [N Bytes] Payload (depends on type duh)

------------------------------------------------------
Key Exchange Flow (Handshaking)
------------------------------------------------------

1. REQ (0x01) - Request Public Key
   Sent by either peer to kick off a key exchange.

2. KEY (0x02) - RSA Public Key
   Response to REQ. Contains PEM-encoded RSA public key.

3. AES (0x03) - AES Session Key
   Encrypted with peer's public key. 256-bit AES key (CBC mode ftw).

4. ACK (0x05) - Key Exchange Confirmation
   Tells the sender: "Yo I got the key bro. All good."

Short Summary: REQ -> KEY -> AES -> ACK -> secure messaging can begin

------------------------------------------------------
Messaging Phase
------------------------------------------------------

5. MES (0x04) - Encrypted Message
   Encrypted using AES-256-CBC. Your juicy secrets go here.

6. PLA (0x07) - Plaintext Message
   Sent unencrypted. For testing, debug memes, or cyber-suicidal behavior.

------------------------------------------------------
Re-Keying (It's important)
------------------------------------------------------

- After 10 encrypted messages (MES), the sender triggers a new key exchange.
- The receiver reuses its RSA key and just replies again.

------------------------------------------------------
Protocol Notes (Read or perish)
------------------------------------------------------

- Message types are identified by the first byte of the Ethernet payload.
- Padding is manually added if payload < 46 bytes. Or IEEE 802.3 will come and send you to GITMO
- THE ETHERNET FRAME ITSELF IS NOT ENCRYPTED!!! IT'S NOT MAGIC or smth like that????
- If you're confused, that's okay. So was the person who wrote this lol.
- Works best if you're root. Don't ask why. Just 'sudo'.
- just use the broadcast its peer to peer so don't shit yourself 

------------------------------------------------------
Frame Format (Inside the Ethernet payload)
------------------------------------------------------

| msg_type (1 byte) | payload (variable) |

------------------------------------------------------
Comment from the Author (and spiritual guide)
------------------------------------------------------

Go watch Girls und Panzer. !???!???!?!?!??
https://www.youtube.com/watch?v=53UXAffRPkg

------------------------------------------------------
Useful Shit You Might Actually Need
------------------------------------------------------

What's a frame again?:
https://en.wikipedia.org/wiki/Ethernet_frame

EtherType explained:
https://en.wikipedia.org/wiki/EtherType

DEFCON talk about EtherTypes:
https://www.youtube.com/watch?v=1lTcuNHMOcs&t

Made by Lauchpaul
"""


import socket
import os
import threading
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

# ===== CONFIGURATION =====
INTERFACE = "eth0"  # CHANGE THIS SHIT!!! TO YOUR INTERFACE <----------------------------------------------------------------------------------------------------------------------
DEST_MAC = bytes.fromhex("ff ff ff ff ff ff")  # Broadcast MAC
SRC_MAC = bytes.fromhex("DE AD B0 0B 1E 69")   # Spoofed MAC haha boobie how funny  DON'T USE THE SPOOFED MAC TWICE YOU DOOFUS
ETHERTYPE_STTP = b'\x88\xb5'  # Experimental EtherType for STTP
MAX_MESSAGES_BEFORE_REKEY = 10
MAX_STTPS_PAYLOAD = 1400

# ===== CRYPTO KEY MANAGEMENT =====
RSA_PRIVATE_PATH = "chatter_private.pem"
RSA_PUBLIC_PATH = "chatter_public.pem"

aes_key = None
rsa_public_key = None
message_counter = 0
awaiting_ack = False

# ===== RAW SOCKET SETUP =====
try:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((INTERFACE, 0))
except PermissionError:
    print("[!] ERROR: Root permission required. Run with sudo.")
    exit(1)
except OSError as e:
    print(f"[!] ERROR binding to interface '{INTERFACE}': {e}")
    exit(1)

# ===== RSA KEYPAIR LOAD/CREATE =====
def generate_or_load_rsa_keypair():
    if os.path.exists(RSA_PRIVATE_PATH) and os.path.exists(RSA_PUBLIC_PATH):
        with open(RSA_PRIVATE_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(RSA_PUBLIC_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        with open(RSA_PRIVATE_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(RSA_PUBLIC_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    return private_key, public_key

private_key, public_key = generate_or_load_rsa_keypair()

# ===== AES ENCRYPTION FUNCTIONS =====
def encrypt_aes(plaintext, key):
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_aes(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ct) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()

# ===== FRAME SENDER =====
def send_frame(msg_type, payload):
    header = DEST_MAC + SRC_MAC + ETHERTYPE_STTP
    full_payload = bytes([msg_type]) + payload
    if len(full_payload) < 46:
        full_payload += b'\x00' * (46 - len(full_payload))
    frame = header + full_payload
    try:
        sock.send(frame)
    except Exception as e:
        print(f"[!] Failed to send frame: {e}")

# ===== KEY EXCHANGE =====
def initiate_key_exchange():
    global rsa_public_key, aes_key, awaiting_ack, message_counter
    rsa_public_key = None
    aes_key = None
    awaiting_ack = False
    message_counter = 0
    send_frame(0x01, b"")
    print("[*] Key exchange initiated (REQ sent)...")

# ===== FRAME READER THREAD =====
def receive_loop():
    global rsa_public_key, aes_key, awaiting_ack
    while True:
        try:
            frame, _ = sock.recvfrom(65535)
            if not frame or len(frame) < 14:
                continue
            if frame[6:12] == SRC_MAC or frame[12:14] != ETHERTYPE_STTP:
                continue

            payload = frame[14:]
            if len(payload) < 1:
                continue

            msg_type = payload[0]
            body = payload[1:].rstrip(b'\x00')

            if msg_type == 0x01:  # REQ
                pub_key_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                send_frame(0x02, pub_key_bytes)

            elif msg_type == 0x02:  # KEY
                if rsa_public_key is not None:
                    continue
                try:
                    peer_key = serialization.load_pem_public_key(body)
                    local_aes_key = os.urandom(32)
                    encrypted_key = peer_key.encrypt(
                        local_aes_key,
                        rsa_padding.OAEP(
                            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    aes_key = local_aes_key
                    send_frame(0x03, encrypted_key)
                    awaiting_ack = True
                except Exception as e:
                    print(f"[!] Error handling KEY frame: {e}")

            elif msg_type == 0x03:  # AES
                try:
                    decrypted_key = private_key.decrypt(
                        body,
                        rsa_padding.OAEP(
                            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    aes_key = decrypted_key
                    send_frame(0x05, b"AES OK")
                except Exception as e:
                    print(f"[!] Failed to decrypt AES key: {e}")

            elif msg_type == 0x05:  # ACK
                if awaiting_ack:
                    print("[+] ACK received. Secure session established!")
                    awaiting_ack = False

            elif msg_type == 0x04:  # MES (encrypted message)
                if not aes_key:
                    print("[!] Encrypted message received, but no AES key yet.")
                    continue
                try:
                    msg = decrypt_aes(body, aes_key).decode("utf-8")
                    print(f"\r[Peer] {msg}\n> ", end="")
                except Exception as e:
                    print(f"\r[!] Failed to decrypt message: {e}\n> ", end="")

            elif msg_type == 0x07:  # PLA (plaintext message)
                try:
                    print(f"\r[Peer/PLA] {body.decode('utf-8')}\n> ", end="")
                except:
                    print("\r[Peer/PLA] <Invalid UTF-8>\n> ", end="")

        except Exception as e:
            print(f"\n[!] Error in receive loop: {e}")

# ===== USER MESSAGE SENDER =====
def send_message(msg):
    global message_counter
    if not aes_key:
        print("[!] Cannot send: No AES key established.")
        return
    if len(msg.encode("utf-8")) > MAX_STTPS_PAYLOAD:
        print(f"[!] Message too long (max {MAX_STTPS_PAYLOAD} bytes)")
        return
    ciphertext = encrypt_aes(msg, aes_key)
    send_frame(0x04, ciphertext)
    message_counter += 1
    if message_counter >= MAX_MESSAGES_BEFORE_REKEY:
        print("[*] Max messages reached. Re-keying...")
        initiate_key_exchange()

def send_plaintext(msg):
    if len(msg.encode("utf-8")) > MAX_STTPS_PAYLOAD:
        print(f"[!] PLA message too long (max {MAX_STTPS_PAYLOAD} bytes)")
        return
    send_frame(0x07, msg.encode("utf-8"))

# ===== MAIN PROGRAM LOOP =====
if __name__ == "__main__":
    print("=== STTPS Chatter (v2.1 - Refactored) ===")
    print("Use sudo to run this script!")
    print("Available commands: !help, !rekey, !pla <message>")

    threading.Thread(target=receive_loop, daemon=True).start()
    initiate_key_exchange()

    try:
        while True:
            msg = input("> ").strip()
            if not msg:
                continue

            if awaiting_ack:
                print("[!] Waiting for ACK from peer...")
                continue

            if msg.lower() == "!help":
                print("""
Commands:
  !help       - Show this help
  !rekey      - Initiate a new key exchange
  !pla <msg>  - Send plaintext message
  <msg>       - Send encrypted message (if key is available)
""")
            elif msg.lower() == "!rekey":
                initiate_key_exchange()
            elif msg.lower().startswith("!pla"):
                plaintext_msg = msg[4:].strip()
                if not plaintext_msg:
                    print("[!] Please provide a message after !pla")
                    continue
                send_plaintext(plaintext_msg)
                print(f"[You/PLA] {plaintext_msg}")
            else:
                send_message(msg)
                print(f"[You] {msg}")

    except (KeyboardInterrupt, EOFError):
        print("\n[!] Exiting...")
    finally:
        sock.close()
        print("[+] Socket closed.")
