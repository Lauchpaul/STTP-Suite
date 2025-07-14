"""
STTPS Protocol - Secure Text Transfer Protocol Secure

THIS IS JUST THE RECIEVER SCRIPT!!!!

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
- fuck this
- If u send a rude DM the author of this code will be veri sad and cry for days. Please don't :(
- Enjoy or smth like that...
- I could add more Message Type but i didn't even bother with this lol

------------------------------------------------------
Frame-Strcure (In the Ethernet Payload)
------------------------------------------------------
EPOK FRAME:

| Type | Payload |                                                                                                                    | hopes and dreams from the author

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
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

INTERFACE = "eth0"
ETHERTYPE_STTP = b'\x88\xb5'
RSA_PRIVATE_PATH = "receiver_private.pem"
RSA_PUBLIC_PATH = "receiver_public.pem"
AES_KEY = None

def generate_or_load_rsa_keypair(): # Making the keypair for the key exchange
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
        with open(RSA_PUBLIC_PATH, "wb") as f: # Forgot to mention that i am only making this Confedential but the Integrety could be theoretically be hurt. Be hurt? I think how you formulate it?
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    return private_key, public_key

private_key, public_key = generate_or_load_rsa_keypair()

# You don't know how long  it took to fucking notice that i have to remove the MTU PADDING FIRST BEFORE DECODING THE FUCKING PAYLOAD I AM SUCH A FUCKING IDIOT
def decrypt_aes(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ct) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()

def handle_frame(frame): # Handle Frame, the fuck, cmon you can do better Lauchpaul
    global AES_KEY
    if frame[12:14] != ETHERTYPE_STTP:
        return
    payload = frame[14:]
    if len(payload) < 1:
        return

    msg_type = payload[0]
    body = payload[1:]

    if msg_type == 0x01:  # REQ
        print("[*] REQ received. Sending public key...")
        key_payload = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        send_frame(0x02, key_payload) # After REQ the Key will be sent to the Reciver.
        print("[*] KEY sent.")

    elif msg_type == 0x03:  # AES Key Request
        print("[*] AES key received. Attempting to decrypt...")
        try:
            AES_KEY = private_key.decrypt(
                body,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("[+] AES key successfully decrypted.")
            send_frame(0x05, b"AES OK")
            print("[+] ACK sent.")
        except Exception:
            print("[!] Failed to decrypt AES key.")

    elif msg_type == 0x04 and AES_KEY:
        try:
            clean_body = body.rstrip(b'\x00')
            msg = decrypt_aes(clean_body, AES_KEY).decode("utf-8")
            print(f"[Encrypted] {msg}")
        except Exception as e:
            print("[!] Failed to decrypt message:", e)

    elif msg_type == 0x07:
        try:
            msg = body.rstrip(b'\x00').decode("utf-8")
            print(f"[Plaintext] {msg}")
        except:
            print("[PLA] <Invalid UTF-8>")

def send_frame(msg_type, payload):
    frame = b'\xff\xff\xff\xff\xff\xff' #Fuck fromhex im a sigma and i use smth else now idk????
    frame += b'\xde\xad\xbe\x42\x00\x69' #Source mac is Hardcoded uhm yeah. Fuck me for that :p
    frame += ETHERTYPE_STTP
    full_payload = bytes([msg_type]) + payload
    if len(full_payload) < 46:
        full_payload += b'\x00' * (46 - len(full_payload))
    frame += full_payload
    sock.send(frame)

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) # I don't know what the fuck i did there. 
sock.bind((INTERFACE, 0))
print(f"[+] STTPS Receiver listening on {INTERFACE}")

while True:
    frame = sock.recv(65535)
    handle_frame(frame)
