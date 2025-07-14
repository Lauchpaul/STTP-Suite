#!/usr/bin/env python3
"""
ESTTPS Chatter (Final Version)

Commands:
!help               Show this command list
!list               Show all seen participants
!detail on|off      Toggle verbose logging
!whoami             Show your current status
!clear              Clear the screen
!exit               Quit the program
!chn <name>         Change your local username
!dm <name>          Start a DM with <name>
!accept <name>      Accept a pending DM request (clears screen for both)
!deny <name>        Deny a pending DM request
!broadcast          Leave a DM and return to broadcast mode
!rel | !unrel       Toggle reliable mode (only in DMs)
!pla <text>         Send plaintext message in the current DM
!rekey              Perform a manual re-key in the current DM
!debug <test>       Send a debug packet. Tests: bad_crc, send_err <msg>
"""

# Now the real shit

"""
ESTTPS Protocol - Extended Text Transfer Protocol Secure

THIS IS THE FULL CHATTER SCRIPT (It's a client, a server, a daemon, and probably sentient. I definitely didn't just keep asking an LLM to "add one more thing" until this beautiful monster was born. AHEM. The fuck, like how am i supposed to know how to make CRC16 work)

This protocol enables encrypted, reliable, peer-to-peer messaging directly over Ethernet (Layer 2). It uses raw sockets, a custom EtherType, and a hybrid crypto scheme (RSA + AES). It has more features than it has any right to, all crammed into one glorious Python file.

---
### Frame Structure
Each Ethernet frame payload is meticulously crafted. Forget simple, we do complex.

'[ESTTPS Header (8 Bytes)] [Username (20 Bytes)] [Payload (Variable)]'

**The 8-Byte Header Breakdown:**

* **[1 Byte] Type:** What *is* this packet? A message, a request, an ACK?
* **[1 Byte] Flags:** The packet's "options menu." Is it encrypted? Reliable? An error?
* **[2 Bytes] Session ID (SID):** Keeps track of which DM is which. Or Broadcast idk AHEM 
* **[2 Bytes] Length:** How long the Username + Payload part is.
* **[2 Bytes] CRC16:** A checksum to make sure the header didn't get mangled in transit. If it did, the packet gets yeeted into the void.

**The Almighty Flags Field:**
The Flags byte works like 8 light switches. It tells the receiver how to handle the packet. Key switches include 'ENC' (encrypted), 'REL' (reliable), 'FRG' (fragmented), 'FIN' (session end), and more.

---
### DM Session Flow (Handshaking)
You don't just "send" a DM. You perform a sacred ritual.

1.  **REQ (0x01) - Request DM:** You ask someone to chat. '!dm <user>'
    * 'You --- (REQ) ---> Them'

2.  **ACC (0x06) + KEY (0x02) - Accept & Public Key:** They accept. They send back an "OK" and their public key so you can whisper secrets.
    * 'You <--- (ACC + KEY) --- Them'

3.  **AES (0x03) - Secret Handshake:** You create a secret one-time password (an AES key), encrypt it with their public key, and send it over.
    * 'You --- (Encrypted AES Key) ---> Them'

4.  **ACK (0x05) - Session Ready:** They get the key and send a final thumbs-up. The secure channel is now open.
    * 'You <--- (Session ACK) --- Them'

5.  **MES (0x04) - Session Ready:** You send your weird ass text to your Crush which isn't real. Its just another Terminal with some weird-ass Waifu in it i don't think girls know what ISO/OSI is yk???.
    * 'You <--- (Session ACK) --- Astolfo (Cus Femboy ig???)'

**Short Summary:** 'REQ -> ACC/KEY -> AES -> ACK'. Now you can message securely.

---
### Reliable (REL) Messaging Flow
For when your message absolutely, positively has to get there. (Only works in DMs).

1.  **MES/PLA + REL Flag + SEQ_NUM:** You send a message with the 'REL' flag turned on. The message secretly contains a sequence number.
    * 'You --- (Message + REL + SEQ) ---> Them'

2.  **MSG_ACK + SEQ_NUM:** The receiver gets it and immediately sends back a tiny ACK packet containing the *same sequence number*.
    * 'You <--- (MSG_ACK + SEQ) --- Them'

3.  **Confirmation:** You receive the ACK and get a confirmation '[v] Message delivered'.

**What if the ACK gets lost?** A background demon ('retransmission_demon') gets angry, waits 5 seconds, and **resends the message** up to 3 times. :Scary demon Picture.png:
---
### Session Management
Leaving a DM is also a formal affair.

1.  **FIN (0x09) - Finish:** You type '!broadcast'. Your client sends a 'FIN' packet to your partner.
2.  **Auto-Switch:** Your partner's client receives the 'FIN', notifies them that you left, and automatically switches them back to broadcast mode. No ghost sessions lol.

---
### Messaging Phase

* **MES (0x04) - Encrypted Message:** Encrypted with the session's AES key. The default for DMs.
* **PLA (0x07) - Plaintext Message:** Sent unencrypted. For '!pla' command, initial "Hello World", or general recklessness.

---
### Protocol Notes (The Fine Print)
* Our custom EtherType is **0x88B5**. We are a special snowflake on the network. (Haha so edgy >.<)
* The **Header** is protected by CRC16. 
* **Fragmentation** is handled automatically. If you send a message bigger than 1400 bytes, it gets chopped up and reassembled. You don't have to do anything. It just works (Hopfully).
* If you're confused, that's a sign that you're paying attention.
* Works best if you're root. Don't ask questions. Just 'sudo' and give me access to your Network card :).

---
### Comment from the Author (and your spiritual guide)

Go watch Girls und Panzer.
https://www.youtube.com/watch?v=53UXAffRPkg

Don't watch this shit in English :)
---
Made by Lauchpaul and a very patient LLM. Thanks Gemini and ChatGPT! d: 


What do you expect from a Network engineer????? That i know how to programm hahahaaha No.
"""

# -------------------------------------------
# Frame-Types (hex)
# 0x01 REQ       – Key Request (SYN)
# 0x02 KEY       – RSA Public Key
# 0x03 AES       – Encrypted AES session key
# 0x04 MES       – Encrypted message
# 0x05 ACK       – Session ready
# 0x06 ACC       – DM accepted
# 0x07 PLA       – Plaintext message
# 0x08 MSG_ACK   – Message acknowledgement for REL mode
# 0x09 FIN       - End DM session
# -------------------------------------------

import argparse, os, random, socket, struct, sys, threading, re, readline, subprocess, time
from collections import defaultdict

# Cryptography imports for RSA and AES
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_pad, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ───────────── Constants ─────────────
ETHERTYPE_ESTTPS = b"\x88\xb5"  # Custom EtherType to identify our protocol's frames.
NAME_LEN         = 20           # Fixed length for username field in the packet.
MAX_PAYLOAD      = 1400         # Maximum size of the data payload before fragmentation is needed.
HEADER_LEN       = 8            # Length of the ESTTPS header (Type, Flags, SID, Length, CRC).
BROADCAST_MAC    = "ff:ff:ff:ff:ff:ff"  # The Ethernet broadcast address.
MAC_RE           = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I) # Regex for validating MAC addresses.

# --- Flags & Protocol Types (used in the 'flags' field of the header) ---
# Each flag is a single bit that can be combined with others using bitwise OR.
FLAG_ENC = 1 << 0  # Bit 0: Payload is encrypted.
FLAG_FRG = 1 << 1  # Bit 1: Packet is a fragment of a larger message.
FLAG_LST = 1 << 2  # Bit 2: This is the LAST fragment of a message.
FLAG_SYN = 1 << 3  # Bit 3: Packet is a session synchronization request.
FLAG_ACK = 1 << 4  # Bit 4: Packet is an acknowledgment.
FLAG_FIN = 1 << 5  # Bit 5: Packet is a session finish request.
FLAG_ERR = 1 << 6  # Bit 6: Packet signals a protocol error.
FLAG_REL = 1 << 7  # Bit 7: Message requires reliable delivery (needs an ACK).

FRAME_TYPE_MSG_ACK = 0x08  # Packet type for a reliable message ACK.
FRAME_TYPE_FIN = 0x09      # Packet type for ending a session.

# --- Timeout Configuration for REL mode ---
RETRANSMISSION_TIMEOUT = 5  # Seconds to wait for an ACK before resending.
MAX_RETRIES = 3             # Maximum number of retransmission attempts.

# --- CRC-16-CCITT Calculation Constants ---
CRC_INIT, CRC_POLY = 0xFFFF, 0x1021
def crc16(buf: bytes) -> int:
    """Calculates the CRC-16-CCITT checksum for a given buffer."""
    crc = CRC_INIT
    for b in buf:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ CRC_POLY) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

# ───────────── Crypto Helpers ─────────────
def aes_encrypt(data, key):
    """Encrypts data using AES-256 in CBC mode with a random IV."""
    iv, padder = os.urandom(16), sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # The IV is prepended to the ciphertext for use during decryption.
    return iv + encryptor.update(padded) + encryptor.finalize()

def aes_decrypt(blob, key):
    """Decrypts an AES-256 blob that has the IV prepended."""
    iv, ct = blob[:16], blob[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decrypt = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(decrypt) + unpadder.finalize()

# ───────────── Utility Functions ────────────
def get_mac_address(iface: str) -> str | None:
    """
    Automatically detects the MAC address for a given network interface.
    Works on both Linux (by reading /sys) and Windows (by parsing ipconfig).
    """
    iface = iface.lower()
    try:
        if sys.platform == "linux":
            with open(f'/sys/class/net/{iface}/address') as f: return f.read().strip()
        elif sys.platform == "win32":
            output = subprocess.check_output(f'ipconfig /all', shell=True, stderr=subprocess.DEVNULL).decode('latin-1')
            lines = output.splitlines()
            for i, line in enumerate(lines):
                if 'adapter ' in line.lower() and iface in line.lower():
                    for j in range(i, len(lines)):
                        if 'physical address' in lines[j].lower():
                            return lines[j].split(':')[-1].strip().replace('-', ':').lower()
    except Exception: return None
    return None

def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def pad_name(n):
    """Pads or truncates a name to the fixed NAME_LEN."""
    return n.encode()[:NAME_LEN].ljust(NAME_LEN, b"\x00")

def mac_bytes(m):
    """Converts a string MAC address 'de:ad:be:ef' to bytes b'\\xde\\xad\\xbe\\xef'."""
    return bytes.fromhex(m.replace(":", ""))

def build_header(t, f, sid, ln):
    """
    Constructs the 8-byte ESTTPS header.
    It packs the fields and appends a CRC-16 checksum of the first 6 bytes.
    """
    pre = struct.pack("!BBHH", t, f, sid, ln) # Type, Flags, SID, Length
    return pre + struct.pack("!H", crc16(pre)) # Append CRC

def parse_header(buf):
    """
    Parses an 8-byte ESTTPS header and validates its CRC checksum.
    Raises a ValueError if the CRC is incorrect.
    """
    t, f, sid, ln, crc = struct.unpack("!BBHHH", buf)
    if crc16(buf[:6]) != crc:
        raise ValueError("Invalid CRC")
    return t, f, sid, ln

# ───────────── Global State Variables ─────────────
participant_map   = {}          # Maps MAC addresses to usernames.
pending_reqs      = set()         # Usernames from whom we have a pending DM request.
session_map       = defaultdict(dict) # Maps a target username to their session info (MAC, SID, AES key, etc.).
unacked_messages  = {}          # Stores reliable messages waiting for an ACK. Key: (sid, seq).
reasm_buffer      = {}          # Reassembly buffer for fragmented messages. Key: (mac, sid).
current_mode      = "broadcast"   # The user's current mode ("broadcast" or "dm").
current_target    = None          # The username of the current DM target.
verbose           = False         # Toggles verbose debug output.
reliable_mode     = False         # Toggles REL/UNREL mode for DMs.
state_lock        = threading.RLock() # A re-entrant lock to protect all shared state variables from race conditions.

# ───────────── RSA Key Pair ─────────────
def load_or_gen():
    """Loads a private RSA key from 'priv.pem' or generates a new one if it doesn't exist."""
    if os.path.exists("priv.pem"):
        with open("priv.pem", "rb") as f: priv = serialization.load_pem_private_key(f.read(), None)
    else:
        priv = rsa.generate_private_key(65537, 2048)
        with open("priv.pem", "wb") as f:
            f.write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return priv, priv.public_key()
priv_key, pub_key = load_or_gen()

# ───────────── Socket Helper ─────────────
def open_sock(iface):
    """Opens a raw socket on the specified interface to send/receive raw Ethernet frames."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((iface, 0))
    return s

# ───────────── Thread-Safe Print ─────────────
def get_prompt():
    """Generates the command prompt string based on the current state."""
    mode_str = f"{current_mode}:{current_target}" if current_target else current_mode
    rel_str = "REL" if reliable_mode else "UNREL"
    return f"[{mode_str}|{rel_str}]# "
    
def safe_print(msg):
    """
    A thread-safe print function to prevent background thread output from
    messing up the user's active input prompt.
    """
    with state_lock:
        # Get the user's current, un-submitted input
        buffer = readline.get_line_buffer()
        # Erase the current line (prompt + user input)
        sys.stdout.write(f"\r{' ' * (len(get_prompt()) + len(buffer))}\r")
        # Print the new message from the background thread
        sys.stdout.write(msg + '\n')
        # Redraw the prompt and the user's original input
        sys.stdout.write(get_prompt() + buffer)
        sys.stdout.flush()

# ───────────── Chatter Class ─────────────
class Chatter:
    """Main class to handle all sending and receiving logic."""
    def __init__(self, iface, mac, name):
        self.iface, self.src_mac, self.name = iface, mac.lower(), name
        self.sock = open_sock(iface)
        # Start the receiver and retransmission loops in separate daemon threads.
        threading.Thread(target=self.recv_loop, daemon=True).start()
        threading.Thread(target=self.retransmission_demon, daemon=True).start()

    def _send(self, dst_mac, header, payload=b""):
        """Constructs and sends a single raw Ethernet frame."""
        with state_lock:
            name_to_send = self.name # Ensure we read the name safely
        
        # L2 Header: Dst MAC + Src MAC + Custom EtherType
        eth_header = mac_bytes(dst_mac) + mac_bytes(self.src_mac) + ETHERTYPE_ESTTPS
        # Full Frame: L2 Header + ESTTPS Header + Padded Name + Payload
        frame = eth_header + header + pad_name(name_to_send) + payload
        # Ethernet frames must be at least 60 bytes long.
        if len(frame) < 60:
            frame += b"\x00" * (60 - len(frame))
        
        self.sock.send(frame)
        
        if verbose:
            t, f, sid, ln = struct.unpack("!BBHH", header[:6])
            safe_print(f"[TX] t={t:02x} f={f:02x} sid={sid:04x} ln={ln} -> {dst_mac}")

    def retransmission_demon(self):
        """
        A background thread that periodically checks for unacknowledged REL messages
        and retransmits them if their timeout has expired.
        """
        while True:
            time.sleep(1) # Check once per second
            timed_out_keys = []
            with state_lock:
                now = time.time()
                # Iterate over a copy of the items to allow modification during iteration.
                for key, msg in list(unacked_messages.items()):
                    if now - msg['sent_time'] > RETRANSMISSION_TIMEOUT:
                        if msg['retries'] < MAX_RETRIES:
                            # Attempt retransmission
                            msg['retries'] += 1
                            msg['sent_time'] = now
                            safe_print(f"[!] Timeout: Resending message to {participant_map.get(msg['dst_mac'], 'Unknown')} ({msg['retries']}/{MAX_RETRIES})...")
                            self._send(msg['dst_mac'], msg['header'], msg['payload'])
                        else:
                            # Max retries reached, give up.
                            timed_out_keys.append(key)
                # Clean up messages that have timed out completely.
                for key in timed_out_keys:
                    if key in unacked_messages:
                        del unacked_messages[key]
                        safe_print(f"[!!] Message could not be delivered after {MAX_RETRIES+1} attempts.")

    def send_req(self, target_name, dst_mac):
        """Sends a DM session request (REQ) to a user."""
        with state_lock:
            sid = random.randint(1, 0x7FFF)
            session_map[target_name] = {"mac": dst_mac, "sid": sid, "aes": None, 'seq_out': 0}
        self._send(dst_mac, build_header(0x01, FLAG_SYN, sid, 0), b"")

    def accept_req(self, target_name):
        """Accepts a DM request, sending back an ACC and our public KEY."""
        with state_lock:
            if target_name not in pending_reqs or not session_map.get(target_name):
                return False
            sess = session_map[target_name]
        pub_bytes = pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        # Flow: -> ACC -> KEY
        self._send(sess["mac"], build_header(0x06, 0, sess["sid"], NAME_LEN), b"")
        self._send(sess["mac"], build_header(0x02, 0, sess["sid"], len(pub_bytes) + NAME_LEN), pub_bytes)
        with state_lock:
            pending_reqs.remove(target_name)
        return True

    def send_msg(self, text, plaintext=False):
        """The main function for sending any user-typed message."""
        is_dm = current_mode == "dm"
        is_rel = reliable_mode and is_dm
        
        with state_lock:
            if is_dm:
                if not session_map.get(current_target) or not session_map[current_target].get("aes"):
                    print("[!] Secure session is not ready."); return
                sess = session_map[current_target]
            else:
                sess = {'sid': 0} # Dummy session for broadcast
            
            payload = text.encode()
            t = 0x07 if plaintext else 0x04
            
            # Set base flags depending on mode.
            base_flags = FLAG_REL if is_rel else 0
            if is_dm and not plaintext:
                base_flags |= FLAG_ENC
                payload = aes_encrypt(payload, sess["aes"])
            
            # In REL mode, prepend a sequence number to the payload.
            if is_rel:
                seq = sess['seq_out']; sess['seq_out'] += 1
                payload = struct.pack('!I', seq) + payload
            
            # --- Fragmentation Logic ---
            # Split the payload into chunks if it exceeds the maximum size.
            chunks = [payload[i:i+MAX_PAYLOAD] for i in range(0, len(payload), MAX_PAYLOAD)]
            num_chunks = len(chunks)

            for i, chunk in enumerate(chunks):
                flags = base_flags
                if num_chunks > 1:
                    flags |= FLAG_FRG
                    if i == num_chunks - 1:
                        flags |= FLAG_LST
                
                hdr = build_header(t, flags, sess["sid"], len(chunk) + NAME_LEN)
                dst_mac = sess["mac"] if is_dm else BROADCAST_MAC
                
                self._send(dst_mac, hdr, chunk)
                
                # If reliable, add the message to the unacked queue to wait for an ACK.
                # We only track the *last* fragment, as an ACK is for the whole message.
                if is_rel and i == num_chunks - 1:
                    unacked_messages[(sess["sid"], seq)] = {'header': hdr, 'payload': chunk, 'dst_mac': dst_mac, 'sent_time': time.time(), 'retries': 0}

    def send_debug_packet(self, test_type, msg=""):
        """Sends a malformed or special packet for testing purposes."""
        with state_lock:
            if current_mode == "dm":
                dst_mac = session_map.get(current_target, {}).get('mac')
                if not dst_mac: safe_print("[!] No target for debug packet."); return
            else:
                dst_mac = BROADCAST_MAC
            sid = session_map.get(current_target, {}).get('sid', 0)

        if test_type == "bad_crc":
            # Sends a packet with a deliberately incorrect CRC.
            header_ok = build_header(0x07, 0, sid, len(msg) + NAME_LEN)
            # Tamper with the CRC (last 2 bytes)
            crc_bytes = bytearray(header_ok[-2:])
            crc_bytes[0] ^= 0xFF 
            header_bad = header_ok[:-2] + crc_bytes
            safe_print("[d] Sending packet with bad CRC...")
            self._send(dst_mac, header_bad, msg.encode())
        elif test_type == "send_err":
            # Sends a plaintext packet with the ERR flag set.
            payload = msg.encode()
            header = build_header(0x07, FLAG_ERR, sid, len(payload) + NAME_LEN)
            safe_print(f"[d] Sending ERR packet with message: {msg}")
            self._send(dst_mac, header, payload)

    def recv_loop(self):
        """The main receiver loop. Listens for packets and handles them based on type and flags."""
        global current_mode, current_target, reliable_mode
        while True:
            try:
                frame = self.sock.recv(65535)
                # Ignore packets that are not our protocol
                if frame[12:14] != ETHERTYPE_ESTTPS: continue
                
                src_mac = ":".join(f"{b:02x}" for b in frame[6:12])
                t, f, sid, ln = parse_header(frame[14:22])
                name = frame[22:22 + NAME_LEN].rstrip(b"\x00").decode(errors="replace")
                with state_lock: participant_map[src_mac] = name

                payload = frame[22 + NAME_LEN : 22 + ln]
                
                # --- FRAGMENTATION REASSEMBLY LOGIC ---
                if f & FLAG_FRG:
                    reasm_key = (src_mac, sid)
                    with state_lock:
                        reasm_buffer.setdefault(reasm_key, b"")
                        reasm_buffer[reasm_key] += payload
                    
                    if not (f & FLAG_LST):
                        # If this isn't the last fragment, we wait for more.
                        continue
                    else:
                        # If it is the last, we get the full payload from the buffer.
                        with state_lock:
                            payload = reasm_buffer.pop(reasm_key)

                # --- PROTOCOL STATE MACHINE ---
                # Check for flags first, as they can modify any packet type.
                if f & FLAG_ERR:
                    safe_print(f"[!!] ERR packet from {name}: {payload.decode(errors='ignore')}")

                # Then, handle based on packet type.
                elif t == FRAME_TYPE_FIN:
                    # Handles a session termination packet (FIN).
                    # Flow: Peer sends FIN -> We are forced back to broadcast.
                    with state_lock:
                        if current_target == name:
                            safe_print(f"[i] {name} has ended the DM session.")
                            current_mode, current_target = "broadcast", None
                            reliable_mode = False # Reset REL mode
                            session_map.pop(name, None)
                            clear_screen()
                            print("[*] Returned to broadcast mode.")

                elif t == FRAME_TYPE_MSG_ACK:
                    # Handles a message acknowledgment in REL mode.
                    acked_seq = struct.unpack('!I', payload)[0]
                    with state_lock:
                        if (sid, acked_seq) in unacked_messages:
                            del unacked_messages[(sid, acked_seq)]
                            safe_print(f"[v] Message delivered to {name}.")
                
                elif t in (0x04, 0x07): # MES or PLA
                    # Handles a standard message (encrypted or plaintext).
                    prefix = "(Broadcast) " if sid == 0 else ""
                    # If it's a reliable message, send back an ACK.
                    if f & FLAG_REL and sid != 0:
                        seq = struct.unpack('!I', payload[:4])[0]
                        payload = payload[4:]
                        self._send(src_mac, build_header(FRAME_TYPE_MSG_ACK, FLAG_ACK, sid, 4 + NAME_LEN), struct.pack('!I', seq))
                    
                    try:
                        # Decrypt if the ENC flag is set.
                        key = session_map.get(name, {}).get("aes") if t == 0x04 else None
                        text = aes_decrypt(payload, key).decode() if (t == 0x04 and f & FLAG_ENC) else payload.decode()
                    except Exception: text = "<decryption error>"
                    safe_print(f"[{prefix}{name}]: {text}")

                elif t == 0x01: # REQ
                    # Handles an incoming DM request.
                    with state_lock:
                        pending_reqs.add(name)
                        session_map[name] = {"mac": src_mac, "sid": sid, "aes": None, 'seq_out': 0}
                    safe_print(f"[+] New DM request from {name}. Use '!accept {name}' to reply.")

                elif t == 0x06: # ACC
                    # Handles the acceptance of our DM request by a peer.
                    # Flow: Peer accepts -> We clear screen and start key exchange by re-sending a REQ.
                    with state_lock:
                        current_mode, current_target = "dm", name
                    clear_screen()
                    safe_print(f"[v] {name} accepted your DM request. DM is active.")
                    self.send_req(name, src_mac)

                elif t == 0x02: # KEY
                    # Handles receiving a public key from a peer.
                    # Flow: -> KEY received -> Generate AES key -> Send AES ->
                    with state_lock:
                        if not session_map.get(name): continue
                        sess = session_map[name]
                    peer_pub = serialization.load_pem_public_key(payload)
                    aes_key = os.urandom(32)
                    encrypted_aes = peer_pub.encrypt(aes_key, rsa_pad.OAEP(mgf=rsa_pad.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                    with state_lock: sess["aes"] = aes_key
                    self._send(src_mac, build_header(0x03, 0, sid, len(encrypted_aes) + NAME_LEN), encrypted_aes)
                    
                elif t == 0x03: # AES
                    # Handles receiving an encrypted AES session key.
                    # Flow: -> AES received -> Decrypt key -> Send ACK -> Session ready.
                    with state_lock:
                        if not session_map.get(name): continue
                        sess = session_map[name]
                    aes_key = priv_key.decrypt(payload, rsa_pad.OAEP(mgf=rsa_pad.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                    with state_lock: sess["aes"] = aes_key
                    self._send(src_mac, build_header(0x05, FLAG_ACK, sid, NAME_LEN), b"")
                    safe_print(f"[v] Secure connection established with {name}!")

                elif t == 0x05: # ACK
                    # Final confirmation that the peer is ready.
                    safe_print(f"[v] Secure connection established with {name}!")
            except ValueError as e: # Catch CRC error specifically
                if "Invalid CRC" in str(e) and verbose:
                    safe_print(f"[!] Dropped packet from {src_mac} due to CRC error.")
            except Exception:
                if verbose: safe_print(f"[!] Error processing packet.")

# ───────────── Main Function ─────────────
def main():
    """Parses arguments and runs the main command loop."""
    global verbose, current_mode, current_target, reliable_mode
    parser = argparse.ArgumentParser(description="ESTTPS Chatter", epilog="Have fun!")
    parser.add_argument("-i", "--iface", default="eth0", help="Network interface")
    parser.add_argument("-m", "--mac", help="Source MAC address (auto-detected if not provided)")
    parser.add_argument("-n", "--name", default=f"User{random.randint(100,999)}", help="Username")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    mac = args.mac or get_mac_address(args.iface)
    if not mac or not MAC_RE.fullmatch(mac):
        print(f"Error: Invalid or undetectable MAC address: '{mac}'. Please provide it manually with -m."); sys.exit(1)
    
    verbose = args.verbose
    chat = Chatter(args.iface, mac, args.name)
    clear_screen()
    print(f"=== ESTTPS Chatter started as {args.name} ({mac}) ===")
    print("Type !help for a list of commands.")
    # Send an initial broadcast to announce presence on the network.
    threading.Timer(1.0, chat.send_msg, args=("Hello World!", True)).start()
    
    # Main command processing loop.
    while True:
        try:
            cmd_input = input(get_prompt()).strip()
            if not cmd_input: continue
            
            cmd, *cargs = cmd_input.split(" ", 1); arg = cargs[0] if cargs else ""
            
            if cmd == "!help": print(__doc__.split("Commands:")[1].split("───")[0].strip())
            elif cmd == "!list":
                output = "--- Participant List ---\n"
                with state_lock:
                    if not participant_map: output = "[i] Nobody else is here."
                    else:
                        for m, n in participant_map.items(): output += f" {n:<20} {m}\n"
                print(output.strip())
            elif cmd == "!chn" and arg:
                with state_lock:
                    chat.name = arg[:NAME_LEN]
                print(f"[*] Name changed to '{chat.name}'")
            elif cmd == "!dm" and arg:
                with state_lock:
                    if arg.lower() == chat.name.lower(): print("[!] You can't DM yourself."); continue
                    target_mac = next((m for m, n in participant_map.items() if n.lower() == arg.lower()), None)
                    if not target_mac: print("[!] Participant not found."); continue
                chat.send_req(arg, target_mac)
                print(f"[*] DM request sent to {arg}...")
            elif cmd == "!accept" and arg:
                with state_lock:
                    # If we are already in a DM, terminate it first before accepting a new one.
                    if current_mode == 'dm' and current_target:
                        old_target_name = current_target
                        if session_map.get(old_target_name):
                            old_sess = session_map[old_target_name]
                            chat._send(old_sess['mac'], build_header(FRAME_TYPE_FIN, FLAG_FIN, old_sess['sid'], NAME_LEN), b"")
                            session_map.pop(old_target_name, None)

                if chat.accept_req(arg):
                    with state_lock:
                        current_mode, current_target = "dm", arg
                    clear_screen()
                    print(f"[*] Connected to DM with {arg}.")
                else:
                    print(f"[!] Could not accept DM from {arg} (request may have expired).")
            elif cmd == "!deny" and arg:
                with state_lock:
                    if arg in pending_reqs:
                        pending_reqs.remove(arg); session_map.pop(arg, None)
                        print(f"[*] DM request from {arg} denied.")
                    else: print(f"[!] No pending request from {arg}.")
            elif cmd == "!broadcast":
                with state_lock:
                    # If we are in a DM, send a FIN packet to the other user.
                    if current_mode == "dm" and current_target and session_map.get(current_target):
                        sess = session_map[current_target]
                        chat._send(sess['mac'], build_header(FRAME_TYPE_FIN, FLAG_FIN, sess['sid'], NAME_LEN), b"")
                        session_map.pop(current_target, None)
                    # Reset local state to broadcast.
                    current_mode, current_target = "broadcast", None
                    reliable_mode = False
                clear_screen()
                print("[*] Returned to broadcast mode.")
            elif cmd == "!clear": clear_screen()
            elif cmd in ("!rel", "!unrel"):
                if current_mode == "dm":
                    with state_lock: reliable_mode = (cmd == "!rel")
                    print(f"[*] Reliable mode {'enabled' if reliable_mode else 'disabled'}.")
                else:
                    print("[!] This command is only available in DM mode.")
            elif cmd == "!debug":
                sub_cmd, *d_args = arg.split(" ", 1)
                d_arg = d_args[0] if d_args else ""
                if sub_cmd == "bad_crc":
                    chat.send_debug_packet("bad_crc", "test")
                elif sub_cmd == "send_err":
                    chat.send_debug_packet("send_err", d_arg)
                else:
                    print("[!] Unknown debug command. Available: bad_crc, send_err <msg>")
            elif cmd == "!rekey":
                with state_lock:
                    if not (current_target and session_map.get(current_target)):
                        print("[!] No DM selected."); continue
                    sess = session_map[current_target]
                print("[*] Performing re-key..."); chat.send_req(current_target, sess["mac"])
            elif cmd == "!detail":
                with state_lock:
                    if arg == "on": verbose = True; print("[*] Verbose mode enabled.")
                    elif arg == "off": verbose = False; print("[*] Verbose mode disabled.")
                    else: print("[!] Usage: !detail on|off")
            elif cmd == "!whoami":
                with state_lock:
                    print(f"Name: {chat.name}\nMAC: {chat.src_mac}\nMode: {current_mode}\nTarget: {current_target or '-'}\nTransfer: {'REL' if reliable_mode else 'UNREL'}\nVerbose: {verbose}")
            elif cmd.startswith("!pla ") and arg: chat.send_msg(arg, plaintext=True)
            elif cmd.startswith("!"): print(f"[!] Unknown command: {cmd}")
            else: chat.send_msg(cmd_input)
        except KeyboardInterrupt:
            print("\nExiting ESTTPS Chatter...")
            break
        except Exception as e:
            print(f"\nAn unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
# The end.... Crazy right???
