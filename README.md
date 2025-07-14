# STTP-Suite

**STTP-Suite** is a collection of experimental Layer 2 protocols that transmit UTF-8 text directly over raw Ethernet. No IP. No TCP. No ports. Just frames.

Originally developed as a learning project, this suite explores how real data travels across networks at the lowest level, and how to build a functioning protocol from scratch – from raw bytes to encryption and reliability.

It's **not** really a serious Project, just a bit fooling around with Frames. Most is written by Ai because i don't code Professionally. I configure Networks and stuff. 

I made this dumpsterfire in 11 Days so don't expect it to be good...

I made this in Juli 2025, I am in my first year of Vocational Training. I only have one year of experience in IT.

So please don't flame me for this dumpsterfire that I call code😭

---

## 📦 Included Protocols

| Protocol | Encryption | Features |
|----------|------------|----------|
| **STTP**    | ❌        | Minimalistic text over raw Ethernet |
| **STTPS**   | ✅ AES + RSA | Secure peer-to-peer messaging |
| **ESTTPS**  | ✅ AES + RSA | Sessions, reliability, flags, CRC |

---

## 🔹 STTP — *Simple Text Transfer Protocol*

> "No headers, no checks, just vibes."

STTP is a barebones Ethernet protocol built for pure learning purposes.

### Features
- Operates entirely on **Layer 2 (Ethernet)** using EtherType '0x88B5'
- Uses raw sockets in Python to send and receive frames
- UTF-8 payload inserted directly into the Ethernet payload
- Sender manually builds Ethernet frames (MAC + EtherType + Payload)
- Receiver filters by EtherType and displays decoded message
- No fragmentation, no encryption, no connection logic – it’s truly "dumb simple"

### Use Case
STTP is perfect for:
- Learning how Ethernet frames work
- Understanding raw socket communication
- Experimenting with protocol design at the byte level

---

## 🔹 STTPS — *Secure Text Transfer Protocol (Secure)*

> "Like STTP – but secret."

STTPS builds upon STTP by introducing asymmetric encryption with a hybrid **RSA + AES** model.

### Key Features
- AES-256 for message encryption
- RSA-2048 for session key exchange
- Still Layer 2 (no IP stack)
- Simple 1-byte header to define the message type

### Message Types
| Code | Name | Description |
|------|------|-------------|
| `0x01` | REQ  | Request public RSA key |
| `0x02` | KEY  | Send public RSA key |
| `0x03` | AES  | Send AES session key (encrypted) |
| `0x05` | ACK  | Confirm successful AES key reception |
| `0x04` | MES  | Encrypted message (AES-256-CBC) |
| `0x07` | PLA  | Plaintext message (for debugging / chaos) |

### Key Exchange Flow

REQ -> KEY -> AES -> ACK


### Notes
- Re-keying happens automatically after 10 encrypted messages
- Still uses EtherType `0x88B5`
- All payloads are manually padded to fulfill Ethernet’s minimum frame size

---

## 🔹 ESTTPS — *Extended Secure Text Transfer Protocol Secure*

> "Yes. It has sessions. And flags. And fragmentation. And probably sentience."

ESTTPS is a fully-featured evolution of STTPS. It introduces **sessions, reliable transmission, fragmentation**, and **custom protocol headers** – all still at Layer 2.

### Protocol Design
Each ESTTPS frame contains:
- **8-byte protocol header**: `Type, Flags, Session-ID, Length, CRC16`
- **20-byte username** (padded UTF-8)
- **Payload** (variable length)

### Header Fields
| Field | Size | Description |
|-------|------|-------------|
| `Type` | 1 byte | Defines the kind of packet (REQ, KEY, MES, etc.) |
| `Flags` | 1 byte | Bit flags for features (ENC, REL, FRAG, FIN...) |
| `Session ID` | 2 bytes | Identifies the session |
| `Length` | 2 bytes | Total length of Username + Payload |
| `CRC16` | 2 bytes | Header checksum (CCITT-FALSE) |

### Flags (Bitmask)
| Flag | Meaning |
|------|---------|
| `ENC` | Payload is AES-encrypted |
| `FRAG` | Fragmented packet |
| `LAST` | Last fragment of message |
| `SYN` | Session setup request |
| `ACK` | Acknowledgment |
| `FIN` | End session |
| `ERR` | Protocol error |
| `REL` | Reliable delivery (requires ACK) |

### Features
- Supports **broadcast mode** and **direct messages (DM)**
- **AES + RSA** key exchange as in STTPS
- **Reliable delivery** with retransmissions and ACKs
- **Session handling** (start, accept, close)
- **Fragmentation and reassembly**
- **Verbose debugging & CLI interface**
- **Fully terminal-controlled (no GUI required)**

---

## 📁 Project Structure


### Notes
- Re-keying happens automatically after 10 encrypted messages
- Still uses EtherType `0x88B5`
- All payloads are manually padded to fulfill Ethernet’s minimum frame size

---

## 🔹 ESTTPS — *Extended Secure Text Transfer Protocol Secure*

> "Yes. It has sessions. And flags. And fragmentation. And probably sentience."

ESTTPS is a fully-featured evolution of STTPS. It introduces **sessions, reliable transmission, fragmentation**, and **custom protocol headers** – all still at Layer 2.

### Protocol Design
Each ESTTPS frame contains:
- **8-byte protocol header**: `Type, Flags, Session-ID, Length, CRC16`
- **20-byte username** (padded UTF-8)
- **Payload** (variable length)

### Header Fields
| Field | Size | Description |
|-------|------|-------------|
| `Type` | 1 byte | Defines the kind of packet (REQ, KEY, MES, etc.) |
| `Flags` | 1 byte | Bit flags for features (ENC, REL, FRAG, FIN...) |
| `Session ID` | 2 bytes | Identifies the session |
| `Length` | 2 bytes | Total length of Username + Payload |
| `CRC16` | 2 bytes | Header checksum (CCITT-FALSE) |

### Flags (Bitmask)
| Flag | Meaning |
|------|---------|
| `ENC` | Payload is AES-encrypted |
| `FRAG` | Fragmented packet |
| `LAST` | Last fragment of message |
| `SYN` | Session setup request |
| `ACK` | Acknowledgment |
| `FIN` | End session |
| `ERR` | Protocol error |
| `REL` | Reliable delivery (requires ACK) |

### Features
- Supports **broadcast mode** and **direct messages (DM)**
- **AES + RSA** key exchange as in STTPS
- **Reliable delivery** with retransmissions and ACKs
- **Session handling** (start, accept, close)
- **Fragmentation and reassembly**
- **Verbose debugging & CLI interface**
- **Fully terminal-controlled (no GUI required)**

---

## 📁 Project Structure


### Notes
- Re-keying happens automatically after 10 encrypted messages
- Still uses EtherType `0x88B5`
- All payloads are manually padded to fulfill Ethernet’s minimum frame size

---

## 🔹 ESTTPS — *Extended Secure Text Transfer Protocol Secure*

> "Yes. It has sessions. And flags. And fragmentation. And probably sentience."

ESTTPS is a fully-featured evolution of STTPS. It introduces **sessions, reliable transmission, fragmentation**, and **custom protocol headers** – all still at Layer 2.

### Protocol Design
Each ESTTPS frame contains:
- **8-byte protocol header**: `Type, Flags, Session-ID, Length, CRC16`
- **20-byte username** (padded UTF-8)
- **Payload** (variable length)

### Header Fields
| Field | Size | Description |
|-------|------|-------------|
| `Type` | 1 byte | Defines the kind of packet (REQ, KEY, MES, etc.) |
| `Flags` | 1 byte | Bit flags for features (ENC, REL, FRAG, FIN...) |
| `Session ID` | 2 bytes | Identifies the session |
| `Length` | 2 bytes | Total length of Username + Payload |
| `CRC16` | 2 bytes | Header checksum (CCITT-FALSE) |

### Flags (Bitmask)
| Flag | Meaning |
|------|---------|
| `ENC` | Payload is AES-encrypted |
| `FRAG` | Fragmented packet |
| `LAST` | Last fragment of message |
| `SYN` | Session setup request |
| `ACK` | Acknowledgment |
| `FIN` | End session |
| `ERR` | Protocol error |
| `REL` | Reliable delivery (requires ACK) |

### Features
- Supports **broadcast mode** and **direct messages (DM)**
- **AES + RSA** key exchange as in STTPS
- **Reliable delivery** with retransmissions and ACKs
- **Session handling** (start, accept, close)
- **Fragmentation and reassembly**
- **Verbose debugging & CLI interface**
- **Fully terminal-controlled (no GUI required)**

---

## 📁 Project Structure


### Notes
- Re-keying happens automatically after 10 encrypted messages
- Still uses EtherType `0x88B5`
- All payloads are manually padded to fulfill Ethernet’s minimum frame size

---

## 🔹 ESTTPS — *Extended Secure Text Transfer Protocol Secure*

> "Yes. It has sessions. And flags. And fragmentation. And probably sentience."

ESTTPS is a fully-featured evolution of STTPS. It introduces **sessions, reliable transmission, fragmentation**, and **custom protocol headers** – all still at Layer 2.

### Protocol Design
Each ESTTPS frame contains:
- **8-byte protocol header**: `Type, Flags, Session-ID, Length, CRC16`
- **20-byte username** (padded UTF-8)
- **Payload** (variable length)

### Header Fields
| Field | Size | Description |
|-------|------|-------------|
| `Type` | 1 byte | Defines the kind of packet (REQ, KEY, MES, etc.) |
| `Flags` | 1 byte | Bit flags for features (ENC, REL, FRAG, FIN...) |
| `Session ID` | 2 bytes | Identifies the session |
| `Length` | 2 bytes | Total length of Username + Payload |
| `CRC16` | 2 bytes | Header checksum (CCITT-FALSE) |

### Flags (Bitmask)
| Flag | Meaning |
|------|---------|
| `ENC` | Payload is AES-encrypted |
| `FRAG` | Fragmented packet |
| `LAST` | Last fragment of message |
| `SYN` | Session setup request |
| `ACK` | Acknowledgment |
| `FIN` | End session |
| `ERR` | Protocol error |
| `REL` | Reliable delivery (requires ACK) |

### Features
- Supports **broadcast mode** and **direct messages (DM)**
- **AES + RSA** key exchange as in STTPS
- **Reliable delivery** with retransmissions and ACKs
- **Session handling** (start, accept, close)
- **Fragmentation and reassembly**
- **Verbose debugging & CLI interface**
- **Fully terminal-controlled (no GUI required)**

---

## 📁 Project Structure

STTP-Suite/
├─ STTP/
│  ├─ sttp-receiver.py
│  ├─ sttp-sender.py
│  ├─ sttp-chatter.py
├─ STTPS/
│  ├─ sttps-sender.py
│  ├─ sttps-reveiver.py
│  ├─ sttps-chatter.py
├─ ESTTPS/
│  ├─ esttps-chatter.py
├─ README.md
├─ LICENSE.md
