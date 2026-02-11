<img width="1600" height="1200" alt="image" src="https://github.com/user-attachments/assets/363187d2-f38d-4a5d-a6ec-561833392358" />

```markdown
# Network and Security Term Project

## Certificate Authority & Secure Key Exchange System

## Overview

This project implements a simplified Public Key Infrastructure (PKI) model and a secure key exchange protocol between two clients. The system demonstrates RSA-based certificate issuance, mutual authentication, master key establishment, and session key generation.

The architecture consists of:

- Certificate Authority (CA)
- Client 1
- Client 2

---

## Objectives

- Implement RSA key pair generation
- Simulate certificate creation and digital signing by a CA
- Perform mutual authentication using nonce-based verification
- Establish a shared Master Key (Km)
- Derive and securely exchange a Session Key (Ks)
- Demonstrate hybrid encryption (asymmetric + symmetric)

---

## System Architecture

```

```
       Certificate Authority
                │
    ┌───────────┴───────────┐
    │                       │
  Client 1  ◄──────────►  Client 2
        Secure Key Exchange
```

````

---

## Cryptographic Components

### RSA (2048-bit)
- Key pair generation for CA and clients
- OAEP padding for encryption
- PKCS1v15 with SHA-256 for digital signatures

### Digital Certificate (Simplified X.509 Structure)
Contains:
- Version
- Serial Number
- Issuer
- Validity Period
- Subject ID
- Subject Public Key
- CA Signature

### Master Key (Km)
- Established after nonce-based mutual authentication
- Encrypted with receiver's public key
- Digitally signed

### Session Key (Ks)
- Random 32-byte key
- Encrypted using Km
- Used for symmetric communication (Fernet)

---

## Protocol Flow

### 1. Certificate Issuance

1. Client generates RSA key pair
2. Client sends public key to CA
3. CA creates and signs certificate
4. Certificate returned to client

---

### 2. Master Key Establishment

1. C1 → C2: `E(PUb, [N1 || IDa])`
2. C2 → C1: `E(PUa, [N1 || N2])`
3. C1 → C2: `E(PUb, N2)`
4. C1 → C2: Signed Km + `E(PUb, Km)`

Ensures:
- Mutual authentication
- Replay attack protection
- Secure master key agreement

---

### 3. Session Key Establishment

1. C1 → C2: `IDa || N1`
2. C2 → C1: `E(Km, [Ks || IDa || IDb || f(N1) || N2])`
3. C1 → C2: `E(Ks, f(N2))`

Result:
- Secure session key generation
- Final mutual verification

---

## Technologies Used

- Python 3.x
- socket (TCP communication)
- tkinter (GUI)
- cryptography library
- RSA 2048
- SHA-256
- Fernet symmetric encryption

---

## Installation

Install required dependency:

```bash
pip install cryptography
````

---

## Running the Project

### 1. Start Certificate Authority

```bash
python ca.py
```

### 2. Start Client 1

```bash
python client1.py
```

Steps:

* Generate Keys
* Request Certificate
* Wait for Client 2

### 3. Start Client 2

```bash
python client2.py
```

Steps:

* Generate Keys
* Request Certificate
* Connect to Client 1

---

## Security Features

* RSA 2048-bit encryption
* SHA-256 hashing
* Digital signature verification
* Nonce-based replay protection
* Hybrid encryption model
* Master + Session key architecture

---

## Purpose

This project is developed as a network security term project to demonstrate practical implementation of PKI concepts, certificate handling, and secure key exchange protocols.

```
```
