# 01 - Cryptography Fundamentals

## Introduction
- Cryptology uses mathematical techniques to protect confidentiality, integrity, and authenticity of information.
- Two main areas:
	- Cryptography: techniques for encrypting and decrypting information.
	- Cryptanalysis: methods for breaking encrypted information.

## Brief History
- Used since ancient times (e.g., Egyptian hieroglyphs, Roman Caesar cipher).
- Modern foundations established in the 20th century (WWII, Enigma, Alan Turing).
- Today cryptology underpins digital security.

## Importance & Applications
- Communication security (internet confidentiality & integrity).
- Secure data storage (encrypted data at rest).
- Authentication (digital signatures, certificates).
- Financial transactions (online banking, e-commerce).
- Government and military secrecy.

## Fundamental Terms
- Encryption: converting information into unreadable form using an algorithm and a key.
- Decryption: returning encrypted information to its original form using algorithm and key.
- Key: secret information used in encryption/decryption; key management covers generation, distribution, storage, destruction.
- Public key / Private key: public keys are shared openly; private keys are kept secret by their owner.
- Cryptographic algorithms: mathematical methods (examples in text: AES, RSA, DES).
- Cryptographic protocols: rule sets that ensure secure use of algorithms (examples: SSL/TLS, SSH, IPsec).

## Goals of Cryptography
- Confidentiality: only authorized parties can read data.
- Integrity: data cannot be altered undetected.
- Authentication: verify sender/source.
- Non-repudiation: sender cannot deny sending.

## Cryptography vs Cryptanalysis
- Cryptography builds protections; cryptanalysis finds weaknesses and attempts to recover plaintext or keys.
- Cryptanalysis techniques evaluate and stress cryptosystems.

## Foundational Principles
- Kerckhoffs's Principle: security should depend on secrecy of the key, not the algorithm.
- Shannon's Uncertainty Theory: ciphertext should appear random and not reveal statistical structure.

## Symmetric Encryption
- Uses the same key for encryption and decryption; fast and efficient but key distribution/management is challenging.

### Symmetric algorithms (from provided text)
- Block ciphers: operate on fixed-size blocks.
	- DES: 56-bit key, legacy, now insecure.
	- 3DES: applies DES three times (168-bit effective keying).
	- AES: NIST standard (2001), supports 128/192/256-bit keys; widely used for security and speed.
- Stream ciphers: process data as a stream of bits/bytes.
	- RC4: variable key length, fast but has weaknesses.
	- Salsa20 / ChaCha20: secure and fast; suitable for low-power/mobile/IoT contexts.

### Modes of operation (block ciphers)
- ECB: encrypts blocks independently — insecure (repeats patterns).
- CBC: XORs each block with previous ciphertext; uses an IV for the first block — reduces patterns.
- CFB / OFB: make the block cipher behave like a stream cipher.
- CTR: uses a counter per block; allows parallel processing for performance.

## Asymmetric Encryption
- Uses a public/private key pair; solves key distribution but is slower and more computationally intensive.

### Asymmetric algorithms (from provided text)
- RSA: used for encryption and digital signatures; security based on factoring large primes (key sizes noted in text: 1024/2048/4096).
- ECC: elliptic-curve based; similar security with shorter keys—useful for mobile/IoT.
- ElGamal: supports encryption and signatures; based on discrete logarithm problems.
- DSA: standardized for digital signatures; used only for signing/verification.

### Pros/Cons
- Advantages: solves key distribution, supports authentication and digital signatures.
- Disadvantages: slower, higher computational cost.

## Public Key Infrastructure (PKI)
- PKI uses digital certificates and CAs to distribute/manage public keys.
	- Certificate Authorities (CA): validate and sign certificates; perform revocation.
	- Registration Authorities (RA): handle authentication/registration on behalf of CAs.
	- Digital certificates: contain a public key + identity info; signed by CAs.
	- Certificate repositories: store/manage certificates.

## Digital Signatures
- Purpose: verify sender identity, ensure integrity, provide non-repudiation.

### How signatures work (workflow in text)
1. Hash the document.
2. Encrypt the hash with sender's private key → signature.
3. Append/send signature with document.
4. Recipient hashes document, decrypts signature with sender's public key, compares hashes.
5. If hashes match, integrity and identity are verified.

### Algorithms for signatures
- RSA, DSA, ECDSA (ECDSA = elliptic curve variant for signatures; efficient with short keys).

## Hash Functions
- Map arbitrary-length input to fixed-length digest; properties:
	- Deterministic, efficient, unpredictable (small input change large output change), collision-resistant.
- Uses: integrity checks, digital signatures, password storage, database indexing.

### Common hash algorithms (from text)
- MD5: 128-bit, historically used, now not recommended (weak collisions).
- SHA-1: 160-bit, not recommended due to collisions found.
- SHA-2 family: includes SHA-224/256/384/512 — secure and widely used.
- SHA-3 family: NIST standard (Keccak-based), alternative design.
- RIPEMD-160: 160-bit alternative.

### Hash properties & attacks
- One-way: infeasible to reverse.
- Collision resistance: hard to find two inputs with same digest.
- Avalanche effect: small input change produces big digest change.
- Attacks: collision attacks, preimage/second-preimage attacks, rainbow table attacks.

## Cryptographic Protocols (overview and examples)
- Protocols define how algorithms are used securely in practice. Examples provided:
	- SSL/TLS: secures web communications (handshake, session keys, authentication, encrypted communication).
	- IPsec: secures IP packets (ESP, AH, IKE for key exchange).
	- SSH: secure remote access (handshake, authentication, encrypted channel).
	- PGP: secures email (uses symmetric encryption for message data + asymmetric to protect session keys, plus digital signatures).
	- Kerberos: network authentication using tickets and session keys.
	- OAuth: authorization for third-party apps (authorization codes and access tokens).

### Protocol security depends on
- Strong algorithms, secure key management, timely updates/patches, and correct implementation.

## Cryptanalysis (techniques summarized)
- Purpose: find weaknesses and recover plaintext or keys; used for security testing and, maliciously, to break systems.

### Techniques listed in the source
1. Brute-force attacks: try all keys — mitigated by long/strong keys.
2. Dictionary attacks: try common passwords from wordlists.
3. Side-channel attacks: exploit physical leakage (timing, power, EM) to infer keys.
4. Known-plaintext attacks: use known plaintext/ciphertext pairs to deduce keys.
5. Frequency analysis: analyze symbol frequencies (effective against simple ciphers).
6. Differential cryptanalysis: analyze output differences from input differences (targets internal structure of block ciphers).
7. Linear cryptanalysis: use linear approximations of cipher behavior.
8. Man-in-the-middle (MitM): intercept/alter communications; defend with secure key exchange and end-to-end encryption.

## Role & Importance
- Cryptography provides security; cryptanalysis evaluates and improves cryptosystems.
- Both fields evolve together: new cryptographic techniques defend against vulnerabilities revealed by cryptanalysis.
