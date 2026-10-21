# CryptX

**A lightweight command-line encryption and decryption tool written in C.**

CryptX provides a simple terminal interface for encrypting and decrypting text, along with file encryption and decryption. Version **1.5.0** introduces AES-256-GCM file encryption, PBKDF2-based key derivation, and a custom `.crypenc` extension for encrypted files.

## Features

- Encrypt text from the command line.
- Decrypt previously encrypted text.
- Encrypt files using AES-256-GCM.
- Decrypt files encrypted with CryptX.
- PBKDF2-based encryption key derivation.
- User-provided encryption key or passphrase.
- Custom `.crypenc` extension for encrypted files.
- Simple command syntax.
- Custom terminal banner.
- Written in C.

## Build

```bash
cd cryptx
make
```

## Usage

### Text Encryption

```bash
cryptx encrypt "string" "encryption key"
```

Example:

```bash
cryptx encrypt "hello world" "my-secret-key"
```

### Text Decryption

```bash
cryptx decrypt "encrypted_string" "encryption key"
```

Example:

```bash
cryptx decrypt "<encrypted-output>" "my-secret-key"
```

Use the matching key and the encrypted output produced by CryptX.

### File Encryption

```bash
cryptx encrypt-file file "encryption key"
```

Example:

```bash
cryptx encrypt-file secret.txt "my-secret-key"
```

Encrypted files use the `.crypenc` extension.

### File Decryption

```bash
cryptx decrypt-file file.crypenc "encryption key"
```

Example:

```bash
cryptx decrypt-file secret.txt.crypenc "my-secret-key"
```

Use the same passphrase that was used to encrypt the file.

## Project Status

**Current version:** `1.5.0`

CryptX is under active development. Version 1.5.0 expands CryptX with file encryption and decryption using AES-256-GCM and PBKDF2-based key derivation. Future releases may expand its functionality, usability, security, and input handling.
