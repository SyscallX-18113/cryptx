
# CryptX

**A lightweight command-line encryption and decryption tool written in C.**

CryptX provides a simple terminal interface for encrypting and decrypting text using a user-provided encryption key. Version **1.0.0** includes the initial encryption and decryption methods and a custom terminal banner.

## Features

- Encrypt text from the command line.
- Decrypt previously encrypted text.
- User-provided encryption key.
- Simple command syntax.
- Custom terminal banner.
- Written in C.

## Build

```bash
cd cryptx
make

```

## Usage

### Encryption

```bash
cryptx encrypt "string" "encryption key"
```

Example:

```bash
cryptx encrypt "hello world" "my-secret-key"
```

### Decryption

```bash
cryptx decrypt "encrypted_string" "encryption key"
```

Example:

```bash
cryptx decrypt "<encrypted-output>" "my-secret-key"
```

Use the matching key and the encrypted output produced by CryptX.



## Project Status

**Current version:** `1.0.0`

CryptX is under active development. Future releases may expand its functionality, usability, and input handling.


