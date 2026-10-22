# CryptX

**A lightweight command-line encryption and decryption tool written in C.**

CryptX provides a simple terminal interface for encrypting and decrypting text, individual files, and directories. Version **2.0.0** adds directory encryption and decryption while retaining the existing text and file encryption features.

## Features

- Encrypt text from the command line.
- Decrypt previously encrypted text.
- Encrypt files using AES-256-GCM.
- Decrypt files encrypted with CryptX.
- Encrypt directories using CryptX.
- Decrypt directories encrypted with CryptX.
- PBKDF2-based encryption key derivation.
- User-provided encryption key or passphrase.
- Custom `.crypenc` extension for encrypted files and directory archives.
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
./cryptx encrypt "string" "encryption key"
```

Example:

```bash
./cryptx encrypt "hello world" "my-secret-key"
```

### Text Decryption

```bash
./cryptx decrypt "encrypted_string" "encryption key"
```

Example:

```bash
./cryptx decrypt "<encrypted-output>" "my-secret-key"
```

Use the matching key and the encrypted output produced by CryptX.

### File Encryption

```bash
./cryptx encrypt-file file "encryption key"
```

Example:

```bash
./cryptx encrypt-file secret.txt "my-secret-key"
```

Encrypted files use the `.crypenc` extension.

### File Decryption

```bash
./cryptx decrypt-file file.crypenc "encryption key"
```

Example:

```bash
./cryptx decrypt-file secret.txt.crypenc "my-secret-key"
```

Use the same passphrase that was used to encrypt the file.

### Folder Encryption

```bash
./cryptx encrypt-dir Folder "mypassword"
```

Example:

```bash
./cryptx encrypt-dir Documents "my-secret-key"
```

CryptX encrypts the specified directory and produces an encrypted `.crypenc` archive.

### Folder Decryption

```bash
./cryptx decrypt-dir Folder.crypenc "mypassword"
```

Example:

```bash
./cryptx decrypt-dir Documents.crypenc "my-secret-key"
```

Use the same passphrase that was used during encryption to decrypt the directory archive.

## Project Status

**Current version:** `2.0.0`

## Feedback & Support

If you:

- Found a bug
- Have a feature request
- Want to suggest improvements
- Found a security issue
- Have documentation suggestions

Please open a GitHub Issue or contact me directly:

syscallx18113@gmail.com
