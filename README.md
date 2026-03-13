# AES-256 Password Manager
**Honours Mini-Project** — Secure Credential Storage using AES-Based Password Management

---

## Project Structure

```
PasswordManager/
└── src/
    ├── CryptoUtils.java         # AES-256-GCM encryption + PBKDF2 key derivation
    ├── Credential.java          # Credential data model (serialization / deserialization)
    ├── VaultManager.java        # Vault file I/O + credential CRUD
    └── PasswordManagerApp.java  # Console UI + entry point
```

---

## Security Design

| Concern | Mechanism |
|---|---|
| Encryption algorithm | AES-256-GCM (authenticated encryption) |
| Key derivation | PBKDF2WithHmacSHA256, 310 000 iterations (OWASP 2023) |
| Salt | 16-byte random per vault (prevents rainbow tables) |
| IV | 12-byte random per encryption (prevents ciphertext reuse) |
| Auth tag | 128-bit GCM tag (detects tampering / corruption) |
| Master password storage | PBKDF2 hash only — never stored in plaintext |
| Memory hygiene | `char[]` passwords wiped with `Arrays.fill(pw, '\0')` after use |

---

## How to Compile & Run

### Requirements
- Java 11 or later (uses standard library only — no external dependencies)

### Compile
```bash
cd PasswordManager/src
javac *.java
```

### Run
```bash
java PasswordManagerApp
```
> Run from a real terminal (not an IDE console) for hidden password input via `System.console()`.

---

## Usage Walkthrough

### First run — creates a new vault
```
╔══════════════════════════════════════╗
║    AES-256 Password Manager v1.0     ║
╚══════════════════════════════════════╝

[*] No vault found. Creating a new one.
    Enter master password  : ****
    Confirm master password: ****
[+] New vault created successfully.
```

### Main menu
```
┌─────────────────────────┐
│  1. Add credential      │
│  2. Retrieve password   │
│  3. List all sites      │
│  4. Delete credential   │
│  0. Exit & lock vault   │
└─────────────────────────┘
```

### Adding a credential
```
Choice: 1
  Site name : github.com
  Username  : alice@example.com
  Password  : ****
[+] Credential saved for: github.com
```

### Retrieving a password
```
Choice: 2
  Site name: github.com
[+] Password for github.com: MyS3cr3tP@ss!
    (clear your terminal after use)
```

---

## Vault File Format (`vault.dat`)

```
VAULT_VERSION:1
MASTER_HASH:<base64-salt>:<base64-pbkdf2-hash>
VAULT_SALT:<base64-aes-salt>
github.com|alice@example.com|<base64-iv>:<base64-ciphertext+tag>
```

All passwords are stored encrypted. Even if `vault.dat` is stolen, passwords
cannot be recovered without the master password.

---

## Limitations (Scope of Honours Project)

- Single-user, single-vault design
- No password generator (can be added as extension)
- No GUI (intentional — focus is on cryptographic correctness)
- vault.dat is stored in the working directory (no OS keychain integration)
