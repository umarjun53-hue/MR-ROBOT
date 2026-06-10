# MR ROBOT — Encrypted Storage System

Terminal-based secure file storage with AES-256-GCM encryption. No browser. All CLI. Security first.

![Python](https://img.shields.io/badge/python-3.8+-blue?style=flat-square)
![Encryption](https://img.shields.io/badge/encryption-AES--256--GCM-green?style=flat-square)
![KDF](https://img.shields.io/badge/KDF-PBKDF2--SHA256-orange?style=flat-square)

## Features

- **AES-256-GCM encryption** — military-grade authenticated encryption
- **PBKDF2-SHA256 key derivation** — 600,000 iterations
- **Terminal-based** — no browser, pure CLI with rich UI
- **Session isolation** — encryption key destroyed on logout
- **Secure shred** — 3-pass random overwrite + delete
- **Distributed nodes** — simulated storage node network
- **File manager** — `ls` shows files like normal terminal, `list` shows vault

## Quick Start

```bash
git clone git@github.com:umarjun53-hue/MR-ROBOT.git
cd MR-ROBOT
pip install rich cryptography
python3 mr_robot.py
```

## First Run — Create Identity

```
$ python3 mr_robot.py

[1] CREATE  [2] LOGIN  [3] EXIT
Select [1/2/3]: 1

[+] CREATE NEW IDENTITY
Username: myuser
Secret key: ********
Confirm: ********

[+] Identity created: myuser
[+] Vault initialized with AES-256-GCM.
```

## Commands

### File Operations

| Command | Description |
|---------|-------------|
| `ls [path]` | List files in current dir (like normal `ls`) |
| `upload <name>` | Upload & encrypt a file from current directory |
| `download <#>` | Decrypt & download file by number |
| `delete <#>` | Delete a file from vault |
| `shred <#>` | Secure 3-pass overwrite + delete |
| `vault` | List all encrypted vault files |
| `search <query>` | Search files in vault |
| `info <#>` | Show file details |

### Navigation

| Command | Description |
|---------|-------------|
| `cd <path>` | Change working directory |
| `pwd` | Show current directory |

### System

| Command | Description |
|---------|-------------|
| `storage` | Show vault statistics |
| `nodes` | Show distributed storage nodes |
| `help` | Show all commands |
| `clear` | Clear screen |
| `logout` | Lock vault & exit |

## Example Workflow

```bash
$ python3 mr_robot.py

# Create identity
> 1
Username: alice
Secret key: MyStr0ngP@ss!
Confirm: MyStr0ngP@ss!

# See what's in current directory
alice@mrrobot > ls
  TYPE  NAME                                SIZE        MODIFIED
  FILE  secret.pdf                          2.1 MB      2026-06-09 15:30
  FILE  notes.txt                           4.2 KB      2026-06-09 14:22
  DIR   Documents                           -           2026-06-09 10:00

# Upload a file (just use filename, no full path needed)
alice@mrrobot > upload secret.pdf
[+] Uploading secret.pdf...
[+] Stored. ID: a1b2c3d4e5f6...
[+] 2.1 MB → 2.1 MB

# List vault contents
alice@mrrobot > vault
  #  FILENAME                           SIZE        STORED
  1  secret.pdf                         2.1 MB      2026-06-09 20:30

# Download by number
alice@mrrobot > download 1
[+] Decrypting secret.pdf...
[+] Saved: /home/alice/secret.pdf

# Navigate directories
alice@mrrobot > cd Documents
  → /home/alice/Documents
alice@mrrobot > ls
alice@mrrobot > upload report.docx
[+] Uploading report.docx...

# Securely delete
alice@mrrobot > shred 1
[+] Shredding secret.pdf...
[+] Securely overwritten (3 passes) and deleted.

# Check stats
alice@mrrobot > storage
  USER: alice
  FILES: 1
  VAULT SIZE: 1.8 MB
  ENCRYPTION: AES-256-GCM

# Logout
alice@mrrobot > logout
[+] Locking vault...
[+] Session terminated.
```

## Security

| Feature | Implementation |
|---------|---------------|
| Encryption | AES-256-GCM (authenticated) |
| Key Derivation | PBKDF2-SHA256, 600,000 iterations |
| Salt | 256-bit random per user |
| Nonce | 96-bit random per file |
| Password Storage | PBKDF2 hash (never plaintext) |
| Session Key | Destroyed on logout |
| Shred | 3-pass random overwrite + delete |

## File Storage

```
~/.mrrobot/
├── key.hash          # Password hash (PBKDF2)
├── vault.meta        # File metadata (encrypted filenames)
├── nodes.json        # Storage node status
└── vault/            # Encrypted file data (random UUID filenames)
    ├── a1b2c3d4...   # Encrypted file 1
    ├── e5f6a7b8...   # Encrypted file 2
    └── ...
```

**WARNING:** Deleting `~/.mrrobot/` destroys all data permanently. No recovery.

## License

MIT
