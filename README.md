# MR ROBOT — Encrypted Storage System

Terminal-based secure file storage with AES-256-GCM encryption. No browser. All CLI. Security first.

![Python](https://img.shields.io/badge/python-3.8+-blue?style=flat-square)
![Encryption](https://img.shields.io/badge/encryption-AES--256--GCM-green?style=flat-square)
![KDF](https://img.shields.io/badge/KDF-PBKDF2--SHA256-orange?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

## Features

- **AES-256-GCM encryption** — military-grade encryption for all stored files
- **PBKDF2-SHA256 key derivation** — 600,000 iterations to brute-force your password
- **Terminal-based** — no browser, no web server, just pure CLI
- **Session isolation** — encryption key is destroyed on logout
- **Secure shred** — 3-pass overwrite before deletion
- **Distributed nodes** — simulated storage node network
- **Rich UI** — colored tables, progress bars, and formatted output

## Requirements

- Python 3.8+
- `pip install rich cryptography`

## Quick Start

```bash
# Clone
git clone git@github.com:umarjun53-hue/MR-ROBOT.git
cd MR-ROBOT

# Install dependencies
pip install rich cryptography

# Run
python3 mr_robot.py
```

## First Time Setup

When you first run MR ROBOT, you need to create an identity:

```
$ python3 mr_robot.py

[1] CREATE NEW IDENTITY
[2] LOGIN
[3] EXIT

Select [1/2/3]: 1

[+] CREATE NEW IDENTITY

Choose username: myuser
Choose Secret Key: ********
Confirm Secret Key: ********

[+] Identity created: myuser
[+] Vault initialized with AES-256-GCM encryption.
```

Your password hash is stored in `~/.mrrobot/key.hash`. The encryption key is derived from your password using PBKDF2-SHA256 with 600,000 iterations.

## Commands

### File Operations

#### Upload a file
```
myuser@mrrobot > upload /path/to/file.txt
[+] Uploading file.txt...
[+] Encrypted & stored. ID: a1b2c3d4...
[+] Original: 1.2 KB → Encrypted: 1.2 KB
```

#### Download a file
```
myuser@mrrobot > download a1b2c3d4
[+] Decrypting file.txt...
[+] Saved to: /current/directory/file.txt
[+] Size: 1.2 KB
```

You can also use the file number from the list:
```
myuser@mrrobot > download 1
```

#### List all files
```
myuser@mrrobot > list
```

#### Search files
```
myuser@mrrobot > search report
```

#### File details
```
myuser@mrrobot > info a1b2c3d4
```

#### Delete a file
```
myuser@mrrobot > delete a1b2c3d4
Delete 'file.txt'? This cannot be undone [y/N]: y
[+] Deleted: file.txt
```

#### Secure shred (3-pass overwrite + delete)
```
myuser@mrrobot > shred a1b2c3d4
[+] Shredding file.txt...
[+] Securely overwritten (3 passes) and deleted.
```

### Vault Operations

#### Check storage stats
```
myuser@mrrobot > storage
```

#### View storage nodes
```
myuser@mrrobot > nodes
```

#### Export vault metadata
```
myuser@mrrobot > export
[+] Metadata exported to: mrrobot_export_1234567890.json
```

### Session

#### Clear screen
```
myuser@mrrobot > clear
```

#### Logout (locks vault, destroys session key)
```
myuser@mrrobot > logout
[+] Locking vault...
[+] Session terminated.
```

#### Exit
```
Select [1/2/3]: 3
[+] MR Robot shutdown complete.
```

## File Storage

All encrypted files are stored in:
```
~/.mrrobot/vault/
```

Each file is stored with a random UUID filename. The original filename and metadata are stored in:
```
~/.mrrobot/vault.meta
```

**IMPORTANT:** If you delete `~/.mrrobot/`, all your encrypted files and password hash are gone forever. There is no recovery.

## Security Details

| Feature | Implementation |
|---------|---------------|
| Encryption | AES-256-GCM (authenticated encryption) |
| Key Derivation | PBKDF2-SHA256, 600,000 iterations |
| Salt | 256-bit random per user |
| Nonce | 96-bit random per file |
| Password Storage | PBKDF2 hash (not plaintext) |
| Session Key | Destroyed on logout |
| Shred | 3-pass random overwrite + delete |

## Example Workflow

```bash
# Start MR Robot
$ python3 mr_robot.py

# Create identity (first time)
> 1
Choose username: alice
Choose Secret Key: MyStr0ngP@ss!
Confirm Secret Key: MyStr0ngP@ss!

# Upload files
alice@mrrobot > upload ~/Documents/secret.pdf
alice@mrrobot > upload ~/Photos/private.jpg
alice@mrrobot > upload ~/code/project.py

# List files
alice@mrrobot > list

# Check storage
alice@mrrobot > storage

# Download a file
alice@mrrobot > download 1

# Securely delete a file
alice@mrrobot > shred 2

# Logout
alice@mrrobot > logout

# Next time, just login
$ python3 mr_robot.py
> 2
Username: alice
Secret Key: MyStr0ngP@ss!
[+] ACCESS GRANTED.
```

## License

MIT
