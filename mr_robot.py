#!/usr/bin/env python3
"""
MR ROBOT — Encrypted Storage System v2.0
Terminal-based secure file storage with AES-256 encryption.
No browser. All CLI. Security first.

Run: python3 mr_robot.py
"""

import os
import random
import sys
import json
import time
import uuid
import hashlib
import secrets
import struct
import getpass
from pathlib import Path
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
    from rich.progress import Progress, BarColumn, TextColumn
    from rich.prompt import Prompt
    RICH = True
except ImportError:
    RICH = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    CRYPTO = True
except ImportError:
    CRYPTO = False

# ── CONFIG ──────────────────────────────────────────────────────────────────
BASE_DIR = Path.home() / ".mrrobot"
VAULT_DIR = BASE_DIR / "vault"
META_FILE = BASE_DIR / "vault.meta"
KEY_FILE = BASE_DIR / "key.hash"
NODES_FILE = BASE_DIR / "nodes.json"

console = Console() if RICH else None

# ── CRYPTO ENGINE ──────────────────────────────────────────────────────────
class CryptoEngine:
    """AES-256-GCM encryption with PBKDF2 key derivation."""

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
            backend=default_backend(),
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, data, None)
        return nonce + ct

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        nonce = data[:12]
        ct = data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, None)

    @staticmethod
    def hash_password(password: str) -> str:
        salt = secrets.token_bytes(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
            backend=default_backend(),
        )
        key = kdf.derive(password.encode())
        return salt.hex() + ":" + key.hex()

    @staticmethod
    def verify_password(password: str, stored: str) -> bool:
        try:
            salt_hex, key_hex = stored.split(":")
            salt = bytes.fromhex(salt_hex)
            expected_key = bytes.fromhex(key_hex)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=600_000,
                backend=default_backend(),
            )
            kdf.verify(password.encode(), expected_key)
            return True
        except Exception:
            return False


# ── STORAGE ENGINE ─────────────────────────────────────────────────────────
class StorageEngine:
    """Manages encrypted file storage on disk."""

    def __init__(self, vault_dir: Path):
        self.vault_dir = vault_dir
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.meta_path = vault_dir.parent / "vault.meta"
        self.metadata = self._load_meta()

    def _load_meta(self) -> dict:
        if self.meta_path.exists():
            try:
                return json.loads(self.meta_path.read_text())
            except Exception:
                pass
        return {"files": {}, "total_size": 0, "created": datetime.now().isoformat()}

    def _save_meta(self):
        self.meta_path.write_text(json.dumps(self.metadata, indent=2))

    def store(self, filename: str, encrypted_data: bytes, key: bytes) -> str:
        """Store encrypted file. Returns file ID."""
        file_id = secrets.token_hex(16)
        file_path = self.vault_dir / file_id
        file_path.write_bytes(encrypted_data)

        self.metadata["files"][file_id] = {
            "name": filename,
            "size": len(encrypted_data),
            "stored": datetime.now().isoformat(),
            "id": file_id,
        }
        self.metadata["total_size"] = sum(
            f["size"] for f in self.metadata["files"].values()
        )
        self._save_meta()
        return file_id

    def retrieve(self, file_id: str) -> bytes | None:
        file_path = self.vault_dir / file_id
        if file_path.exists():
            return file_path.read_bytes()
        return None

    def delete(self, file_id: str) -> bool:
        file_path = self.vault_dir / file_id
        if file_path.exists():
            file_path.unlink()
            if file_id in self.metadata["files"]:
                del self.metadata["files"][file_id]
            self.metadata["total_size"] = sum(
                f["size"] for f in self.metadata["files"].values()
            )
            self._save_meta()
            return True
        return False

    def list_files(self) -> list:
        return [
            {"id": fid, **info}
            for fid, info in self.metadata["files"].items()
        ]

    def search(self, query: str) -> list:
        query = query.lower()
        return [
            {"id": fid, **info}
            for fid, info in self.metadata["files"].items()
            if query in info["name"].lower()
        ]

    def get_stats(self) -> dict:
        files = self.list_files()
        return {
            "total_files": len(files),
            "total_size": self.metadata.get("total_size", 0),
            "vault_path": str(self.vault_dir),
        }


# ── NODE MANAGER ───────────────────────────────────────────────────────────
class NodeManager:
    """Simulates distributed storage nodes."""

    def __init__(self, nodes_file: Path):
        self.nodes_file = nodes_file
        self.nodes = self._load_nodes()

    def _load_nodes(self) -> list:
        if self.nodes_file.exists():
            try:
                return json.loads(self.nodes_file.read_text())
            except Exception:
                pass
        # Generate default nodes
        nodes = []
        for i in range(3):
            nodes.append({
                "id": f"node-{i+1}",
                "address": f"10.0.0.{i+1}",
                "status": "ONLINE" if i < 2 else "OFFLINE",
                "latency": f"{random.randint(10, 80)}ms",
                "stored_chunks": random.randint(5, 50),
            })
        self._save_nodes(nodes)
        return nodes

    def _save_nodes(self, nodes: list):
        self.nodes_file.write_text(json.dumps(nodes, indent=2))

    def get_status(self) -> list:
        # Simulate status changes
        for node in self.nodes:
            if secrets.randbelow(100) < 5:  # 5% chance of status change
                node["status"] = "OFFLINE" if node["status"] == "ONLINE" else "ONLINE"
                node["latency"] = f"{random.randint(10, 80)}ms"
        self._save_nodes(self.nodes)
        return self.nodes


# ── DISPLAY ─────────────────────────────────────────────────────────────────
def print_slow(text, delay=0.02, style="dim"):
    if console:
        for char in text:
            console.print(char, end="", style=style)
            time.sleep(delay)
        console.print()
    else:
        print(text)

def print_line(text, style="default"):
    if console:
        console.print(text, style=style)
    else:
        print(text)

def show_logo():
    logo = r"""
███╗   ███╗██████╗     ██████╗  ██████╗ ██████╗  ██████╗ ████████╗
████╗ ████║██╔══██╗    ██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗╚══██╔══╝
██╔████╔██║██████╔╝    ██████╔╝██║   ██║██████╔╝██║   ██║   ██║
██║╚██╔╝██║██╔══██╗    ██╔══██╗██║   ██║██╔══██╗██║   ██║   ██║
██║ ╚═╝ ██║██║  ██║    ██║  ██║╚██████╔╝██████╔╝╚██████╔╝   ██║
╚═╝     ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝   ╚═╝
          [ SECURE ENCRYPTED STORAGE — NO BROWSER ]
    """
    if console:
        console.print(logo, style="bold green")
    else:
        print(logo)

def show_dashboard(user: str, stats: dict):
    if console:
        table = Table(title="MR ROBOT STORAGE", border_style="green", show_header=False)
        table.add_column("Key", style="cyan", width=20)
        table.add_column("Value", style="white")
        table.add_row("USER", user)
        table.add_row("FILES", str(stats["total_files"]))
        table.add_row("VAULT SIZE", format_size(stats["total_size"]))
        table.add_row("VAULT PATH", stats["vault_path"])
        table.add_row("ENCRYPTION", "AES-256-GCM")
        table.add_row("KDF", "PBKDF2-SHA256 (600K iterations)")
        console.print(table)
    else:
        print(f"\n=== MR ROBOT STORAGE ===")
        print(f"USER: {user}")
        print(f"FILES: {stats['total_files']}")
        print(f"VAULT SIZE: {format_size(stats['total_size'])}")
        print(f"ENCRYPTION: AES-256-GCM")

def show_files(files: list):
    if not files:
        print_line("[-] Vault is empty.", style="dim")
        return
    if console:
        table = Table(title="ENCRYPTED FILES", border_style="green")
        table.add_column("#", style="dim", width=4)
        table.add_column("FILENAME", style="cyan", width=30)
        table.add_column("SIZE", style="white", width=12)
        table.add_column("STORED", style="dim", width=20)
        table.add_column("ID", style="dim", width=16)
        for i, f in enumerate(files, 1):
            table.add_row(
                str(i), f["name"], format_size(f["size"]),
                f.get("stored", "?")[:19], f["id"][:12] + "..."
            )
        console.print(table)
    else:
        print(f"\n{'#':<4} {'FILENAME':<30} {'SIZE':<12} {'STORED':<20}")
        print("-" * 70)
        for i, f in enumerate(files, 1):
            print(f"{i:<4} {f['name']:<30} {format_size(f['size']):<12} {f.get('stored', '?')[:19]}")

def show_nodes(nodes: list):
    if console:
        table = Table(title="STORAGE NODES", border_style="green")
        table.add_column("NODE", style="cyan")
        table.add_column("ADDRESS", style="white")
        table.add_column("STATUS", style="white")
        table.add_column("LATENCY", style="dim")
        table.add_row("NODE", "ADDRESS", "STATUS", "LATENCY")
        for node in nodes:
            status_style = "green" if node["status"] == "ONLINE" else "red"
            table.add_row(
                node["id"], node["address"],
                f"[{status_style}]{node['status']}[/{status_style}]",
                node["latency"],
            )
        console.print(table)
    else:
        print(f"\n{'NODE':<12} {'ADDRESS':<16} {'STATUS':<10} {'LATENCY':<10}")
        print("-" * 50)
        for node in nodes:
            print(f"{node['id']:<12} {node['address']:<16} {node['status']:<10} {node['latency']:<10}")

def format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1048576:
        return f"{size_bytes/1024:.1f} KB"
    if size_bytes < 1073741824:
        return f"{size_bytes/1048576:.1f} MB"
    return f"{size_bytes/1073741824:.2f} GB"

def show_help():
    help_text = """
[ COMMANDS ]
─────────────────────────────────────
  upload <path>     Upload & encrypt a file
  download <id>     Decrypt & download a file
  delete <id>       Permanently delete a file
  list              List all encrypted files
  search <query>    Search files by name
  info <id>         Show file details
  storage           Show vault statistics
  nodes             Show connected storage nodes
  shred <id>        Secure overwrite + delete
  export            Export vault metadata
  clear             Clear screen
  help              Show this help
  logout            Lock vault & exit
─────────────────────────────────────
"""
    if console:
        console.print(help_text, style="dim")
    else:
        print(help_text)


# ── MAIN APP ────────────────────────────────────────────────────────────────
class MRRobot:
    def __init__(self):
        self.crypto = CryptoEngine()
        self.storage = StorageEngine(VAULT_DIR)
        self.nodes = NodeManager(NODES_FILE)
        self.current_user = None
        self.session_key = None
        self.session_salt = None
        self.running = True

    def startup(self):
        show_logo()
        print_slow("[+] Initializing MR Robot Storage Engine...", delay=0.03)
        print_slow("[+] Loading AES-256-GCM encryption module...", delay=0.03)
        print_slow("[+] Connecting to distributed storage nodes...", delay=0.03)
        print_slow("[+] Establishing secure session...", delay=0.03)
        print_slow("[+] System ready.\n", delay=0.03)

    def authenticate(self) -> bool:
        """Login or create identity."""
        BASE_DIR.mkdir(parents=True, exist_ok=True)

        if console:
            console.print("\n[1] CREATE NEW IDENTITY", style="bold yellow")
            console.print("[2] LOGIN", style="bold yellow")
            console.print("[3] EXIT\n", style="dim")
            choice = Prompt.ask("Select", choices=["1", "2", "3"])
        else:
            print("\n[1] CREATE NEW IDENTITY")
            print("[2] LOGIN")
            print("[3] EXIT")
            choice = input("Select: ").strip()

        if choice == "3":
            self.running = False
            return False

        if choice == "1":
            return self._create_identity()
        elif choice == "2":
            return self._login()
        return False

    def _create_identity(self) -> bool:
        if console:
            console.print("\n[+] CREATE NEW IDENTITY\n", style="bold yellow")
            username = Prompt.ask("Choose username")
            password = Prompt.ask("Choose secret key", password=True)
            confirm = Prompt.ask("Confirm secret key", password=True)
        else:
            print("\n[+] CREATE NEW IDENTITY\n")
            username = input("Choose username: ").strip()
            password = getpass.getpass("Choose secret key: ")
            confirm = getpass.getpass("Confirm secret key: ")

        if password != confirm:
            print_line("[-] Keys do not match.", style="red")
            return False

        if len(password) < 8:
            print_line("[-] Secret key must be at least 8 characters.", style="red")
            return False

        # Hash password for storage
        pw_hash = self.crypto.hash_password(password)
        # Store salt alongside hash for key derivation
        salt = bytes.fromhex(pw_hash.split(":")[0])
        KEY_FILE.write_text(pw_hash)

        # Derive encryption key from stored salt
        key = self.crypto.derive_key(password, salt)

        self.current_user = username
        self.session_key = key
        self.session_salt = salt

        print_slow(f"\n[+] Identity created: {username}", delay=0.02, style="green")
        print_slow("[+] Vault initialized with AES-256-GCM encryption.\n", delay=0.02)
        return True

    def _login(self) -> bool:
        if not KEY_FILE.exists():
            print_line("[-] No identity found. Create one first.", style="red")
            return False

        if console:
            console.print("\n[+] LOGIN\n", style="bold yellow")
            username = Prompt.ask("Username")
            password = Prompt.ask("Secret key", password=True)
        else:
            print("\n[+] LOGIN\n")
            username = input("Username: ").strip()
            password = getpass.getpass("Secret key: ")

        stored_hash = KEY_FILE.read_text().strip()
        if not self.crypto.verify_password(password, stored_hash):
            print_slow("\n[-] ACCESS DENIED.", delay=0.03, style="red")
            return False

        # Derive key using the SAME salt from the stored hash
        salt = bytes.fromhex(stored_hash.split(":")[0])
        key = self.crypto.derive_key(password, salt)

        self.current_user = username
        self.session_key = key
        self.session_salt = salt

        print_slow("\n[+] ACCESS GRANTED.", delay=0.02, style="green")
        print_slow("[+] Secure session established.\n", delay=0.02)
        return True

    def cmd_upload(self, args: list):
        if not args:
            print_line("[-] Usage: upload <filepath>", style="red")
            return
        filepath = Path(" ".join(args))
        if not filepath.exists():
            print_line(f"[-] File not found: {filepath}", style="red")
            return
        if not filepath.is_file():
            print_line("[-] Not a file.", style="red")
            return

        data = filepath.read_bytes()
        encrypted = self.crypto.encrypt(data, self.session_key)
        file_id = self.storage.store(filepath.name, encrypted, self.session_key)

        print_slow(f"[+] Uploading {filepath.name}...", delay=0.02)
        print_line(f"[+] Encrypted & stored. ID: {file_id[:16]}...", style="green")
        print_line(f"[+] Original: {format_size(len(data))} → Encrypted: {format_size(len(encrypted))}", style="dim")

    def cmd_download(self, args: list):
        if not args:
            print_line("[-] Usage: download <file_id> or download <number>", style="red")
            return

        file_id = args[0]
        # Support numeric index
        files = self.storage.list_files()
        if file_id.isdigit():
            idx = int(file_id) - 1
            if 0 <= idx < len(files):
                file_id = files[idx]["id"]
            else:
                print_line("[-] Invalid file number.", style="red")
                return

        # Find matching file (partial ID match)
        matched = [f for f in files if f["id"].startswith(file_id)]
        if not matched:
            print_line("[-] File not found.", style="red")
            return
        file_info = matched[0]
        file_id = file_info["id"]

        encrypted = self.storage.retrieve(file_id)
        if not encrypted:
            print_line("[-] Could not retrieve file.", style="red")
            return

        try:
            decrypted = self.crypto.decrypt(encrypted, self.session_key)
        except Exception:
            print_line("[-] Decryption failed. Wrong key?", style="red")
            return

        # Save to current directory
        out_path = Path.cwd() / file_info["name"]
        counter = 1
        while out_path.exists():
            stem = Path(file_info["name"]).stem
            suffix = Path(file_info["name"]).suffix
            out_path = Path.cwd() / f"{stem}_{counter}{suffix}"
            counter += 1

        out_path.write_bytes(decrypted)
        print_slow(f"[+] Decrypting {file_info['name']}...", delay=0.02)
        print_line(f"[+] Saved to: {out_path}", style="green")
        print_line(f"[+] Size: {format_size(len(decrypted))}", style="dim")

    def cmd_delete(self, args: list):
        if not args:
            print_line("[-] Usage: delete <file_id> or delete <number>", style="red")
            return

        file_id = args[0]
        files = self.storage.list_files()
        if file_id.isdigit():
            idx = int(file_id) - 1
            if 0 <= idx < len(files):
                file_id = files[idx]["id"]
            else:
                print_line("[-] Invalid file number.", style="red")
                return

        matched = [f for f in files if f["id"].startswith(file_id)]
        if not matched:
            print_line("[-] File not found.", style="red")
            return

        file_info = matched[0]
        if console:
            confirm = Prompt.ask(
                f"Delete '{file_info['name']}'? This cannot be undone",
                choices=["y", "n"], default="n"
            )
        else:
            confirm = input(f"Delete '{file_info['name']}'? (y/n): ").strip().lower()

        if confirm == "y":
            self.storage.delete(file_info["id"])
            print_line(f"[+] Deleted: {file_info['name']}", style="green")
        else:
            print_line("[-] Cancelled.", style="dim")

    def cmd_shred(self, args: list):
        """Secure overwrite + delete."""
        if not args:
            print_line("[-] Usage: shred <file_id>", style="red")
            return

        file_id = args[0]
        files = self.storage.list_files()
        if file_id.isdigit():
            idx = int(file_id) - 1
            if 0 <= idx < len(files):
                file_id = files[idx]["id"]
            else:
                print_line("[-] Invalid file number.", style="red")
                return

        matched = [f for f in files if f["id"].startswith(file_id)]
        if not matched:
            print_line("[-] File not found.", style="red")
            return

        file_info = matched[0]
        file_path = VAULT_DIR / file_info["id"]

        if file_path.exists():
            size = file_path.stat().st_size
            # Overwrite with random data 3 times
            for pass_num in range(3):
                random_data = secrets.token_bytes(size)
                file_path.write_bytes(random_data)
                os.sync()
            file_path.unlink()

        self.storage.delete(file_info["id"])
        print_slow(f"[+] Shredding {file_info['name']}...", delay=0.03, style="red")
        print_line(f"[+] Securely overwritten (3 passes) and deleted.", style="green")

    def cmd_list(self, args: list):
        files = self.storage.list_files()
        show_files(files)

    def cmd_search(self, args: list):
        if not args:
            print_line("[-] Usage: search <query>", style="red")
            return
        query = " ".join(args)
        results = self.storage.search(query)
        if results:
            show_files(results)
        else:
            print_line("[-] No results found.", style="dim")

    def cmd_info(self, args: list):
        if not args:
            print_line("[-] Usage: info <file_id>", style="red")
            return

        file_id = args[0]
        files = self.storage.list_files()
        if file_id.isdigit():
            idx = int(file_id) - 1
            if 0 <= idx < len(files):
                file_id = files[idx]["id"]
            else:
                print_line("[-] Invalid file number.", style="red")
                return

        matched = [f for f in files if f["id"].startswith(file_id)]
        if not matched:
            print_line("[-] File not found.", style="red")
            return

        f = matched[0]
        if console:
            table = Table(title="FILE INFO", border_style="green", show_header=False)
            table.add_column("Key", style="cyan", width=18)
            table.add_column("Value", style="white")
            table.add_row("NAME", f["name"])
            table.add_row("SIZE", format_size(f["size"]))
            table.add_row("STORED", f.get("stored", "?"))
            table.add_row("ID", f["id"])
            table.add_row("ENCRYPTION", "AES-256-GCM")
            console.print(table)
        else:
            print(f"\nNAME: {f['name']}")
            print(f"SIZE: {format_size(f['size'])}")
            print(f"STORED: {f.get('stored', '?')}")
            print(f"ID: {f['id']}")
            print(f"ENCRYPTION: AES-256-GCM")

    def cmd_storage(self, args: list):
        stats = self.storage.get_stats()
        show_dashboard(self.current_user, stats)

    def cmd_nodes(self, args: list):
        nodes = self.nodes.get_status()
        show_nodes(nodes)

    def cmd_export(self, args: list):
        export_path = Path.cwd() / f"mrrobot_export_{int(time.time())}.json"
        export_data = {
            "exported": datetime.now().isoformat(),
            "user": self.current_user,
            "files": self.storage.list_files(),
            "stats": self.storage.get_stats(),
        }
        export_path.write_text(json.dumps(export_data, indent=2))
        print_line(f"[+] Metadata exported to: {export_path}", style="green")

    def run(self):
        self.startup()

        while self.running:
            if not self.authenticate():
                if not self.running:
                    break
                continue

            show_dashboard(self.current_user, self.storage.get_stats())

            while self.running:
                try:
                    if console:
                        prompt = f"[bold green]{self.current_user}@mrrobot[/bold green] > "
                    else:
                        prompt = f"{self.current_user}@mrrobot > "

                    if console:
                        user_input = console.input(prompt).strip()
                    else:
                        user_input = input(prompt).strip()

                    if not user_input:
                        continue

                    parts = user_input.split()
                    cmd = parts[0].lower()
                    args = parts[1:]

                    if cmd == "upload":
                        self.cmd_upload(args)
                    elif cmd == "download":
                        self.cmd_download(args)
                    elif cmd == "delete":
                        self.cmd_delete(args)
                    elif cmd == "shred":
                        self.cmd_shred(args)
                    elif cmd == "list":
                        self.cmd_list(args)
                    elif cmd == "search":
                        self.cmd_search(args)
                    elif cmd == "info":
                        self.cmd_info(args)
                    elif cmd == "storage":
                        self.cmd_storage(args)
                    elif cmd == "nodes":
                        self.cmd_nodes(args)
                    elif cmd == "export":
                        self.cmd_export(args)
                    elif cmd == "help":
                        show_help()
                    elif cmd == "clear":
                        if console:
                            console.clear()
                        else:
                            os.system("clear")
                        show_dashboard(self.current_user, self.storage.get_stats())
                    elif cmd in ("logout", "exit", "quit"):
                        print_slow("\n[+] Locking vault...", delay=0.02, style="yellow")
                        self.session_key = None
                        self.session_salt = None
                        self.current_user = None
                        print_slow("[+] Session terminated.\n", delay=0.02)
                        break
                    else:
                        print_line(f"[-] Unknown command: {cmd}. Type 'help'.", style="red")

                except KeyboardInterrupt:
                    print_slow("\n[+] Use 'logout' to exit safely.", style="dim")
                except EOFError:
                    self.running = False
                    break

        print_slow("\n[+] MR Robot shutdown complete.", delay=0.02, style="dim")


if __name__ == "__main__":
    if not CRYPTO:
        print("ERROR: Install cryptography: pip install cryptography")
        sys.exit(1)
    if not RICH:
        print("WARNING: Install rich for better UI: pip install rich")

    app = MRRobot()
    app.run()
