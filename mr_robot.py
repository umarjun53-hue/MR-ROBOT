"""
MR ROBOT — Encrypted Storage System v3.0
Terminal-based secure file storage with AES-256-GCM encryption.
No browser. All CLI. Security first.

Run: python3 mr_robot.py
"""

import os, random, sys, json, time, secrets, getpass, shutil
from pathlib import Path
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.prompt import Prompt
    from rich.progress import Progress, BarColumn, TextColumn
    from rich.panel import Panel
    from rich.text import Text
    RICH = True
except ImportError:
    RICH = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    CRYPTO = True
except ImportError:
    CRYPTO = False

BASE_DIR = Path.home() / ".mrrobot"
VAULT_DIR = BASE_DIR / "vault"
KEY_FILE = BASE_DIR / "key.hash"
NODES_FILE = BASE_DIR / "nodes.json"
console = Console() if RICH else None

FILE_ICONS = {
    ".txt": "📄", ".md": "📝", ".py": "🐍", ".sh": "⚙️",
    ".json": "📋", ".yaml": "📋", ".yml": "📋", ".toml": "📋",
    ".jpg": "🖼️", ".jpeg": "🖼️", ".png": "🖼️", ".gif": "🖼️", ".svg": "🖼️",
    ".mp3": "🎵", ".wav": "🎵", ".flac": "🎵",
    ".mp4": "🎬", ".mkv": "🎬", ".avi": "🎬",
    ".zip": "📦", ".tar": "📦", ".gz": "📦", ".bz2": "📦", ".7z": "📦", ".rar": "📦",
    ".pdf": "📕", ".doc": "📘", ".docx": "📘",
    ".exe": "⚡", ".bin": "⚡",
    ".c": "🔧", ".cpp": "🔧", ".rs": "🔧", ".go": "🔧", ".js": "🔧", ".ts": "🔧",
    ".crypt": "🔒", ".enc": "🔒",
}


def fmt(b):
    if b < 1024: return f"{b} B"
    if b < 1048576: return f"{b/1024:.1f} KB"
    if b < 1073741824: return f"{b/1048576:.1f} MB"
    return f"{b/1073741824:.2f} GB"


def file_icon(name):
    ext = Path(name).suffix.lower()
    return FILE_ICONS.get(ext, "📄")


def ss(text, d=0.02, style="dim"):
    if console:
        for c in text:
            console.print(c, end="", style=style)
            time.sleep(d)
        console.print()
    else:
        print(text)


def pl(text, style="default"):
    if console:
        console.print(text, style=style)
    else:
        print(text)


def pw_strength(pw):
    """Return (score 0-4, label, color)"""
    s = 0
    if len(pw) >= 8: s += 1
    if len(pw) >= 12: s += 1
    if any(c.isupper() for c in pw) and any(c.islower() for c in pw): s += 1
    if any(c.isdigit() for c in pw): s += 1
    if any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in pw): s += 1
    labels = ["VERY WEAK", "WEAK", "FAIR", "STRONG", "VERY STRONG"]
    colors = ["red", "yellow", "yellow", "green", "green"]
    # cap at 4
    idx = min(s, 4)
    bar = "█" * s + "░" * (5 - s)
    return f"[{colors[idx]}]{bar} {labels[idx]}[/{colors[idx]}]" if console else f"{labels[idx]} [{bar}]"


class Crypto:
    @staticmethod
    def derive(pw, salt):
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=600_000, backend=default_backend()
        ).derive(pw.encode())

    @staticmethod
    def enc(data, key):
        n = secrets.token_bytes(12)
        return n + AESGCM(key).encrypt(n, data, None)

    @staticmethod
    def dec(data, key):
        return AESGCM(key).decrypt(data[:12], data[12:], None)

    @staticmethod
    def hash(pw):
        s = secrets.token_bytes(32)
        k = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=s,
            iterations=600_000, backend=default_backend()
        ).derive(pw.encode())
        return s.hex() + ":" + k.hex()

    @staticmethod
    def verify(pw, stored):
        try:
            s, k = stored.split(":")
            PBKDF2HMAC(
                algorithm=hashes.SHA256(), length=32, salt=bytes.fromhex(s),
                iterations=600_000, backend=default_backend()
            ).verify(pw.encode(), bytes.fromhex(k))
            return True
        except Exception:
            return False


class Vault:
    def __init__(self, d):
        self.d = d
        self.d.mkdir(parents=True, exist_ok=True)
        self.mp = d.parent / "vault.meta"
        if self.mp.exists():
            try:
                self.meta = json.loads(self.mp.read_text())
            except (json.JSONDecodeError, IOError):
                self.meta = {"files": {}, "total_size": 0}
        else:
            self.meta = {"files": {}, "total_size": 0}

    def save(self):
        self.mp.write_text(json.dumps(self.meta, indent=2))

    def store(self, name, data):
        fid = secrets.token_hex(16)
        (self.d / fid).write_bytes(data)
        self.meta["files"][fid] = {
            "name": name, "size": len(data),
            "stored": datetime.now().isoformat(), "id": fid
        }
        self._recalc()
        self.save()
        return fid

    def get(self, fid):
        p = self.d / fid
        return p.read_bytes() if p.exists() else None

    def delete(self, fid):
        p = self.d / fid
        if p.exists():
            p.unlink()
        removed = self.meta["files"].pop(fid, None)
        self._recalc()
        self.save()
        return removed is not None

    def rename(self, fid, new_name):
        if fid in self.meta["files"]:
            self.meta["files"][fid]["name"] = new_name
            self.save()
            return True
        return False

    def ls(self):
        return [{"id": fid, **i} for fid, i in self.meta["files"].items()]

    def search(self, q):
        q = q.lower()
        return [{"id": fid, **i} for fid, i in self.meta["files"].items() if q in i["name"].lower()]

    def stats(self):
        files = self.ls()
        actual_size = sum(
            (self.d / f["id"]).stat().st_size
            for f in files if (self.d / f["id"]).exists()
        )
        return {"total_files": len(files), "total_size": actual_size}

    def integrity_check(self):
        """Return list of issues found"""
        issues = []
        for fid, info in list(self.meta["files"].items()):
            p = self.d / fid
            if not p.exists():
                issues.append(f"MISSING: {info['name']} ({fid[:12]}...)")
            else:
                actual = p.stat().st_size
                if actual != info["size"]:
                    issues.append(
                        f"SIZE MISMATCH: {info['name']} "
                        f"(meta={info['size']}, actual={actual})"
                    )
        # Check for orphan files on disk
        meta_ids = set(self.meta["files"].keys())
        for f in self.d.iterdir():
            if f.name not in meta_ids:
                issues.append(f"ORPHAN: {f.name} ({fmt(f.stat().st_size)})")
        return issues

    def export_index(self, key):
        """Export vault index as encrypted JSON"""
        data = json.dumps(self.meta, indent=2).encode()
        return Crypto.enc(data, key)

    def import_index(self, data, key):
        """Replace vault index from encrypted JSON"""
        dec = Crypto.dec(data, key)
        self.meta = json.loads(dec)
        self.save()

    def _recalc(self):
        self.meta["total_size"] = sum(
            f["size"] for f in self.meta["files"].values()
        )


class Nodes:
    def __init__(self, f):
        self.f = f
        if f.exists():
            try:
                self.nodes = json.loads(f.read_text())
            except (json.JSONDecodeError, IOError):
                self.nodes = []
        else:
            self.nodes = []
        if not self.nodes:
            self.nodes = [
                {"id": f"node-{i+1}", "address": f"10.0.0.{i+1}",
                 "status": "ONLINE" if i < 2 else "OFFLINE",
                 "latency": f"{random.randint(10,80)}ms"}
                for i in range(3)
            ]
        self.save()

    def save(self):
        self.f.write_text(json.dumps(self.nodes, indent=2))

    def status(self):
        for n in self.nodes:
            if secrets.randbelow(100) < 5:
                n["status"] = "OFFLINE" if n["status"] == "ONLINE" else "ONLINE"
                n["latency"] = f"{random.randint(10,80)}ms"
        self.save()
        return self.nodes


def show_logo():
    if console:
        console.print("""
███╗   ███╗██████╗     ██████╗  ██████╗ ██████╗  ██████╗ ████████╗
████╗ ████║██╔══██╗    ██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗╚══██╔══╝
██╔████╔██║██████╔╝    ██████╔╝██║   ██║██████╔╝██║   ██║   ██║
██║╚██╔╝██║██╔══██╗    ██╔══██╗██║   ██║██╔══██╗██║   ██║   ██║
██║ ╚═╝ ██║██║  ██║    ██║  ██║╚██████╔╝██████╔╝╚██████╔╝   ██║
╚═╝     ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝   ╚═╝
          [ SECURE ENCRYPTED STORAGE — NO BROWSER ]""", style="bold green")
    else:
        print("MR ROBOT v3.0")


def show_ls(paths=None, workdir=None):
    """List files. Usage: show_ls(paths=['/some/path']) or show_ls(workdir=Path)"""
    if paths:
        target = Path(paths[0])
    elif workdir:
        target = Path(workdir)
    else:
        target = Path.cwd()

    if not target.exists():
        pl(f"  [-] Not found: {target}", style="red")
        return

    if target.is_file():
        # Single file: show info
        st = target.stat()
        if console:
            t = Table(border_style="blue", show_header=False)
            t.add_column("Key", style="cyan", width=15)
            t.add_column("Value", style="white")
            t.add_row("NAME", target.name)
            t.add_row("SIZE", fmt(st.st_size))
            t.add_row("MODIFIED", datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"))
            t.add_row("PERMISSIONS", oct(st.st_mode)[-3:])
            console.print(t)
        else:
            print(f"  {target.name}  {fmt(st.st_size)}")
        return

    try:
        entries = sorted(target.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
    except PermissionError:
        pl("  [-] Permission denied.", style="red")
        return

    if not entries:
        pl("  (empty)", style="dim")
        return

    if console:
        tbl = Table(border_style="blue", show_header=True, padding=(0, 1))
        tbl.add_column("TYPE", width=6)
        tbl.add_column("NAME", style="cyan", width=40)
        tbl.add_column("SIZE", style="white", width=12)
        tbl.add_column("MODIFIED", style="dim", width=20)
        for e in entries:
            if e.name.startswith("."):
                continue
            icon = "📁" if e.is_dir() else file_icon(e.name)
            tbl.add_row(
                f"{icon} {'DIR ' if e.is_dir() else 'FILE'}",
                e.name, "-" if e.is_dir() else fmt(e.stat().st_size),
                datetime.fromtimestamp(e.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            )
        console.print(tbl)
    else:
        for e in entries:
            if e.name.startswith("."):
                continue
            tag = "[DIR]" if e.is_dir() else "     "
            print(f"  {tag} {e.name}")


def show_vault(files):
    if not files:
        pl("  (vault is empty)", style="dim")
        return
    if console:
        tbl = Table(border_style="green")
        tbl.add_column("#", style="dim", width=4)
        tbl.add_column("FILENAME", style="cyan", width=35)
        tbl.add_column("SIZE", style="white", width=12)
        tbl.add_column("STORED", style="dim", width=20)
        for i, f in enumerate(files, 1):
            tbl.add_row(str(i), file_icon(f["name"]) + " " + f["name"],
                        fmt(f["size"]), f.get("stored", "?")[:19])
        console.print(tbl)
    else:
        for i, f in enumerate(files, 1):
            print(f"  {i}. {f['name']:<30} {fmt(f['size']):<12}")


def show_dash(user, stats, wd):
    if console:
        t = Table(title="MR ROBOT STORAGE", border_style="green", show_header=False)
        t.add_column("Key", style="cyan", width=20)
        t.add_column("Value", style="white")
        t.add_row("USER", user)
        t.add_row("FILES", str(stats["total_files"]))
        t.add_row("VAULT SIZE", fmt(stats["total_size"]))
        t.add_row("WORKDIR", str(wd))
        t.add_row("ENCRYPTION", "AES-256-GCM")
        console.print(t)
    else:
        print(f"\nUSER:{user} | FILES:{stats['total_files']} | SIZE:{fmt(stats['total_size'])} | DIR:{wd}")


def show_help():
    h = """
[ COMMANDS ]
─────────────────────────────────────────────────
  ls [path]            List files (like normal ls)
  upload <name|path>   Upload & encrypt file to vault
  download <#|id>      Decrypt & download from vault
  delete <#|id>        Delete file from vault
  rename <#|id> <name> Rename file in vault
  search <query>       Search files in vault
  info <#|id>          File details
  vault                List all vault files
  storage              Vault statistics
  nodes                Storage nodes status
  shred <#|id>         Secure 3-pass overwrite + delete

  cat <path>           View file contents
  cd <path>            Change directory
  pwd                  Show current directory
  mkdir <name>         Create directory
  cp <src> <dst>       Copy file
  mv <src> <dst>       Move/rename file
  rm <path>            Delete file from disk
  tree [path]          Directory tree view

  integrity            Vault integrity check
  export               Export encrypted vault index
  import               Import encrypted vault index

  clear                Clear screen
  help                 This help
  logout               Lock & exit
─────────────────────────────────────────────────"""
    if console:
        console.print(h, style="dim")
    else:
        print(h)


def show_tree(path=None, workdir=None, prefix="", max_depth=3, _depth=0):
    if _depth >= max_depth:
        return
    if path:
        p = Path(path)
    elif workdir:
        p = Path(workdir)
    else:
        p = Path.cwd()
    if not p.exists() or not p.is_dir():
        pl(f"  [-] Not a directory: {p}", style="red")
        return
    try:
        entries = sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
    except PermissionError:
        return
    visible = [e for e in entries if not e.name.startswith(".")]
    for i, e in enumerate(visible):
        is_last = (i == len(visible) - 1)
        connector = "└── " if is_last else "├── "
        icon = "📁" if e.is_dir() else file_icon(e.name)
        if console:
            style = "bold blue" if e.is_dir() else "white"
            console.print(f"{prefix}{connector}{icon} {e.name}", style=style)
        else:
            tag = "[D]" if e.is_dir() else "[F]"
            print(f"{prefix}{connector}{tag} {e.name}")
        if e.is_dir():
            ext = "    " if is_last else "│   "
            show_tree(path=str(e), prefix=prefix + ext, max_depth=max_depth, _depth=_depth + 1)


def cat_file(filepath, workdir):
    fp = Path(filepath)
    if not fp.is_absolute():
        fp = Path(workdir) / fp
    if not fp.exists():
        pl(f"  [-] Not found: {filepath}", style="red")
        return
    if fp.is_dir():
        pl(f"  [-] Is a directory: {filepath}", style="red")
        return
    if fp.stat().st_size > 1_000_000:
        pl(f"  [-] File too large ({fmt(fp.stat().st_size)}). Use a real editor.", style="red")
        return
    try:
        content = fp.read_text(errors="replace")
    except UnicodeDecodeError:
        pl("  [-] Binary file — cannot display.", style="red")
        return
    if console:
        console.print(Panel(content, title=f"📄 {fp.name}", border_style="blue"))
    else:
        print(f"--- {fp.name} ---")
        print(content)


def resolve_vault_id(arg, files):
    """Resolve a user argument to a vault file ID. Supports index number or partial ID."""
    if arg.isdigit():
        idx = int(arg) - 1
        if 0 <= idx < len(files):
            return files[idx]["id"]
        return None
    # Try exact ID first
    for f in files:
        if f["id"] == arg:
            return f["id"]
    # Try partial prefix match
    matches = [f for f in files if f["id"].startswith(arg)]
    if len(matches) == 1:
        return matches[0]["id"]
    return None


class App:
    def __init__(self):
        self.vault = Vault(VAULT_DIR)
        self.nodes = Nodes(NODES_FILE)
        self.user = None
        self.key = None
        self.wd = Path.cwd()
        self.running = True

    def startup(self):
        show_logo()
        ss("[+] Initializing...", d=0.03)
        ss("[+] AES-256-GCM loaded.", d=0.03)
        ss("[+] Nodes connected.", d=0.03)
        ss("[+] Ready.\n", d=0.03)

    def auth(self):
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        if console:
            console.print("\n[1] CREATE  [2] LOGIN  [3] EXIT\n", style="bold yellow")
            c = Prompt.ask("Select", choices=["1", "2", "3"])
        else:
            print("\n[1] CREATE  [2] LOGIN  [3] EXIT")
            c = input("Select: ").strip()
        if c == "3":
            self.running = False
            return False
        if c == "1":
            return self._create()
        if c == "2":
            return self._login()
        return False

    def _create(self):
        if console:
            console.print("\n[+] CREATE NEW IDENTITY\n", style="bold yellow")
            u = Prompt.ask("Username")
            p = Prompt.ask("Secret key", password=True)
            cp = Prompt.ask("Confirm", password=True)
        else:
            print("\n[+] CREATE NEW IDENTITY\n")
            u = input("Username: ").strip()
            p = getpass.getpass("Secret key: ")
            cp = getpass.getpass("Confirm: ")
        if p != cp:
            pl("[-] Keys don't match.", "red")
            return False
        if len(p) < 8:
            pl("[-] Min 8 characters.", "red")
            return False
        if console:
            console.print(f"  STRENGTH: {pw_strength(p)}")
        else:
            pl(f"  STRENGTH: {pw_strength(p)}")
        h = Crypto.hash(p)
        s = bytes.fromhex(h.split(":")[0])
        KEY_FILE.write_text(h)
        self.user = u
        self.key = Crypto.derive(p, s)
        ss(f"[+] Identity created: {u}", d=0.02, style="green")
        return True

    def _login(self):
        if not KEY_FILE.exists():
            pl("[-] No identity. Create one.", "red")
            return False
        if console:
            console.print("\n[+] LOGIN\n", style="bold yellow")
            u = Prompt.ask("Username")
            p = Prompt.ask("Secret key", password=True)
        else:
            print("\n[+] LOGIN\n")
            u = input("Username: ").strip()
            p = getpass.getpass("Secret key: ")
        h = KEY_FILE.read_text().strip()
        if not Crypto.verify(p, h):
            ss("[-] ACCESS DENIED.", d=0.03, style="red")
            return False
        s = bytes.fromhex(h.split(":")[0])
        self.user = u
        self.key = Crypto.derive(p, s)
        ss("[+] ACCESS GRANTED.", d=0.02, style="green")
        return True

    def cmd_ls(self, args):
        if args:
            show_ls(paths=args)
        else:
            show_ls(workdir=self.wd)

    def cmd_upload(self, args):
        if not args:
            pl("[-] Usage: upload <filename>", "red")
            return
        fn = " ".join(args)
        fp = self.wd / fn
        if not fp.exists():
            fp = Path(fn)
        if not fp.exists() or not fp.is_file():
            pl(f"[-] Not found: {fn}", "red")
            pl(f"    CWD: {self.wd}", "dim")
            return
        data = fp.read_bytes()
        if len(data) == 0:
            pl("[-] File is empty — skipping.", "yellow")
            return
        if console:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(), console=console
            ) as prog:
                t = prog.add_task("[cyan]Encrypting...", start=False)
                prog.update(t, completed=30)
                enc = Crypto.enc(data, self.key)
                prog.update(t, completed=70, description="[cyan]Storing...")
                fid = self.vault.store(fp.name, enc)
                prog.update(t, completed=100, description="[green]Done!")
        else:
            ss(f"[+] Uploading {fp.name}...", d=0.02)
            enc = Crypto.enc(data, self.key)
            fid = self.vault.store(fp.name, enc)
        pl(f"[+] Stored. ID: {fid[:16]}...", "green")
        pl(f"[+] {fmt(len(data))} → {fmt(len(enc))}", "dim")

    def cmd_download(self, args):
        if not args:
            pl("[-] Usage: download <#|id>", "red")
            return
        files = self.vault.ls()
        fid = resolve_vault_id(args[0], files)
        if not fid:
            pl("[-] Not found.", "red")
            return
        info = self.vault.meta["files"][fid]
        enc = self.vault.get(fid)
        if not enc:
            pl("[-] Retrieve failed — file missing from disk.", "red")
            pl("    Run 'integrity' to check vault health.", "dim")
            return
        try:
            dec = Crypto.dec(enc, self.key)
        except Exception:
            pl("[-] Decryption failed. Wrong key or corrupted data.", "red")
            return
        out = self.wd / info["name"]
        c = 1
        while out.exists():
            s = Path(info["name"]).stem
            x = Path(info["name"]).suffix
            out = self.wd / f"{s}_{c}{x}"
            c += 1
        out.write_bytes(dec)
        if console:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(), console=console
            ) as prog:
                t = prog.add_task("[cyan]Decrypting...", start=False)
                prog.update(t, completed=50)
                prog.update(t, completed=100, description="[green]Done!")
        else:
            ss(f"[+] Decrypting {info['name']}...", d=0.02)
        pl(f"[+] Saved: {out}", "green")

    def cmd_delete(self, args):
        if not args:
            pl("[-] Usage: delete <#|id>", "red")
            return
        files = self.vault.ls()
        fid = resolve_vault_id(args[0], files)
        if not fid:
            pl("[-] Not found.", "red")
            return
        name = self.vault.meta["files"][fid]["name"]
        ok = (Prompt.ask(f"Delete '{name}'? [y/N]", choices=["y", "n"], default="n")
              if console else input(f"Delete '{name}'? (y/n): ").strip().lower())
        if ok == "y":
            self.vault.delete(fid)
            pl(f"[+] Deleted: {name}", "green")

    def cmd_rename(self, args):
        if len(args) < 2:
            pl("[-] Usage: rename <#|id> <new_name>", "red")
            return
        files = self.vault.ls()
        fid = resolve_vault_id(args[0], files)
        if not fid:
            pl("[-] Not found.", "red")
            return
        new_name = " ".join(args[1:])
        old_name = self.vault.meta["files"][fid]["name"]
        self.vault.rename(fid, new_name)
        pl(f"[+] Renamed: {old_name} → {new_name}", "green")

    def cmd_shred(self, args):
        if not args:
            pl("[-] Usage: shred <#|id>", "red")
            return
        files = self.vault.ls()
        fid = resolve_vault_id(args[0], files)
        if not fid:
            pl("[-] Not found.", "red")
            return
        name = self.vault.meta["files"][fid]["name"]
        vp = VAULT_DIR / fid
        if vp.exists():
            sz = vp.stat().st_size
            for _ in range(3):
                vp.write_bytes(secrets.token_bytes(sz))
                os.sync()
            vp.unlink()
        self.vault.delete(fid)
        ss(f"[+] Shredding {name}...", d=0.03, style="red")
        pl("[+] 3-pass overwrite + deleted.", "green")

    def cmd_info(self, args):
        if not args:
            pl("[-] Usage: info <#|id>", "red")
            return
        files = self.vault.ls()
        fid = resolve_vault_id(args[0], files)
        if not fid:
            pl("[-] Not found.", "red")
            return
        f = self.vault.meta["files"][fid]
        on_disk = (VAULT_DIR / f["id"]).exists()
        if console:
            tbl = Table(border_style="green", show_header=False)
            tbl.add_column("Key", style="cyan", width=15)
            tbl.add_column("Value", style="white")
            tbl.add_row("NAME", f["name"])
            tbl.add_row("SIZE", fmt(f["size"]))
            tbl.add_row("STORED", f.get("stored", "?"))
            tbl.add_row("ID", f["id"])
            tbl.add_row("ON DISK", "✅ Yes" if on_disk else "❌ MISSING")
            tbl.add_row("ENCRYPTION", "AES-256-GCM")
            console.print(tbl)
        else:
            print(f"NAME:{f['name']}\nSIZE:{fmt(f['size'])}\nID:{f['id']}\nDISK:{'Yes' if on_disk else 'MISSING'}")

    def cmd_integrity(self, args):
        issues = self.vault.integrity_check()
        if not issues:
            if console:
                console.print("[✅] Vault integrity: ALL CLEAN", style="bold green")
            else:
                print("[OK] Vault integrity: ALL CLEAN")
        else:
            if console:
                console.print(f"[!] {len(issues)} issue(s) found:", style="bold red")
                for i in issues:
                    console.print(f"  • {i}", style="yellow")
            else:
                print(f"[!] {len(issues)} issue(s):")
                for i in issues:
                    print(f"  * {i}")

    def cmd_export(self, args):
        data = self.vault.export_index(self.key)
        out_path = self.wd / f"mrrobot_export_{int(time.time())}.enc"
        out_path.write_bytes(data)
        pl(f"[+] Exported: {out_path}", "green")
        pl(f"[+] Size: {fmt(len(data))}", "dim")

    def cmd_import(self, args):
        if not args:
            pl("[-] Usage: import <file.enc>", "red")
            return
        fp = Path(args[0])
        if not fp.is_absolute():
            fp = self.wd / fp
        if not fp.exists():
            pl(f"[-] Not found: {args[0]}", "red")
            return
        try:
            self.vault.import_index(fp.read_bytes(), self.key)
            pl("[+] Vault index imported.", "green")
            pl("[+] Files: " + str(len(self.vault.ls())), "dim")
        except Exception as e:
            pl(f"[-] Import failed: {e}", "red")

    def run(self):
        self.startup()
        while self.running:
            if not self.auth():
                continue
            show_dash(self.user, self.vault.stats(), self.wd)
            while self.running:
                try:
                    if console:
                        prompt = f"[bold green]{self.user}@mrrobot[/bold green] > "
                        inp = console.input(prompt).strip()
                    else:
                        prompt = f"{self.user}@mrrobot > "
                        inp = input(prompt).strip()
                    if not inp:
                        continue
                    parts = inp.split()
                    cmd, args = parts[0].lower(), parts[1:]

                    handlers = {
                        "ls": lambda: self.cmd_ls(args),
                        "upload": lambda: self.cmd_upload(args),
                        "download": lambda: self.cmd_download(args),
                        "delete": lambda: self.cmd_delete(args),
                        "rename": lambda: self.cmd_rename(args),
                        "shred": lambda: self.cmd_shred(args),
                        "info": lambda: self.cmd_info(args),
                        "vault": lambda: show_vault(self.vault.ls()),
                        "search": lambda: self._cmd_search(args),
                        "storage": lambda: show_dash(self.user, self.vault.stats(), self.wd),
                        "nodes": lambda: self._cmd_nodes(),
                        "cat": lambda: self._cmd_cat(args),
                        "cd": lambda: self._cmd_cd(args),
                        "pwd": lambda: pl(f"  {self.wd}", "cyan"),
                        "mkdir": lambda: self._cmd_mkdir(args),
                        "cp": lambda: self._cmd_cp(args),
                        "mv": lambda: self._cmd_mv(args),
                        "rm": lambda: self._cmd_rm(args),
                        "tree": lambda: self._cmd_tree(args),
                        "integrity": lambda: self.cmd_integrity(args),
                        "export": lambda: self.cmd_export(args),
                        "import": lambda: self.cmd_import(args),
                        "clear": lambda: self._cmd_clear(),
                        "help": lambda: show_help(),
                    }

                    if cmd in ("logout", "exit", "quit"):
                        ss("\n[+] Locking vault...", d=0.02, style="yellow")
                        self.key = None
                        self.user = None
                        ss("[+] Session terminated.\n", d=0.02)
                        break
                    elif cmd in handlers:
                        handlers[cmd]()
                    else:
                        pl(f"[-] Unknown: {cmd}. Type 'help'.", "red")

                except KeyboardInterrupt:
                    ss("\n[+] Use 'logout' to exit.", "dim")
                except EOFError:
                    self.running = False
                    break
        ss("[+] MR Robot shutdown.", d=0.02, style="dim")

    def _cmd_search(self, args):
        if not args:
            pl("[-] Usage: search <query>", "red")
            return
        r = self.vault.search(" ".join(args))
        if r:
            show_vault(r)
        else:
            pl("[-] No results.", "dim")

    def _cmd_nodes(self):
        ns = self.nodes.status()
        if console:
            tbl = Table(title="STORAGE NODES", border_style="green")
            tbl.add_column("NODE", style="cyan")
            tbl.add_column("ADDRESS", style="white")
            tbl.add_column("STATUS", style="white")
            tbl.add_column("LATENCY", style="dim")
            for n in ns:
                ss_ = "green" if n["status"] == "ONLINE" else "red"
                tbl.add_row(n["id"], n["address"],
                            f"[{ss_}]{n['status']}[/{ss_}]", n["latency"])
            console.print(tbl)
        else:
            for n in ns:
                print(f"  {n['id']:<12} {n['address']:<16} {n['status']:<10} {n['latency']}")

    def _cmd_cat(self, args):
        if not args:
            pl("[-] Usage: cat <filepath>", "red")
            return
        cat_file(args[0], self.wd)

    def _cmd_cd(self, args):
        if not args:
            pl(f"  {self.wd}", "dim")
            return
        np = Path(args[0])
        if not np.is_absolute():
            np = self.wd / np
        if np.is_dir():
            self.wd = np.resolve()
            pl(f"  → {self.wd}", "dim")
        else:
            pl(f"[-] Not a dir: {args[0]}", "red")

    def _cmd_mkdir(self, args):
        if not args:
            pl("[-] Usage: mkdir <name>", "red")
            return
        np = self.wd / args[0]
        if np.exists():
            pl(f"[-] Already exists: {args[0]}", "red")
            return
        np.mkdir(parents=True)
        pl(f"[+] Created: {np}", "green")

    def _cmd_cp(self, args):
        if len(args) < 2:
            pl("[-] Usage: cp <source> <dest>", "red")
            return
        src = self.wd / args[0]
        dst = self.wd / args[1]
        if not src.exists():
            src = Path(args[0])
        if not dst.is_absolute():
            dst = self.wd / args[1]
        if not src.exists():
            pl(f"[-] Not found: {args[0]}", "red")
            return
        try:
            if src.is_dir():
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
            pl(f"[+] Copied: {src.name} → {dst}", "green")
        except Exception as e:
            pl(f"[-] Copy failed: {e}", "red")

    def _cmd_mv(self, args):
        if len(args) < 2:
            pl("[-] Usage: mv <source> <dest>", "red")
            return
        src = self.wd / args[0]
        dst = self.wd / args[1]
        if not src.exists():
            src = Path(args[0])
        if not dst.is_absolute():
            dst = self.wd / args[1]
        if not src.exists():
            pl(f"[-] Not found: {args[0]}", "red")
            return
        try:
            shutil.move(str(src), str(dst))
            pl(f"[+] Moved: {src.name} → {dst}", "green")
        except Exception as e:
            pl(f"[-] Move failed: {e}", "red")

    def _cmd_rm(self, args):
        if not args:
            pl("[-] Usage: rm <path>", "red")
            return
        fp = self.wd / args[0]
        if not fp.exists():
            fp = Path(args[0])
        if not fp.exists():
            pl(f"[-] Not found: {args[0]}", "red")
            return
        if fp.is_dir():
            ok = (Prompt.ask(f"Delete directory '{fp.name}' recursively? [y/N]",
                             choices=["y", "n"], default="n")
                  if console else input(f"Delete dir '{fp.name}'? (y/n): ").strip().lower())
            if ok == "y":
                shutil.rmtree(fp)
                pl(f"[+] Deleted directory: {fp}", "green")
        else:
            fp.unlink()
            pl(f"[+] Deleted: {fp}", "green")

    def _cmd_tree(self, args):
        if args:
            show_tree(paths=args)
        else:
            show_tree(workdir=self.wd)

    def _cmd_clear(self):
        if console:
            console.clear()
        else:
            os.system("clear")
        show_dash(self.user, self.vault.stats(), self.wd)


if __name__ == "__main__":
    if not CRYPTO:
        print("ERROR: pip install cryptography")
        sys.exit(1)
    App().run()
