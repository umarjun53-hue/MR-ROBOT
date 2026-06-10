#!/usr/bin/env python3
"""
MR ROBOT — Encrypted Storage System v2.1
Terminal-based secure file storage with AES-256-GCM encryption.
No browser. All CLI. Security first.

Run: python3 mr_robot.py
"""

import os, random, sys, json, time, secrets, getpass
from pathlib import Path
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.prompt import Prompt
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


def fmt(b):
    if b < 1024: return f"{b} B"
    if b < 1048576: return f"{b/1024:.1f} KB"
    if b < 1073741824: return f"{b/1048576:.1f} MB"
    return f"{b/1073741824:.2f} GB"

def ss(text, d=0.02, style="dim"):
    if console:
        for c in text: console.print(c, end="", style=style); time.sleep(d)
        console.print()
    else: print(text)

def pl(text, style="default"):
    console.print(text, style=style) if console else print(text)


class Crypto:
    @staticmethod
    def derive(pw, salt):
        return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000, backend=default_backend()).derive(pw.encode())
    @staticmethod
    def enc(data, key):
        n = secrets.token_bytes(12); return n + AESGCM(key).encrypt(n, data, None)
    @staticmethod
    def dec(data, key):
        return AESGCM(key).decrypt(data[:12], data[12:], None)
    @staticmethod
    def hash(pw):
        s = secrets.token_bytes(32); k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=s, iterations=600_000, backend=default_backend()).derive(pw.encode())
        return s.hex() + ":" + k.hex()
    @staticmethod
    def verify(pw, stored):
        try:
            s, k = stored.split(":"); PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=bytes.fromhex(s), iterations=600_000, backend=default_backend()).verify(pw.encode(), bytes.fromhex(k)); return True
        except: return False


class Vault:
    def __init__(self, d): self.d = d; self.d.mkdir(parents=True, exist_ok=True); self.mp = d.parent / "vault.meta"; self.meta = json.loads(self.mp.read_text()) if self.mp.exists() else {"files":{},"total_size":0}
    def save(self): self.mp.write_text(json.dumps(self.meta, indent=2))
    def store(self, name, data):
        fid = secrets.token_hex(16); (self.d / fid).write_bytes(data)
        self.meta["files"][fid] = {"name":name,"size":len(data),"stored":datetime.now().isoformat(),"id":fid}
        self.meta["total_size"] = sum(f["size"] for f in self.meta["files"].values()); self.save(); return fid
    def get(self, fid): p = self.d / fid; return p.read_bytes() if p.exists() else None
    def delete(self, fid):
        p = self.d / fid
        if p.exists(): p.unlink(); self.meta["files"].pop(fid,None); self.meta["total_size"] = sum(f["size"] for f in self.meta["files"].values()); self.save(); return True
        return False
    def ls(self): return [{"id":fid,**i} for fid,i in self.meta["files"].items()]
    def search(self, q): q=q.lower(); return [{"id":fid,**i} for fid,i in self.meta["files"].items() if q in i["name"].lower()]
    def stats(self): return {"total_files":len(self.ls()),"total_size":self.meta.get("total_size",0)}


class Nodes:
    def __init__(self, f): self.f = f; self.nodes = json.loads(f.read_text()) if f.exists() else [{"id":f"node-{i+1}","address":f"10.0.0.{i+1}","status":"ONLINE" if i<2 else "OFFLINE","latency":f"{random.randint(10,80)}ms"} for i in range(3)]; self.save()
    def save(self): self.f.write_text(json.dumps(self.nodes, indent=2))
    def status(self):
        for n in self.nodes:
            if secrets.randbelow(100)<5: n["status"]="OFFLINE" if n["status"]=="ONLINE" else "ONLINE"; n["latency"]=f"{random.randint(10,80)}ms"
        self.save(); return self.nodes


def show_logo():
    console.print("""
███╗   ███╗██████╗     ██████╗  ██████╗ ██████╗  ██████╗ ████████╗
████╗ ████║██╔══██╗    ██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗╚══██╔══╝
██╔████╔██║██████╔╝    ██████╔╝██║   ██║██████╔╝██║   ██║   ██║
██║╚██╔╝██║██╔══██╗    ██╔══██╗██║   ██║██╔══██╗██║   ██║   ██║
██║ ╚═╝ ██║██║  ██║    ██║  ██║╚██████╔╝██████╔╝╚██████╔╝   ██║
╚═╝     ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝   ╚═╝
          [ SECURE ENCRYPTED STORAGE — NO BROWSER ]""", style="bold green") if console else print("MR ROBOT v2.1")

def show_ls(path=None, workdir=None):
    if path:
        p = Path(path)
    elif workdir:
        p = Path(workdir)
    else:
        p = Path.cwd()
    if not p.exists(): pl(f"  [-] Not found: {p}", style="red"); return
    try: entries = sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
    except PermissionError: pl("  [-] Permission denied.", style="red"); return
    if not entries: pl("  (empty)", style="dim"); return
    if console:
        t = Table(border_style="blue", show_header=True, padding=(0,1))
        t.add_column("TYPE", width=6); t.add_column("NAME", style="cyan", width=35); t.add_column("SIZE", style="white", width=12); t.add_column("MODIFIED", style="dim", width=20)
        for e in entries:
            if e.name.startswith("."): continue
            t.add_row("📁 DIR " if e.is_dir() else "📄 FILE", e.name, "-" if e.is_dir() else fmt(e.stat().st_size), datetime.fromtimestamp(e.stat().st_mtime).strftime("%Y-%m-%d %H:%M"))
        console.print(t)
    else:
        for e in entries:
            if e.name.startswith("."): continue
            print(f"  {'[DIR]' if e.is_dir() else '     '} {e.name}")

def show_vault(files):
    if not files: pl("  (vault is empty)", style="dim"); return
    if console:
        t = Table(border_style="green"); t.add_column("#",style="dim",width=4); t.add_column("FILENAME",style="cyan",width=30); t.add_column("SIZE",style="white",width=12); t.add_column("STORED",style="dim",width=20)
        for i,f in enumerate(files,1): t.add_row(str(i),f["name"],fmt(f["size"]),f.get("stored","?")[:19])
        console.print(t)
    else:
        for i,f in enumerate(files,1): print(f"  {i}. {f['name']:<30} {fmt(f['size']):<12}")

def show_dash(user, stats, wd):
    if console:
        t=Table(title="MR ROBOT STORAGE",border_style="green",show_header=False); t.add_column("Key",style="cyan",width=20); t.add_column("Value",style="white")
        t.add_row("USER",user); t.add_row("FILES",str(stats["total_files"])); t.add_row("VAULT SIZE",fmt(stats["total_size"])); t.add_row("WORKDIR",str(wd)); t.add_row("ENCRYPTION","AES-256-GCM")
        console.print(t)
    else: print(f"\nUSER:{user} | FILES:{stats['total_files']} | SIZE:{fmt(stats['total_size'])} | DIR:{wd}")

def show_help():
    h="""
[ COMMANDS ]
─────────────────────────────────────────────
  ls [path]         List files (like normal ls)
  upload <name>     Upload & encrypt (from current dir)
  download <#>      Decrypt & download a file
  delete <#>        Delete a file
  search <query>    Search files in vault
  info <#>          File details
  storage           Vault statistics
  nodes             Storage nodes
  shred <#>         Secure overwrite + delete
  cd <path>         Change directory
  pwd               Show current directory
  clear             Clear screen
  help              This help
  logout            Lock & exit
─────────────────────────────────────────────"""
    console.print(h,style="dim") if console else print(h)


class App:
    def __init__(self):
        self.vault = Vault(VAULT_DIR); self.nodes = Nodes(NODES_FILE)
        self.user = None; self.key = None; self.wd = Path.cwd(); self.running = True

    def startup(self):
        show_logo(); ss("[+] Initializing...",d=0.03); ss("[+] AES-256-GCM loaded.",d=0.03); ss("[+] Nodes connected.",d=0.03); ss("[+] Ready.\n",d=0.03)

    def auth(self):
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        if console:
            console.print("\n[1] CREATE  [2] LOGIN  [3] EXIT\n", style="bold yellow")
            c = Prompt.ask("Select", choices=["1","2","3"])
        else:
            print("\n[1] CREATE  [2] LOGIN  [3] EXIT"); c = input("Select: ").strip()
        if c=="3": self.running=False; return False
        if c=="1": return self._create()
        if c=="2": return self._login()
        return False

    def _create(self):
        if console:
            console.print("\n[+] CREATE NEW IDENTITY\n", style="bold yellow")
            u=Prompt.ask("Username"); p=Prompt.ask("Secret key",password=True); cp=Prompt.ask("Confirm",password=True)
        else:
            print("\n[+] CREATE NEW IDENTITY\n"); u=input("Username: ").strip(); p=getpass.getpass("Secret key: "); cp=getpass.getpass("Confirm: ")
        if p!=cp: pl("[-] Keys don't match.","red"); return False
        if len(p)<8: pl("[-] Min 8 characters.","red"); return False
        h=Crypto.hash(p); s=bytes.fromhex(h.split(":")[0]); KEY_FILE.write_text(h)
        self.user=u; self.key=Crypto.derive(p,s)
        ss(f"[+] Identity created: {u}",d=0.02,style="green"); return True

    def _login(self):
        if not KEY_FILE.exists(): pl("[-] No identity. Create one.","red"); return False
        if console:
            console.print("\n[+] LOGIN\n", style="bold yellow")
            u=Prompt.ask("Username"); p=Prompt.ask("Secret key",password=True)
        else:
            print("\n[+] LOGIN\n"); u=input("Username: ").strip(); p=getpass.getpass("Secret key: ")
        h=KEY_FILE.read_text().strip()
        if not Crypto.verify(p,h): ss("[-] ACCESS DENIED.",d=0.03,style="red"); return False
        s=bytes.fromhex(h.split(":")[0]); self.user=u; self.key=Crypto.derive(p,s)
        ss("[+] ACCESS GRANTED.",d=0.02,style="green"); return True

    def run(self):
        self.startup()
        while self.running:
            if not self.auth(): continue
            show_dash(self.user, self.vault.stats(), self.wd)
            while self.running:
                try:
                    prompt = f"[bold green]{self.user}@mrrobot[/bold green] > " if console else f"{self.user}@mrrobot > "
                    inp = console.input(prompt).strip() if console else input(prompt).strip()
                    if not inp: continue
                    parts = inp.split(); cmd, args = parts[0].lower(), parts[1:]

                    if cmd=="ls": show_ls(args[0] if args else None, self.workdir)
                    elif cmd=="upload":
                        if not args: pl("[-] Usage: upload <filename>","red"); continue
                        fn=" ".join(args); fp=self.wd/fn
                        if not fp.exists(): fp=Path(fn)
                        if not fp.exists() or not fp.is_file(): pl(f"[-] Not found: {fn}","red"); pl(f"    CWD: {self.wd}","dim"); continue
                        data=fp.read_bytes(); enc=Crypto.enc(data,self.key); fid=self.vault.store(fp.name,enc)
                        ss(f"[+] Uploading {fp.name}...",d=0.02); pl(f"[+] Stored. ID: {fid[:16]}...","green"); pl(f"[+] {fmt(len(data))} → {fmt(len(enc))}","dim")
                    elif cmd=="download":
                        if not args: pl("[-] Usage: download <#>","red"); continue
                        files=self.vault.ls(); fid=args[0]
                        if fid.isdigit():
                            idx=int(fid)-1
                            if 0<=idx<len(files): fid=files[idx]["id"]
                            else: pl("[-] Invalid #.","red"); continue
                        m=[f for f in files if f["id"].startswith(fid)]
                        if not m: pl("[-] Not found.","red"); continue
                        info=m[0]; enc=self.vault.get(info["id"])
                        if not enc: pl("[-] Retrieve failed.","red"); continue
                        try: dec=Crypto.dec(enc,self.key)
                        except: pl("[-] Decryption failed.","red"); continue
                        out=self.wd/info["name"]; c=1
                        while out.exists(): s=Path(info["name"]).stem; x=Path(info["name"]).suffix; out=self.wd/f"{s}_{c}{x}"; c+=1
                        out.write_bytes(dec); ss(f"[+] Decrypting {info['name']}...",d=0.02); pl(f"[+] Saved: {out}","green")
                    elif cmd=="delete":
                        if not args: pl("[-] Usage: delete <#>","red"); continue
                        files=self.vault.ls(); fid=args[0]
                        if fid.isdigit():
                            idx=int(fid)-1
                            if 0<=idx<len(files): fid=files[idx]["id"]
                            else: pl("[-] Invalid #.","red"); continue
                        m=[f for f in files if f["id"].startswith(fid)]
                        if not m: pl("[-] Not found.","red"); continue
                        ok=Prompt.ask(f"Delete '{m[0]['name']}'? [y/N]",choices=["y","n"],default="n") if console else input(f"Delete '{m[0]['name']}'? (y/n): ").strip().lower()
                        if ok=="y": self.vault.delete(m[0]["id"]); pl(f"[+] Deleted: {m[0]['name']}","green")
                    elif cmd=="shred":
                        if not args: pl("[-] Usage: shred <#>","red"); continue
                        files=self.vault.ls(); fid=args[0]
                        if fid.isdigit():
                            idx=int(fid)-1
                            if 0<=idx<len(files): fid=files[idx]["id"]
                            else: pl("[-] Invalid #.","red"); continue
                        m=[f for f in files if f["id"].startswith(fid)]
                        if not m: pl("[-] Not found.","red"); continue
                        vp=VAULT_DIR/m[0]["id"]
                        if vp.exists():
                            sz=vp.stat().st_size
                            for _ in range(3): vp.write_bytes(secrets.token_bytes(sz)); os.sync()
                            vp.unlink()
                        self.vault.delete(m[0]["id"]); ss(f"[+] Shredding {m[0]['name']}...",d=0.03,style="red"); pl("[+] 3-pass overwrite + deleted.","green")
                    elif cmd=="vault": show_vault(self.vault.ls())
                    elif cmd=="search":
                        if not args: pl("[-] Usage: search <query>","red"); continue
                        r=self.vault.search(" ".join(args)); show_vault(r) if r else pl("[-] No results.","dim")
                    elif cmd=="info":
                        if not args: pl("[-] Usage: info <#>","red"); continue
                        files=self.vault.ls(); fid=args[0]
                        if fid.isdigit():
                            idx=int(fid)-1
                            if 0<=idx<len(files): fid=files[idx]["id"]
                            else: pl("[-] Invalid #.","red"); continue
                        m=[f for f in files if f["id"].startswith(fid)]
                        if not m: pl("[-] Not found.","red"); continue
                        f=m[0]
                        if console:
                            t=Table(border_style="green",show_header=False); t.add_column("Key",style="cyan",width=15); t.add_column("Value",style="white")
                            t.add_row("NAME",f["name"]); t.add_row("SIZE",fmt(f["size"])); t.add_row("STORED",f.get("stored","?")); t.add_row("ID",f["id"]); t.add_row("ENCRYPTION","AES-256-GCM")
                            console.print(t)
                        else: print(f"NAME:{f['name']}\nSIZE:{fmt(f['size'])}\nID:{f['id']}")
                    elif cmd=="storage": show_dash(self.user,self.vault.stats(),self.wd)
                    elif cmd=="nodes":
                        ns=self.nodes.status()
                        if console:
                            t=Table(title="STORAGE NODES",border_style="green"); t.add_column("NODE",style="cyan"); t.add_column("ADDRESS",style="white"); t.add_column("STATUS",style="white"); t.add_column("LATENCY",style="dim")
                            for n in ns: ss_="green" if n["status"]=="ONLINE" else "red"; t.add_row(n["id"],n["address"],f"[{ss_}]{n['status']}[/{ss_}]",n["latency"])
                            console.print(t)
                        else:
                            for n in ns: print(f"  {n['id']:<12} {n['address']:<16} {n['status']:<10} {n['latency']}")
                    elif cmd=="cd":
                        if not args: pl(f"  {self.wd}","dim"); continue
                        np=Path(args[0])
                        if not np.is_absolute(): np=self.wd/np
                        if np.is_dir(): self.wd=np.resolve(); pl(f"  → {self.wd}","dim")
                        else: pl(f"[-] Not a dir: {args[0]}","red")
                    elif cmd=="pwd": pl(f"  {self.wd}","cyan")
                    elif cmd=="clear":
                        console.clear() if console else os.system("clear"); show_dash(self.user,self.vault.stats(),self.wd)
                    elif cmd=="help": show_help()
                    elif cmd in ("logout","exit","quit"):
                        ss("\n[+] Locking vault...",d=0.02,style="yellow"); self.key=None; self.user=None; ss("[+] Session terminated.\n",d=0.02); break
                    else: pl(f"[-] Unknown: {cmd}. Type 'help'.","red")
                except KeyboardInterrupt: ss("\n[+] Use 'logout' to exit.","dim")
                except EOFError: self.running=False; break
        ss("[+] MR Robot shutdown.",d=0.02,style="dim")


if __name__=="__main__":
    if not CRYPTO: print("ERROR: pip install cryptography"); sys.exit(1)
    App().run()
