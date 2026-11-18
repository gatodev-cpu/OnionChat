#!/usr/bin/env python3
"""OnionChat - client.

E2EE (AES-256-GCM) | any server | chunked file transfers | encrypted history |
slash commands | Rich TUI

Usage:
    python client.py                      # asks which server to join
    python client.py example.com:5000
    python client.py abcd1234.onion       # .onion addresses go through Tor automatically

Dependencies:  pip install cryptography rich PySocks
"""
import argparse
import base64
import codecs
import getpass
import glob
import hashlib
import json
import logging
import math
import os
import re
import secrets
import shlex
import socket
import sqlite3
import sys
import threading
import time
import zlib
from collections import deque, namedtuple
from datetime import datetime

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from rich import box
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text
except ImportError:
    print("[!] Missing dependencies. Install them with:  pip install cryptography rich PySocks")
    sys.exit(1)

if os.name != "nt":
    import select

PORTRAIT = r"""
                            ~
                           /~
                     \  \ /**
                      \ ////
                      // //
                     // //
                   ///&//
                  / & /\ \
                /  & .,,  \
              /& %  :       \
            /&  %   :  ;     `\
           /&' &..%   !..    `.\
          /&' : &''" !  ``. : `.\
         /#' % :  "" * .   : : `.\
        I# :& :  !"  *  `.  : ::  I
        I &% : : !%.` '. . : : :  I
        I && :%: .&.   . . : :  : I
        I %&&&%%: WW. .%. : :     I
         \&&&##%%%`W! & '  :   ,'/
          \####ITO%% W &..'  #,'/
            \W&&##%%&&&&### %./
              \###j[\##//##}/
                 ++///~~\//_
                  \\ \ \ \  \_
                  /  /    \ 
                       _             
                      (_)            
            ___  _ __  _  ___  _ __  
           / _ \| '_ \| |/ _ \| '_ \ 
          | (_) | | | | | (_) | | | |
           \___/|_| |_|_|\___/|_| |_|

"""

ROOM_SALT = b"onionchat-room-v1"
AAD_MSG = b"onionchat-msg-v1"
AAD_HIST = b"onionchat-hist-v1"
DEFAULT_PORT = 5000
MAX_LINE = 1_000_000            # must match the server
CHUNK_SIZE = 64 * 1024          # raw bytes per file chunk
DEFAULT_MAX_FILE_MB = 25
MAX_INCOMING = 4                # simultaneous incoming transfers
TRANSFER_TIMEOUT = 120          # seconds without a chunk before an incoming transfer is dropped
MAX_FILES_PER_COMMAND = 50
COLORS = ["cyan", "magenta", "yellow", "blue", "bright_red",
          "bright_green", "bright_cyan", "bright_magenta"]
RE_ESC = re.compile(r"\x1b(\[[0-9;?]*[ -/]*[@-~]|O.|.)?")   # special-key escape sequences
RE_TID = re.compile(r"[0-9a-f]{16}")
RE_SHA = re.compile(r"[0-9a-f]{64}")

log = logging.getLogger("onionchat.client")
Msg = namedtuple("Msg", "kind ts name text old")


# ───────────────────────────── helpers ─────────────────────────────

def sanitize(text, limit=2000):
    """Strip newlines and control characters.

    A malicious peer could send ANSI escape sequences to mess with your
    terminal, so everything that comes from the network goes through here.
    """
    text = str(text).replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return "".join(c for c in text if c.isprintable())[:limit]


def safe_name(name):
    name = os.path.basename(str(name).replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".")
    return name[:100] or "file"


def derive_key(password, salt):
    """Password -> 256-bit key (scrypt is deliberately slow against brute force)."""
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def parse_server(text):
    """'host', 'host:port' or '[ipv6]:port' -> (host, port)."""
    text = (text or "").strip()
    if not text:
        raise ValueError("invalid server address (use host or host:port)")
    port = DEFAULT_PORT
    if text.startswith("["):
        end = text.find("]")
        if end <= 1:
            raise ValueError("invalid IPv6 address (use [host]:port)")
        host, rest = text[1:end], text[end + 1:]
        if rest:
            if not rest.startswith(":") or not rest[1:].isdigit():
                raise ValueError(f"invalid port: '{rest[1:] if rest.startswith(':') else rest}'")
            port = int(rest[1:])
    elif text.count(":") > 1:
        host = text  # IPv6 without brackets (no port)
    elif ":" in text:
        host, _, p = text.rpartition(":")
        if not p.isdigit():
            raise ValueError(f"invalid port: '{p}'")
        port = int(p)
    else:
        host = text
    host = host.strip()
    if not host or not 1 <= port <= 65535:
        raise ValueError("invalid server address (use host or host:port)")
    return host, port


def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def unique_path(folder, filename):
    """Reserve a file name that does not exist yet (never overwrites)."""
    base, ext = os.path.splitext(filename)
    candidate, i = os.path.join(folder, filename), 0
    while True:
        try:
            with open(candidate, "xb"):
                pass
            return candidate
        except FileExistsError:
            i += 1
            candidate = os.path.join(folder, f"{base}_{i}{ext}")


def setup_logging(path):
    # File only: the screen belongs to the TUI.
    log_dir = os.path.dirname(path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s",
                                           "%Y-%m-%d %H:%M:%S"))
    log.setLevel(logging.INFO)
    log.addHandler(handler)


# ───────────────────────────── crypto & history ─────────────────────────────

class Cipher:
    """AES-256-GCM: encrypts and also detects any tampering."""

    def __init__(self, key, aad):
        self.aes = AESGCM(key)
        self.aad = aad

    def encrypt(self, obj):
        nonce = os.urandom(12)  # unique per message
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        return nonce + self.aes.encrypt(nonce, data, self.aad)

    def decrypt(self, blob):
        if len(blob) < 28:
            raise ValueError("message too short")
        return json.loads(self.aes.decrypt(blob[:12], blob[12:], self.aad))


class History:
    """SQLite history where every message is encrypted with your master password."""

    def __init__(self, path, password):
        self.path = path
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self.db.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v BLOB)")
        self.db.execute("CREATE TABLE IF NOT EXISTS messages("
                        "id INTEGER PRIMARY KEY AUTOINCREMENT, data BLOB NOT NULL)")
        row = self.db.execute("SELECT v FROM meta WHERE k='salt'").fetchone()
        if row is None:  # new database
            salt = os.urandom(16)
            self.cipher = Cipher(derive_key(password, salt), AAD_HIST)
            self.db.execute("INSERT INTO meta VALUES('salt', ?)", (salt,))
            self.db.execute("INSERT INTO meta VALUES('check', ?)", (self.cipher.encrypt({"ok": 1}),))
            self.db.commit()
        else:            # existing database: verify the password
            self.cipher = Cipher(derive_key(password, row[0]), AAD_HIST)
            chk = self.db.execute("SELECT v FROM meta WHERE k='check'").fetchone()
            try:
                if chk is None:
                    raise ValueError("missing verifier")
                self.cipher.decrypt(chk[0])
            except (InvalidTag, ValueError):
                self.db.close()
                self.db = None
                raise ValueError("wrong master password for this history file")

    def save(self, kind, name, text, ts, server):
        data = self.cipher.encrypt({"kind": kind, "n": name, "m": text, "ts": ts, "srv": server})
        with self.lock:
            if self.db is None:
                return
            self.db.execute("INSERT INTO messages(data) VALUES(?)", (data,))
            self.db.commit()

    def recent(self, n, server):
        """Last n messages that belong to this server."""
        with self.lock:
            if self.db is None:
                return []
            rows = self.db.execute("SELECT data FROM messages ORDER BY id DESC LIMIT 500").fetchall()
        out = []
        for (blob,) in reversed(rows):
            try:
                rec = self.cipher.decrypt(blob)
            except (InvalidTag, ValueError, TypeError):
                continue
            if isinstance(rec, dict) and rec.get("srv") == server:
                out.append(rec)
        return out[-n:]

    def close(self):
        with self.lock:
            if self.db is None:
                return
            self.db.close()
            self.db = None


# ───────────────────────────── keyboard ─────────────────────────────

class Keyboard:
    """Non-blocking key reader without echo (Windows and Unix)."""

    def __enter__(self):
        if os.name != "nt":
            import termios
            import tty
            self.fd = sys.stdin.fileno()
            self._old = termios.tcgetattr(self.fd)
            tty.setcbreak(self.fd)  # no echo, but Ctrl+C still works
            self._dec = codecs.getincrementaldecoder("utf-8")(errors="ignore")
            self._queue = deque()
        return self

    def __exit__(self, *exc):
        if os.name != "nt":
            import termios
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self._old)

    def read(self, timeout=0.2):
        """Return one character, or None if nothing was typed within 'timeout' seconds."""
        if os.name == "nt":
            import msvcrt
            end = time.time() + timeout
            while time.time() < end:
                if msvcrt.kbhit():
                    ch = msvcrt.getwch()
                    if ch in ("\x00", "\xe0"):   # special keys (arrows, etc.)
                        msvcrt.getwch()
                        return None
                    return ch
                time.sleep(0.01)
            return None

        if self._queue:
            return self._queue.popleft()
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return None
        data = os.read(self.fd, 4096)
        if not data:
            raise EOFError
        self._queue.extend(RE_ESC.sub("", self._dec.decode(data)))
        return self._queue.popleft() if self._queue else None


# ───────────────────────────── file transfers ─────────────────────────────

class Incoming:
    """A file being received: chunks are streamed to disk, never held in RAM."""

    def __init__(self, tid, sender, filename, size, sha, chunks, part_path):
        self.tid, self.sender, self.filename = tid, sender, filename
        self.size, self.sha, self.chunks = size, sha, chunks
        self.part_path = part_path
        self.fh = open(part_path, "wb")
        self.hash = hashlib.sha256()
        self.next = 0
        self.received = 0
        self.last = time.time()

    def discard(self):
        try:
            self.fh.close()
        except OSError:
            pass
        try:
            os.remove(self.part_path)
        except OSError:
            pass


# ───────────────────────────── client ─────────────────────────────

class Client:
    def __init__(self, args, name, history):
        self.args = args
        self.name = name
        self.history = history
        self.max_file_bytes = args.max_file_mb * 1024 * 1024
        self.downloads = args.downloads

        self.console = Console()
        self.messages = deque(maxlen=400)
        self.input_buf = ""
        self.prompt_label = ""
        self.pending = None            # callback waiting for hidden input (passwords)

        self.running = threading.Event()
        self.connected = threading.Event()
        self.connecting = False
        self.lock_send = threading.Lock()
        self.lock_transfers = threading.Lock()
        self.lock_connect = threading.Lock()

        self.sock = None
        self.cipher = None
        self.host = self.port = None
        self.via_tor = False
        self.tor_port = None
        self.ciphers = {}              # (host, port) -> Cipher, so /connect can reuse keys

        self.incoming = {}
        self.outgoing = {}

        self.connected_since = time.time()
        self.latency_ms = None
        self.sent = self.received = 0
        self.bytes_tx = self.bytes_rx = 0
        self._last_decrypt_error = 0.0
        self._decrypt_errors = 0

    # ── screen messages ──

    def add(self, kind, text, name="", old=False, ts=None):
        try:
            ts = float(ts)
        except (TypeError, ValueError):
            ts = time.time()
        self.messages.append(Msg(kind, ts, name, text, old))

    def info(self, text):
        self.add("sys", text)

    def error(self, text):
        self.add("err", text)

    def server_label(self):
        return f"{self.host}:{self.port}"

    # ── networking ──

    def open_socket(self, host, port):
        """Connect directly, or through Tor for .onion hosts / --tor.

        Returns (socket, via_tor, tor_port). Raises ConnectionError with a
        human-readable message on failure.
        """
        use_tor = self.args.tor or host.lower().endswith(".onion")
        if not use_tor:
            try:
                s = socket.create_connection((host, port), timeout=15)
            except ConnectionRefusedError:
                raise ConnectionError("connection refused (is the server running, and is the port right?)")
            except socket.gaierror:
                raise ConnectionError("could not resolve that host name")
            except socket.timeout:
                raise ConnectionError("connection timed out")
            except OSError as e:
                raise ConnectionError(str(e))
            s.settimeout(None)
            return s, False, None

        try:
            import socks
        except ImportError:
            raise ConnectionError("PySocks is required for Tor:  pip install PySocks")

        ports = [self.args.tor_port] if self.args.tor_port else [9050, 9150]  # daemon, Tor Browser
        for tor_port in ports:
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, self.args.tor_host, tor_port, rdns=True)
            s.settimeout(60)
            try:
                s.connect((host, port))
            except socks.ProxyConnectionError:      # nothing listening on that Tor port
                s.close()
                continue
            except socks.ProxyError as e:
                s.close()
                raise ConnectionError(f"Tor could not reach the server: {e}")
            except socket.timeout:
                s.close()
                raise ConnectionError("connection through Tor timed out")
            except OSError as e:
                s.close()
                raise ConnectionError(str(e))
            s.settimeout(None)
            return s, True, tor_port
        raise ConnectionError(f"no Tor proxy found on {self.args.tor_host} "
                              f"(tried port {'/'.join(map(str, ports))}). Is Tor running?")

    def install(self, sock, host, port, cipher, via_tor, tor_port):
        """Make `sock` the live connection, closing the previous one if any."""
        self.abort_all_transfers("connection changed")
        with self.lock_send:
            old, old_cipher = self.sock, self.cipher
            self.sock, self.cipher = sock, cipher
            self.host, self.port, self.via_tor, self.tor_port = host, port, via_tor, tor_port
            self.connected.set()
        self.ciphers[(host, port)] = cipher
        self.connected_since = time.time()
        self.latency_ms = None
        log.info("CONNECTED    to %s:%d%s", host, port, " via Tor" if via_tor else "")

        if old is not None:
            try:  # polite goodbye on the old server
                line = base64.b64encode(old_cipher.encrypt({"t": "leave", "n": self.name})).decode()
                old.sendall((line + "\n").encode())
            except OSError:
                pass
            try:
                old.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            old.close()

    def start_receiver(self):
        threading.Thread(target=self.receive_loop, args=(self.sock,), daemon=True).start()

    def send_line(self, line):
        data = (line + "\n").encode("utf-8")
        with self.lock_send:
            if not self.connected.is_set() or self.sock is None:
                raise ConnectionError("not connected")
            self.sock.sendall(data)
        self.bytes_tx += len(data)

    def send_encrypted(self, obj):
        with self.lock_send:
            if not self.connected.is_set() or self.sock is None:
                raise ConnectionError("not connected")
            data = (base64.b64encode(self.cipher.encrypt(obj)).decode("ascii") + "\n").encode()
            self.sock.sendall(data)
        self.bytes_tx += len(data)
        return len(data)

    def receive_loop(self, sock):
        """Receiver thread for one socket: process whatever arrives, any time."""
        try:
            with sock.makefile("r", encoding="utf-8", newline="\n") as reader:
                while True:
                    line = reader.readline(MAX_LINE + 1)
                    if not line:
                        break
                    if len(line) > MAX_LINE and not line.endswith("\n"):
                        log.error("Oversized line from the server, closing")
                        break
                    if sock is not self.sock:      # we already switched servers
                        return
                    self.bytes_rx += len(line)
                    line = line.strip()
                    if line.startswith("PONG "):
                        self.on_pong(line[5:])
                    elif line:
                        try:
                            self.process(line)
                        except Exception:
                            log.exception("Failed to process a server line")
        except (OSError, ValueError, UnicodeError):
            pass
        finally:
            if sock is self.sock and self.connected.is_set():
                self.connected.clear()
                self.abort_all_transfers("connection lost")
                self.error("Connection closed by the server. Use /connect to reconnect or /exit to quit.")
                log.warning("DISCONNECTED by the server")

    def heartbeat(self):
        """Every 5 s: measure real latency (PING/PONG) and drop stale transfers."""
        while self.running.is_set():
            if self.connected.is_set():
                try:
                    self.send_line(f"PING {time.monotonic():.6f}")
                except OSError:
                    pass
            self.drop_stale_transfers()
            time.sleep(5)

    def on_pong(self, payload):
        try:
            self.latency_ms = (time.monotonic() - float(payload)) * 1000
        except ValueError:
            pass

    # ── incoming messages ──

    def process(self, line):
        try:
            data = self.cipher.decrypt(base64.b64decode(line, validate=True))
        except (InvalidTag, ValueError, TypeError):
            self._decrypt_errors += 1
            if time.time() - self._last_decrypt_error > 5:   # do not flood the screen or the log
                self._last_decrypt_error = time.time()
                log.warning("UNDECRYPTABLE %d message(s): different key or tampered data",
                            self._decrypt_errors)
                self.error("Could not decrypt a message (different room password, or tampered). "
                           "Use /password to re-enter it.")
            return
        if not isinstance(data, dict):
            log.warning("Ignoring non-object payload from the server")
            return

        kind = data.get("t")
        name = sanitize(data.get("n", "?"), 20) or "?"
        if kind == "msg":
            text = sanitize(data.get("m", ""))
            self.received += 1
            self.add("msg", text, name)
            log.info("RECEIVED     message from '%s' (%d chars)", name, len(text))
            self.remember("msg", name, text)
        elif kind == "join":
            self.info(f"{name} joined the chat")
            log.info("JOIN         '%s'", name)
        elif kind == "leave":
            self.info(f"{name} left the chat")
            log.info("LEAVE        '%s'", name)
        elif kind == "file_start":
            self.on_file_start(data, name)
        elif kind == "file_chunk":
            self.on_file_chunk(data, name)

    def remember(self, kind, name, text):
        if self.history:
            try:
                self.history.save(kind, name, text, time.time(), self.server_label())
            except sqlite3.Error as e:
                log.error("Could not save to history: %s", e)

    # ── receiving files ──

    def on_file_start(self, d, sender):
        try:
            tid, size, chunks = str(d["id"]), int(d["s"]), int(d["c"])
            sha, filename = str(d["h"]).lower(), safe_name(d["f"])
        except (KeyError, ValueError, TypeError):
            log.warning("Malformed file_start from '%s'", sender)
            return
        reason = None
        if not RE_TID.fullmatch(tid) or not RE_SHA.fullmatch(sha):
            reason = "malformed header"
        elif size < 1 or chunks != math.ceil(size / CHUNK_SIZE):
            reason = "inconsistent size"
        elif size > self.max_file_bytes:
            reason = f"too large ({human_size(size)} > limit {human_size(self.max_file_bytes)})"
        with self.lock_transfers:
            if reason is None and (tid in self.incoming or len(self.incoming) >= MAX_INCOMING):
                reason = "too many simultaneous transfers"
            if reason is None:
                try:
                    os.makedirs(self.downloads, exist_ok=True)
                    self.incoming[tid] = Incoming(tid, sender, filename, size, sha, chunks,
                                                  os.path.join(self.downloads, f".incoming-{tid}.part"))
                except OSError as e:
                    reason = f"cannot write to '{self.downloads}': {e}"
        if reason:
            self.error(f"Rejected file '{filename}' from {sender}: {reason}")
            log.warning("FILE REJECTED '%s' from '%s': %s", filename, sender, reason)
            return
        self.info(f"Receiving '{filename}' ({human_size(size)}) from {sender}...")
        log.info("FILE START   '%s' (%d bytes, %d chunks) from '%s'", filename, size, chunks, sender)

    def on_file_chunk(self, d, sender):
        with self.lock_transfers:
            t = self.incoming.get(str(d.get("id")))
            if t is None or t.sender != sender:
                return
            try:
                index = int(d["i"])
                raw = base64.b64decode(d["d"], validate=True)
            except (KeyError, ValueError, TypeError):
                self._abort(t, "malformed chunk")
                return
            if index != t.next or t.received + len(raw) > t.size:
                self._abort(t, "chunk out of order or oversized")
                return
            try:
                t.fh.write(raw)
            except OSError as e:
                self._abort(t, f"disk error: {e}")
                return
            t.hash.update(raw)
            t.received += len(raw)
            t.next += 1
            t.last = time.time()
            if t.next == t.chunks:
                self._finish(t)

    def _finish(self, t):  # lock_transfers held
        del self.incoming[t.tid]
        final = None
        try:
            t.fh.close()
            if t.received != t.size or t.hash.hexdigest() != t.sha:
                raise ValueError("integrity check failed (SHA-256 mismatch)")
            final = unique_path(self.downloads, t.filename)
            os.replace(t.part_path, final)
        except (OSError, ValueError) as e:
            t.discard()
            if final:
                try:
                    os.remove(final)
                except OSError:
                    pass
            self.error(f"File '{t.filename}' from {t.sender} discarded: {e}")
            log.warning("FILE FAILED  '%s' from '%s': %s", t.filename, t.sender, e)
            return
        self.add("file", f"{os.path.basename(final)} ({human_size(t.size)}) saved to {final}", t.sender)
        log.info("FILE DONE    '%s' from '%s' -> %s", t.filename, t.sender, final)

    def _abort(self, t, reason):  # lock_transfers held
        self.incoming.pop(t.tid, None)
        t.discard()
        self.error(f"Transfer of '{t.filename}' from {t.sender} aborted: {reason}")
        log.warning("FILE ABORTED '%s' from '%s': %s", t.filename, t.sender, reason)

    def abort_all_transfers(self, reason):
        with self.lock_transfers:
            for t in list(self.incoming.values()):
                self._abort(t, reason)

    def drop_stale_transfers(self):
        with self.lock_transfers:
            for t in list(self.incoming.values()):
                if time.time() - t.last > TRANSFER_TIMEOUT:
                    self._abort(t, "timed out waiting for data")

    # ── sending ──

    def send_message(self, text):
        try:
            n = self.send_encrypted({"t": "msg", "n": self.name, "m": text})
        except OSError as e:
            self.error(f"Could not send: {e}")
            log.error("SEND ERROR: %s", e)
            return
        self.sent += 1
        self.add("me", text, self.name)
        log.info("SENT         message (%d chars, %d encrypted bytes)", len(text), n)
        self.remember("me", self.name, text)

    def expand_paths(self, arg):
        """Turn '/file' arguments (several paths, quotes, wildcards, folders) into a file list."""
        try:
            tokens = shlex.split(arg, posix=False)
        except ValueError as e:
            self.error(f"Could not parse the paths: {e}")
            return []
        files, seen = [], set()
        for token in tokens:
            token = os.path.expanduser(token.strip("\"'"))
            matches = glob.glob(token) if any(c in token for c in "*?[") else [token]
            if not matches:
                self.error(f"No files match: {token}")
                continue
            for match in matches:
                if os.path.isdir(match):
                    found = sorted(os.path.join(match, x) for x in os.listdir(match)
                                   if os.path.isfile(os.path.join(match, x)))
                    if not found:
                        self.error(f"Folder has no files: {match}")
                elif os.path.isfile(match):
                    found = [match]
                else:
                    self.error(f"Not found: {match}")
                    continue
                for path in found:
                    path = os.path.abspath(path)
                    if path not in seen:
                        seen.add(path)
                        files.append(path)
        if len(files) > MAX_FILES_PER_COMMAND:
            self.error(f"Too many files; sending only the first {MAX_FILES_PER_COMMAND}.")
            files = files[:MAX_FILES_PER_COMMAND]
        return files

    def cmd_file(self, arg):
        if not arg:
            self.error("Usage: /file <path> [path ...]   (quotes, wildcards like *.png, and folders work)")
            return
        if not self.connected.is_set():
            self.error("Not connected. Use /connect first.")
            return
        files = self.expand_paths(arg)
        if not files:
            return
        self.info(f"Queued {len(files)} file(s) for sending (limit {human_size(self.max_file_bytes)} each).")
        threading.Thread(target=self.send_files, args=(files,), daemon=True).start()

    def send_files(self, files):
        for path in files:
            if not self.connected.is_set():
                self.error("Connection lost; remaining files were not sent.")
                return
            self.send_one_file(path)

    def send_one_file(self, path):
        name = os.path.basename(path)
        try:
            size = os.path.getsize(path)
            if size == 0:
                self.error(f"Skipped '{name}': the file is empty")
                return
            if size > self.max_file_bytes:
                self.error(f"Skipped '{name}': {human_size(size)} exceeds the limit "
                           f"of {human_size(self.max_file_bytes)} (see --max-file-mb)")
                return
            sha = hash_file(path)
        except OSError as e:
            self.error(f"Could not read '{name}': {e}")
            return

        tid, chunks, sock0 = secrets.token_hex(8), math.ceil(size / CHUNK_SIZE), self.sock
        self.outgoing[tid] = {"name": name, "done": 0, "size": size}
        try:
            self.send_encrypted({"t": "file_start", "n": self.name, "id": tid, "f": name,
                                 "s": size, "c": chunks, "h": sha})
            with open(path, "rb") as f:
                for i in range(chunks):
                    if self.sock is not sock0 or not self.connected.is_set():
                        raise ConnectionError("connection changed during the transfer")
                    raw = f.read(CHUNK_SIZE)
                    self.send_encrypted({"t": "file_chunk", "n": self.name, "id": tid, "i": i,
                                         "d": base64.b64encode(raw).decode("ascii")})
                    self.outgoing[tid]["done"] += len(raw)
        except OSError as e:
            self.error(f"Sending '{name}' failed: {e}")
            log.error("FILE SEND FAILED '%s': %s", name, e)
        else:
            self.info(f"Sent '{name}' ({human_size(size)})")
            log.info("FILE SENT    '%s' (%d bytes, %d chunks)", name, size, chunks)
        finally:
            self.outgoing.pop(tid, None)

    # ── commands ──

    def ask_secret(self, label, callback):
        self.prompt_label, self.pending, self.input_buf = label, callback, ""
        self.info("Type the password and press Enter (empty cancels). Input is hidden.")

    def handle_input(self, text):
        if not text.startswith("/"):
            self.send_message(text)
            return

        cmd, _, arg = text[1:].partition(" ")
        cmd, arg = cmd.lower(), arg.strip()
        if cmd in ("exit", "quit"):
            self.running.clear()
        elif cmd == "help":
            for line in ("Commands:",
                         "  /help                 show this help",
                         "  /status               connection, encryption and transfer info",
                         "  /clear                clear the screen (history is kept)",
                         "  /file <path> [...]    send files (several paths, wildcards and folders work)",
                         "  /connect [host[:port]] join another server (no argument = reconnect)",
                         "  /password             change the room password for this server",
                         "  /exit                 quit"):
                self.info(line)
        elif cmd == "status":
            self.show_status()
        elif cmd == "clear":
            self.messages.clear()
        elif cmd == "file":
            self.cmd_file(arg)
        elif cmd == "connect":
            self.cmd_connect(arg)
        elif cmd == "password":
            if self.host is None:
                self.error("Not connected to any server yet.")
            else:
                self.ask_secret(f"New room password for {self.server_label()}", self.change_password)
        else:
            self.error(f"Unknown command: /{cmd}  (try /help)")

    def _begin_connect(self):
        with self.lock_connect:
            if self.connecting:
                return False
            self.connecting = True
            return True

    def cmd_connect(self, arg):
        if self.connecting:
            self.error("Already connecting, please wait...")
            return
        try:
            host, port = parse_server(arg) if arg else (self.host, self.port)
        except ValueError as e:
            self.error(str(e))
            return
        if host is None or port is None:
            self.error("Usage: /connect [host[:port]]")
            return
        cipher = self.ciphers.get((host, port))
        if cipher is not None:     # already known in this session: reuse its key
            if not self._begin_connect():
                self.error("Already connecting, please wait...")
                return
            threading.Thread(target=self.switch, args=(host, port, cipher, None), daemon=True).start()
        else:
            self.ask_secret(f"Room password for {host}:{port}",
                            lambda pw: self.connect_with_password(host, port, pw))

    def connect_with_password(self, host, port, password):
        if not password:
            self.info("Cancelled.")
            return
        if not self._begin_connect():
            self.error("Already connecting, please wait...")
            return
        threading.Thread(target=self.switch, args=(host, port, None, password), daemon=True).start()

    def switch(self, host, port, cipher, password):
        """Connect to another server. The current connection stays up if this fails."""
        try:
            self.info(f"Connecting to {host}:{port} ...")
            if cipher is None:
                cipher = Cipher(derive_key(password, ROOM_SALT), AAD_MSG)
            sock, via_tor, tor_port = self.open_socket(host, port)
            self.install(sock, host, port, cipher, via_tor, tor_port)
            self.show_server_view(initial=False)
            self.start_receiver()
            self.send_encrypted({"t": "join", "n": self.name})
        except OSError as e:     # ConnectionError is a subclass
            self.error(f"Could not connect to {host}:{port}: {e}")
            log.error("CONNECT ERROR to %s:%d: %s", host, port, e)
        finally:
            with self.lock_connect:
                self.connecting = False

    def change_password(self, password):
        if not password:
            self.info("Cancelled.")
            return

        def work():
            cipher = Cipher(derive_key(password, ROOM_SALT), AAD_MSG)
            with self.lock_send:
                self.cipher = cipher
                self.ciphers[(self.host, self.port)] = cipher
            self.info(f"Room password updated for {self.server_label()}.")
        threading.Thread(target=work, daemon=True).start()

    def show_status(self):
        a = self.args
        try:
            local = "%s:%d" % self.sock.getsockname()[:2]
        except (OSError, AttributeError):
            local = "?"
        lat = f"{self.latency_ms:.0f} ms" if self.latency_ms is not None else "measuring..."
        secs = int(time.time() - self.connected_since)
        route = (f"via Tor ({a.tor_host}:{self.tor_port})" if self.via_tor else "direct")
        for line in (
            f"Connection: {'active' if self.connected.is_set() else 'closed'} "
            f"({secs // 3600:02d}:{secs % 3600 // 60:02d}:{secs % 60:02d})",
            f"Server: {self.server_label()}  {route}",
            f"Local socket: {local}",
            f"Latency to server: {lat}",
            f"Messages: {self.sent} sent, {self.received} received",
            f"Traffic: {human_size(self.bytes_tx)} sent, {human_size(self.bytes_rx)} received",
            f"Transfers: {len(self.outgoing)} sending, {len(self.incoming)} receiving "
            f"(limit {human_size(self.max_file_bytes)} per file, saved in '{self.downloads}')",
            "Encryption: AES-256-GCM, key derived with scrypt",
            f"History: {self.history.path if self.history else 'disabled'}",
        ):
            self.info(line)

    # ── TUI (Rich) ──

    def render_line(self, m):
        if m.kind == "art":
            return Text(m.text or " ", style="cyan", no_wrap=True)
        t = Text()
        try:
            stamp = datetime.fromtimestamp(m.ts).strftime("%H:%M ")
        except (OverflowError, OSError, TypeError, ValueError):
            stamp = "--:-- "
        t.append(stamp, style="dim")
        if m.kind in ("msg", "me"):
            color = "green" if m.kind == "me" else COLORS[zlib.crc32(m.name.encode()) % len(COLORS)]
            t.append(m.name, style=("dim " if m.old else "") + f"bold {color}")
            t.append(": ")
            t.append(m.text, style="dim" if m.old else "")
        elif m.kind == "sys":
            t.append(f"* {m.text}", style="italic yellow")
        elif m.kind == "err":
            t.append(f"! {m.text}", style="bold red")
        elif m.kind == "file":
            t.append(f"[file from {m.name}] {m.text}", style="bold magenta")
        return t

    def transfer_summary(self):
        parts = [f"TX {t['name'][:14]} {100 * t['done'] // t['size']}%" for t in list(self.outgoing.values())]
        parts += [f"RX {t.filename[:14]} {100 * t.received // t.size}%" for t in list(self.incoming.values())]
        return " | ".join(parts)

    def render(self):
        width, height = self.console.size
        chat_height = max(1, height - 3 - 3 - 1 - 2)

        lines = []
        for m in list(self.messages)[-chat_height:]:
            lines.extend(self.render_line(m).wrap(self.console, max(10, width - 4)))
        lines = lines[-chat_height:]

        header = Text()
        header.append("OnionChat", style="bold white")
        header.append("  |  ", style="dim")
        header.append(self.name, style="bold green")
        header.append("  |  ", style="dim")
        header.append(self.server_label() if self.host else "not connected", style="cyan")
        header.append("  |  ", style="dim")
        header.append("E2EE AES-256-GCM", style="green")

        hidden = self.pending is not None
        label = f"{self.prompt_label}: " if hidden else "> "
        shown = "*" * len(self.input_buf) if hidden else self.input_buf
        entry = Text()
        entry.append(label, style="bold yellow" if hidden else "bold green")
        entry.append(shown[-max(1, width - 8 - len(label)):])
        entry.append("▌", style="blink")

        if self.connecting:
            state, style = "CONNECTING", "bold black on yellow"
        elif self.connected.is_set():
            state, style = "CONNECTED", "bold white on dark_green"
        else:
            state, style = "DISCONNECTED", "bold white on red"
        lat = f"{self.latency_ms:.0f} ms" if self.latency_ms is not None else "-- ms"
        bar = f" {state} | {self.server_label() if self.host else '-'}{' (Tor)' if self.via_tor else ''} " \
              f"| ping {lat} | sent {self.sent} recv {self.received} "
        extra = self.transfer_summary()
        bar += f"| {extra} " if extra else "| /help "

        layout = Layout()
        layout.split_column(
            Layout(Panel(header, box=box.ROUNDED, border_style="blue"), size=3),
            Layout(Panel(Group(*lines), box=box.ROUNDED, title="Chat",
                         title_align="left", border_style="blue")),
            Layout(Panel(entry, box=box.ROUNDED, border_style="yellow" if hidden else "green"), size=3),
            Layout(Text(bar.ljust(width)[:width], style=style), size=1),
        )
        return layout

    def interface(self):
        with Live(get_renderable=self.render, console=self.console,
                  screen=True, refresh_per_second=10), Keyboard() as keyboard:
            while self.running.is_set():
                ch = keyboard.read()
                if ch is None:
                    continue
                if ch in ("\r", "\n"):
                    text, self.input_buf = self.input_buf, ""
                    if self.pending is not None:
                        callback, self.pending, self.prompt_label = self.pending, None, ""
                        callback(text)                       # passwords are not stripped
                    elif text.strip():
                        self.handle_input(text.strip())
                elif ch in ("\x7f", "\x08"):
                    self.input_buf = self.input_buf[:-1]
                elif ch == "\x15":                           # Ctrl+U
                    self.input_buf = ""
                elif ch in ("\x03", "\x04"):                 # Ctrl+C / Ctrl+D
                    raise KeyboardInterrupt
                elif ch.isprintable() and len(self.input_buf) < 1000:
                    self.input_buf += ch

    # ── lifecycle ──

    def show_server_view(self, initial):
        if initial:
            for line in PORTRAIT.splitlines():
                self.add("art", line)
        else:
            self.messages.clear()
        if self.history:
            previous = self.history.recent(50, self.server_label())
            if previous:
                self.info(f"--- {len(previous)} earlier messages (encrypted history) ---")
                for r in previous:
                    if not isinstance(r, dict):
                        continue
                    self.add(r.get("kind", "msg"), r.get("m", ""), r.get("n", "?"),
                             old=True, ts=r.get("ts"))
                self.info("--- end of history ---")
        route = f" via Tor ({self.args.tor_host}:{self.tor_port})" if self.via_tor else ""
        self.info(f"Connected to {self.server_label()}{route}. Messages are end-to-end encrypted. "
                  f"Type /help for commands.")

    def run(self):
        self.running.set()
        self.show_server_view(initial=True)
        self.start_receiver()
        threading.Thread(target=self.heartbeat, daemon=True).start()
        try:
            self.send_encrypted({"t": "join", "n": self.name})
            self.interface()
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            self.shutdown()

    def shutdown(self):
        self.running.clear()
        try:
            self.send_encrypted({"t": "leave", "n": self.name})
        except OSError:
            pass
        self.connected.clear()
        self.abort_all_transfers("client closed")
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()
        if self.history:
            self.history.close()
        log.info("CLOSED       session of '%s' ended", self.name)


# ───────────────────────────── main ─────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="OnionChat - client")
    ap.add_argument("server", nargs="?",
                    help="host[:port] to join (.onion addresses use Tor automatically); asked if omitted")
    ap.add_argument("--tor", action="store_true", help="force Tor (SOCKS5) for any host")
    ap.add_argument("--tor-host", default="127.0.0.1")
    ap.add_argument("--tor-port", type=int, default=None,
                    help="Tor SOCKS port (default: try 9050, then 9150 for Tor Browser)")
    ap.add_argument("--db", default="onionchat_history.db", help="encrypted history file")
    ap.add_argument("--max-file-mb", type=int, default=DEFAULT_MAX_FILE_MB,
                    help=f"largest file to send or accept, in MB (default {DEFAULT_MAX_FILE_MB})")
    ap.add_argument("--downloads", default="downloads", help="folder for received files")
    ap.add_argument("--log", default="onionchat-client.log", help="log file")
    args = ap.parse_args()
    if args.max_file_mb < 1:
        print("[!] --max-file-mb must be at least 1")
        return 1
    if args.tor_port is not None and not 1 <= args.tor_port <= 65535:
        print("[!] --tor-port must be between 1 and 65535")
        return 1

    setup_logging(args.log)
    print(PORTRAIT)

    history = None
    try:
        name = sanitize(input("Your name: "), 20).strip() or "anonymous"

        master = getpass.getpass("Master password for your encrypted local history (empty = no history): ")
        if master:
            print("[*] Opening encrypted history (deriving key)...")
            try:
                history = History(args.db, master)
            except ValueError as e:
                print(f"[!] Could not open '{args.db}': {e}")
                print("    Use another file with --db, delete it, or leave the password empty.")
                return 1

        client = Client(args, name, history)

        target, first = args.server, True
        while True:
            if not target:
                if first:
                    target = input(f"Server to join (host[:port], default 127.0.0.1:{DEFAULT_PORT}): ").strip() \
                             or f"127.0.0.1:{DEFAULT_PORT}"
                else:
                    target = input("Try another server (empty to quit): ").strip()
                    if not target:
                        return 1
            first = False
            try:
                host, port = parse_server(target)
            except ValueError as e:
                print(f"[!] {e}")
                target = None
                continue

            password = getpass.getpass(f"Room password for {host}:{port}: ")
            if not password:
                print("[!] The room password cannot be empty.")
                target = None
                continue
            print("[*] Deriving key...")
            cipher = Cipher(derive_key(password, ROOM_SALT), AAD_MSG)
            print(f"[*] Connecting to {host}:{port} ...")
            try:
                sock, via_tor, tor_port = client.open_socket(host, port)
            except OSError as e:
                print(f"[!] Could not connect: {e}")
                log.error("CONNECT ERROR to %s:%d: %s", host, port, e)
                target = None
                continue
            client.install(sock, host, port, cipher, via_tor, tor_port)
            break

        client.run()
    except (KeyboardInterrupt, EOFError):
        print("\n[*] Bye.")
    finally:
        if history is not None:
            history.close()
    print("[*] Session closed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())