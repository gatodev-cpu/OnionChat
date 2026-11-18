#!/usr/bin/env python3
"""OnionChat - server.

A BLIND RELAY: it forwards encrypted lines between clients and cannot read
them. The key never reaches this process. To chat yourself, run the client.
"""
import argparse
import logging
import os
import queue
import re
import socket
import threading

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

MAX_LINE = 1_000_000                          # bytes per message (file chunks are ~120 KB)
MAX_QUEUED_BYTES = 64 * 1024 * 1024           # per-client backlog before it is dropped
QUIET_RELAY_BYTES = 20_000                    # bigger relays (file chunks) log at DEBUG
RE_B64 = re.compile(rb"[A-Za-z0-9+/=]+")      # encrypted messages are pure base64
RE_PING = re.compile(rb"[0-9.]{1,32}")

log = logging.getLogger("onionchat.server")


def setup_logging(log_path, verbose):
    log_dir = os.path.dirname(log_path)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    fmt = logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s", "%Y-%m-%d %H:%M:%S")
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    for handler in (logging.FileHandler(log_path, encoding="utf-8"), logging.StreamHandler()):
        handler.setFormatter(fmt)
        log.addHandler(handler)


class Peer:
    """A connected client with its own queue and writer thread.

    A slow client cannot block the others, and two threads never write to the
    same socket at once (so bytes never interleave). The backlog is limited in
    bytes, not messages, so large file transfers are handled fairly.
    """

    def __init__(self, conn, address):
        self.conn = conn
        self.label = f"{address[0]}:{address[1]}"
        self.queue = queue.Queue()
        self.queued = 0
        self.qlock = threading.Lock()
        self.closed = False

    def send(self, data):
        with self.qlock:
            if self.closed:
                return
            overflow = self.queued + len(data) > MAX_QUEUED_BYTES
            if not overflow:
                self.queued += len(data)
        if overflow:
            log.warning("BACKLOG    %s is too slow (over %d MB queued), dropping it",
                        self.label, MAX_QUEUED_BYTES // (1024 * 1024))
            self.close()
            return
        self.queue.put(data)

    def writer(self):
        while True:
            data = self.queue.get()
            if data is None:
                return
            try:
                self.conn.sendall(data)
            except OSError:
                self.close()
                return
            with self.qlock:
                self.queued -= len(data)

    def close(self):
        with self.qlock:
            if self.closed:
                return
            self.closed = True
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.queue.put(None)


class Server:
    def __init__(self, ip="127.0.0.1", port=5000, max_clients=50):
        # Listen locally only. With Tor, the hidden service points here.
        self.ip = ip
        self.port = port
        self.max_clients = max_clients
        self.peers = set()
        self.lock = threading.Lock()
        self.stop = threading.Event()

    @staticmethod
    def portrait():
        print(PORTRAIT)

    def broadcast(self, data, exclude=None):
        with self.lock:
            targets = [p for p in self.peers if p is not exclude]
        for peer in targets:
            peer.send(data)
        return len(targets)

    def remove(self, peer):
        with self.lock:
            self.peers.discard(peer)
        peer.close()
        try:
            peer.conn.close()
        except OSError:
            pass

    def serve_client(self, peer):
        """One thread per client: read lines and relay them without decrypting."""
        log.info("CONNECTED    %s (%d connected)", peer.label, len(self.peers))
        try:
            with peer.conn.makefile("rb") as reader:
                while not self.stop.is_set():
                    line = reader.readline(MAX_LINE + 1)
                    if not line:
                        break
                    if len(line) > MAX_LINE and not line.endswith(b"\n"):
                        log.warning("OVERSIZED   line from %s, disconnecting", peer.label)
                        break

                    clean = line.rstrip(b"\r\n")
                    if not clean:
                        continue

                    # Latency probe: answer only the client that asked
                    if clean.startswith(b"PING "):
                        payload = clean[5:]
                        if RE_PING.fullmatch(payload):
                            peer.send(b"PONG " + payload + b"\n")
                        continue

                    # Relay valid base64 only (prevents injecting control lines)
                    if not RE_B64.fullmatch(clean):
                        log.warning("BAD FORMAT   from %s (%d bytes), dropped", peer.label, len(clean))
                        continue

                    n = self.broadcast(clean + b"\n", exclude=peer)
                    level = logging.DEBUG if len(clean) > QUIET_RELAY_BYTES else logging.INFO
                    log.log(level, "RELAY        %d encrypted bytes from %s -> %d recipient(s)",
                            len(clean), peer.label, n)
        except OSError as e:
            log.warning("NETWORK ERR  with %s: %s", peer.label, e)
        finally:
            self.remove(peer)
            log.info("DISCONNECTED %s (%d connected)", peer.label, len(self.peers))

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                server.bind((self.ip, self.port))
            except OSError as e:
                log.error("Could not bind to %s:%d: %s", self.ip, self.port, e)
                return
            server.listen(5)
            server.settimeout(1.0)  # lets us check 'stop' and Ctrl+C

            log.info("Server started on %s:%d (blind relay, Ctrl+C to stop)", self.ip, self.port)

            try:
                while not self.stop.is_set():
                    try:
                        conn, address = server.accept()
                    except socket.timeout:
                        continue

                    with self.lock:
                        full = len(self.peers) >= self.max_clients
                    if full:
                        log.warning("REJECTED     %s:%d (server full)", *address)
                        conn.close()
                        continue

                    peer = Peer(conn, address)
                    with self.lock:
                        self.peers.add(peer)
                    threading.Thread(target=peer.writer, daemon=True).start()
                    threading.Thread(target=self.serve_client, args=(peer,), daemon=True).start()
            except KeyboardInterrupt:
                pass
            finally:
                log.info("Shutting down...")
                self.stop.set()
                with self.lock:
                    remaining = list(self.peers)
                for peer in remaining:
                    peer.close()
                    try:
                        peer.conn.close()
                    except OSError:
                        pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="OnionChat - relay server")
    ap.add_argument("--ip", default="127.0.0.1", help="IP to listen on (do not use 0.0.0.0 with Tor)")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--max-clients", type=int, default=50)
    ap.add_argument("--log", default="logs/onionchat.log", help="log file path")
    ap.add_argument("--verbose", action="store_true", help="also log every file-chunk relay")
    args = ap.parse_args()
    if not 1 <= args.port <= 65535:
        raise SystemExit("[!] --port must be between 1 and 65535")
    if args.max_clients < 1:
        raise SystemExit("[!] --max-clients must be at least 1")

    setup_logging(args.log, args.verbose)
    server = Server(args.ip, args.port, args.max_clients)
    server.portrait()
    server.start()