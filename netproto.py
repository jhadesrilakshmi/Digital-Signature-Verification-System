"""
netproto.py
-----------
Length-prefixed JSON framing for TCP communication.

Protocol:
    Each message is encoded as:
      [4-byte big-endian length][UTF-8 JSON payload]

    This prevents partial reads and message boundaries issues.
"""

import json
import socket
import struct

MAX_MESSAGE_SIZE = 50 * 1024 * 1024  # 50 MB safety limit


def send_json(sock: socket.socket, data: dict) -> None:
    """Serialise *data* as JSON and send it length-prefixed over *sock*."""
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    length = len(payload)
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message too large: {length} bytes (max {MAX_MESSAGE_SIZE}).")
    header = struct.pack(">I", length)
    sock.sendall(header + payload)


def recv_json(sock: socket.socket) -> dict:
    """Receive a length-prefixed JSON message from *sock* and return the dict."""
    # Read the 4-byte header
    header = _recv_exactly(sock, 4)
    if header is None:
        raise ConnectionError("Connection closed by remote host.")
    (length,) = struct.unpack(">I", header)
    if length == 0:
        return {}
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Incoming message too large: {length} bytes.")
    payload = _recv_exactly(sock, length)
    if payload is None:
        raise ConnectionError("Connection closed mid-message.")
    return json.loads(payload.decode("utf-8"))


def _recv_exactly(sock: socket.socket, n: int) -> bytes | None:
    """Read exactly *n* bytes from *sock*, or return None on EOF."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf
