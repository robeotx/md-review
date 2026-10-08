"""Minimal pure-Python mDNS responder (RFC 6762) — friendly LAN names.

Lets any device on the LAN reach the server as ``http://<name>.local:<port>/``
with **zero external dependencies and zero platform daemons** — no Avahi, no
Bonjour install, no Windows service. The whole mechanism: join the mDNS
multicast group (224.0.0.251:5353), and answer queries for our exact name
with an A record pointing at the host's LAN IPv4 addresses.

Deliberate scope (what a minimal responder may skip, and does):

- IPv4 answers only. If the network is v6-only, clients still resolve the
  name — most dual-stack clients fall back to A lookups seamlessly.
- No NSEC records, no goodbye packets, no probe-claim-announce sequence.
  One startup probe detects a collision (another machine already answering
  the name) and falls back to ``<name>-<hostname>.local`` with a loud
  warning instead of fighting over the name (RFC 6762 §9's spirit: never
  answer a name you don't uniquely own).
- Cache-flush bit set on answers; TTL 120 s so mobility/roaming churn
  heals quickly.

Client reachability notes (documented in the README): macOS/iOS/Windows 10+
resolve ``.local`` natively; Linux desktops with Avahi or systemd-resolved
do too; stock Android does NOT — there the answer is a router-level DNS
entry, which no application can provide for you.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import socket
import struct
import sys
import threading

MDNS_GROUP_V4 = "224.0.0.251"
MDNS_PORT = 5353
ANSWER_TTL_SECONDS = 120
PROBE_WAIT_SECONDS = 0.3

_TYPE_A = 1
_TYPE_AAAA = 28
_TYPE_ANY = 255
_CLASS_IN = 1
_FLAG_QR_AA = 0x8400  # response + authoritative answer
_PTR_QUESTION = 0xC00C  # compression pointer back to the question's name

NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def validate_mdns_name(name: str) -> str:
    """Normalize and validate an mDNS left-most label, or raise ValueError."""
    normalized = name.strip().lower().removesuffix(".local").strip(".")
    if not NAME_RE.match(normalized):
        raise ValueError(
            f"invalid mDNS name '{name}': use 1-63 chars of a-z 0-9 and interior dashes "
            "(e.g. md-review, reviewbox)"
        )
    return normalized


def encode_name(fqdn: str) -> bytes:
    """DNS wire-format name: length-prefixed labels, root terminator."""
    out = bytearray()
    for label in fqdn.rstrip(".").split("."):
        encoded = label.encode("ascii")
        out.append(len(encoded))
        out += encoded
    out.append(0)
    return bytes(out)


def decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Read a (possibly compressed) DNS name; return (name, next_offset)."""
    labels: list[str] = []
    jumped = False
    end = offset
    while True:
        length = packet[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(packet[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels) + ".", end


def parse_query(packet: bytes) -> tuple[int, list[tuple[str, int, int]]]:
    """Extract (transaction id, [(qname, qtype, qclass)]) from a DNS query packet.

    Malformed packets raise ValueError — callers treat that as "ignore".
    The raw qclass is preserved because bit 0x8000 (the QU bit) is the
    querier asking for a UNICAST response (RFC 6762 §5.4) — answering such
    a query by multicast leaves the querier waiting forever.
    """
    if len(packet) < 12:
        raise ValueError("short packet")
    tid, _flags, qdcount, _an, _ns, _ar = struct.unpack(">HHHHHH", packet[:12])
    questions: list[tuple[str, int, int]] = []
    offset = 12
    for _ in range(qdcount):
        qname, offset = decode_name(packet, offset)
        qtype, qclass = struct.unpack(">HH", packet[offset : offset + 4])
        offset += 4
        questions.append((qname, qtype, qclass))
    return tid, questions


def build_answer(tid: int, question: bytes, addresses: list[str]) -> bytes:
    """Build an authoritative-answer response echoing one question."""
    records = bytearray()
    for addr in addresses:
        # name-ptr(2) type(2) class-with-cache-flush(2) TTL(4) rdlength(2) rdata(4)
        records += struct.pack(">HHHI", _PTR_QUESTION, _TYPE_A, 0x8000 | _CLASS_IN, ANSWER_TTL_SECONDS)
        records += struct.pack(">H", 4)
        records += ipaddress.ip_address(addr).packed
    header = struct.pack(">HHHHHH", tid, _FLAG_QR_AA, 1, len(addresses), 0, 0)
    return header + question + bytes(records)


def probe_name_taken(fqdn: str, timeout: float = PROBE_WAIT_SECONDS) -> bool:
    """Best-effort collision probe: does ANYONE else already answer this name?

    A single ANY query; any answer from an address that isn't one of ours
    means the name is taken. Best-effort by design (a silent owner within the
    300 ms window is indistinguishable from an absent one) — answering is
    still gated on the exact-name match, so a missed probe is a naming
    collision, never a traffic hijack.
    """
    query = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + encode_name(fqdn) + struct.pack(">HH", _TYPE_ANY, _CLASS_IN)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (MDNS_GROUP_V4, MDNS_PORT))
            try:
                data, _src = sock.recvfrom(4096)
            except TimeoutError:
                return False
        try:
            _tid, _questions = parse_query(data)
            an_count = struct.unpack(">H", data[6:8])[0]
            return an_count > 0
        except (ValueError, struct.error, IndexError):
            return False
    except OSError:
        return False  # multicast unavailable — don't block naming on it


def response_target(src: tuple[str, int], qclass: int) -> tuple[str, int]:
    """Where an answer must go for a given querier (RFC 6762 §5.4).

    - A query from a source port OTHER than 5353 is a "legacy unicast query":
      the answer MUST go back unicast to the querier's own socket. Resolvers
      like systemd-resolved, Windows' mDNS client, and Android's NSD do
      exactly this — a multicast answer to them is dropped on the floor.
    - A query from 5353 with the QU bit (qclass 0x8000) asks for unicast too.
    - Otherwise the answer goes to the multicast group for everyone's cache.
    """
    if src[1] != MDNS_PORT or (qclass & 0x8000):
        return src
    return (MDNS_GROUP_V4, MDNS_PORT)


class MdnsResponder:
    """Background thread answering mDNS queries for exactly one name."""

    def __init__(self, fqdn: str, addresses: list[str]):
        if not addresses:
            raise ValueError("mDNS responder needs at least one LAN IPv4 address to advertise")
        self.fqdn = fqdn if fqdn.endswith(".") else fqdn + "."
        self.addresses = addresses
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._socket: socket.socket | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        self._socket = self._open_socket()
        self._thread = threading.Thread(target=self._serve_guarded, name=f"mdns-{self.fqdn}", daemon=True)
        self._thread.start()

    def _serve_guarded(self) -> None:
        # A dead responder must never fail SILENTLY — the name just stops
        # resolving and everyone assumes "mDNS is flaky".
        try:
            self._serve()
        except Exception as exc:  # noqa: BLE001 — last-resort boundary log
            sys.stderr.write(f"[md-review] mDNS responder for {self.fqdn} died: {exc!r}\n")

    def stop(self) -> None:
        self._stop.set()
        if self._socket is not None:
            with contextlib.suppress(OSError):
                self._socket.close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _open_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", MDNS_PORT))
        membership = ipaddress.ip_address(MDNS_GROUP_V4).packed + ipaddress.ip_address("0.0.0.0").packed
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        sock.settimeout(1.0)
        return sock

    def _serve(self) -> None:
        assert self._socket is not None
        while not self._stop.is_set():
            try:
                packet, src = self._socket.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                break  # socket closed by stop()
            try:
                tid, questions = parse_query(packet)
            except (ValueError, IndexError, struct.error):
                continue  # foreign mDNS chatter is constant and not ours to parse
            offset = 12
            for qname, qtype, qclass in questions:
                try:
                    qname_wire, next_offset = _question_wire(packet, offset)
                except (IndexError, struct.error):
                    break  # malformed tail — stop walking this packet
                offset = next_offset
                if qname.lower() != self.fqdn.lower():
                    continue
                if qtype not in (_TYPE_A, _TYPE_ANY):
                    continue  # AAAA/others: stay silent (v4-only responder)
                answer = build_answer(tid, qname_wire, self.addresses)
                try:
                    self._socket.sendto(answer, response_target(src, qclass))
                except OSError:
                    break


def _question_wire(packet: bytes, offset: int) -> tuple[bytes, int]:
    """Return (question section bytes, offset past it) for one question."""
    _name, end = decode_name(packet, offset)
    return packet[offset : end + 4], end + 4


def advertise(name: str, addresses: list[str]) -> tuple[MdnsResponder, str]:
    """Probe, pick a unique name, and start the responder.

    Returns (responder, fqdn-advertised). On collision, falls back to
    ``<name>-<hostname>.local`` and warns — the caller should print the
    final name loudly since it differs from what was asked for.
    """
    fqdn = f"{name}.local"
    advertised = fqdn
    if probe_name_taken(fqdn):
        fallback = f"{name}-{socket.gethostname().lower()}.local"
        print(f"[md-review] mDNS name '{fqdn}' is already taken on this LAN; advertising '{fallback}' instead", file=sys.stderr)
        advertised = fallback
    responder = MdnsResponder(advertised, addresses)
    responder.start()
    return responder, advertised
