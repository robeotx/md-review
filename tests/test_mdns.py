"""mDNS responder tests: packet codec round-trips, name validation, and
Host-validation integration. Multicast itself is exercised best-effort
(the probe), never asserted — CI networks may block it."""

from __future__ import annotations

import struct
import unittest

from mdreview import mdns
from mdreview.server import host_allowed


def make_query(tid: int, fqdn: str, qtype: int = 1) -> bytes:
    return struct.pack(">HHHHHH", tid, 0, 1, 0, 0, 0) + mdns.encode_name(fqdn) + struct.pack(">HH", qtype, 1)


class NameValidationTests(unittest.TestCase):
    def test_good_names(self) -> None:
        self.assertEqual(mdns.validate_mdns_name("md-review"), "md-review")
        self.assertEqual(mdns.validate_mdns_name("MD-Review.local"), "md-review")  # case + suffix normalized
        self.assertEqual(mdns.validate_mdns_name("reviewbox"), "reviewbox")
        self.assertEqual(mdns.validate_mdns_name("a1"), "a1")

    def test_bad_names_rejected(self) -> None:
        for bad in ["", "-lead", "trail-", "has space", "under_score", "x" * 64, "..", "a..b"]:
            with self.assertRaises(ValueError, msg=bad):
                mdns.validate_mdns_name(bad)


class PacketCodecTests(unittest.TestCase):
    def test_name_round_trip(self) -> None:
        for name in ["md-review.local.", "a.b.c.", "x.local."]:
            encoded = mdns.encode_name(name)
            decoded, end = mdns.decode_name(encoded, 0)
            self.assertEqual(decoded, name)
            self.assertEqual(end, len(encoded))

    def test_parse_query(self) -> None:
        packet = make_query(0x1234, "md-review.local.")
        tid, questions = mdns.parse_query(packet)
        self.assertEqual(tid, 0x1234)
        self.assertEqual(questions, [("md-review.local.", 1, 1)])

    def test_build_answer_layout(self) -> None:
        query = make_query(0xBEEF, "md-review.local.")
        tid, questions = mdns.parse_query(query)
        _qname_wire, _end = mdns._question_wire(query, 12)
        answer = mdns.build_answer(tid, _qname_wire, ["10.0.0.45"])
        # header: id echoed, QR+AA set, 1 question, 1 answer
        rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", answer[:12])
        self.assertEqual(rid, 0xBEEF)
        self.assertEqual(flags & 0x8400, 0x8400)
        self.assertEqual((qd, an, ns, ar), (1, 1, 0, 0))
        # answer record: compressed name pointer, type A, TTL, IPv4 rdata
        answer_start = 12 + len(_qname_wire)
        name_ptr, rtype, rclass, ttl, rdlen = struct.unpack(">HHHIH", answer[answer_start : answer_start + 12])
        self.assertEqual(name_ptr, 0xC00C)
        self.assertEqual(rtype, 1)
        self.assertTrue(rclass & 0x8000)  # cache-flush
        self.assertEqual(ttl, mdns.ANSWER_TTL_SECONDS)
        self.assertEqual(rdlen, 4)
        self.assertEqual(answer[answer_start + 12 : answer_start + 16], bytes([10, 0, 0, 45]))

    def test_parse_rejects_short_packet(self) -> None:
        with self.assertRaises(ValueError):
            mdns.parse_query(b"\x00" * 5)


class ResponderContractTests(unittest.TestCase):
    def test_requires_addresses(self) -> None:
        with self.assertRaises(ValueError):
            mdns.MdnsResponder("md-review.local", [])

    def test_probe_quiet_name_not_taken(self) -> None:
        # A name nothing on any sane LAN answers; multicast failure also maps
        # to False (best-effort probe must never block naming).
        self.assertFalse(mdns.probe_name_taken("md-review-probe-nonexistent-zzz.local"))


class ResponseTargetTests(unittest.TestCase):
    """RFC 6762 §5.4: legacy unicast queries (source port != 5353) and QU-bit
    questions must get their answers UNICAST — answering them by multicast is
    exactly what made phone resolvers time out (observed on a phone, 2026-08-01)."""

    def test_legacy_unicast_port_gets_unicast(self) -> None:
        self.assertEqual(mdns.response_target(("10.0.0.17", 64021), 1), ("10.0.0.17", 64021))

    def test_qu_bit_gets_unicast_even_from_5353(self) -> None:
        self.assertEqual(mdns.response_target(("10.0.0.17", 5353), 0x8001), ("10.0.0.17", 5353))

    def test_plain_5353_query_gets_multicast(self) -> None:
        self.assertEqual(
            mdns.response_target(("10.0.0.17", 5353), 1),
            (mdns.MDNS_GROUP_V4, mdns.MDNS_PORT),
        )


class HostValidationIntegrationTests(unittest.TestCase):
    def test_advertised_name_passes_only_when_registered(self) -> None:
        self.assertFalse(host_allowed("md-review.local:8779"))
        self.assertTrue(host_allowed("md-review.local:8779", frozenset({"md-review.local"})))
        self.assertTrue(host_allowed("md-review.local", frozenset({"md-review.local"})))
        # collision-fallback names work the same way
        self.assertTrue(host_allowed("md-review-myhost.local:8779", frozenset({"md-review-myhost.local"})))
        # and registering one name doesn't open the whole .local namespace
        self.assertFalse(host_allowed("anything.local:8779", frozenset({"md-review.local"})))


if __name__ == "__main__":
    raise SystemExit(unittest.main())
