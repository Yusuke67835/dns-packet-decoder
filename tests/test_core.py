import struct
import unittest

from dns_packet_decoder import (
    DNSPacket,
    Header,
    Question,
    ResourceRecord,
    RdataA,
    RdataAAAA,
    RdataCNAME,
    RdataNS,
    RdataPTR,
    RdataTXT,
    RdataMX,
    RdataSOA,
    RdataSRV,
    RdataUnknown,
    DecodeError,
    decode,
)


def _name(name: str) -> bytes:
    """Encode a domain name without compression."""
    out = bytearray()
    if name:
        for label in name.split("."):
            b = label.encode("ascii")
            if len(b) > 63:
                raise ValueError("label too long")
            out.append(len(b))
            out.extend(b)
    out.append(0)
    return bytes(out)


def _question(name: str, qtype: int, qclass: int = 1) -> bytes:
    return _name(name) + struct.pack("!HH", qtype, qclass)


def _rr(name: str, rtype: int, rdata: bytes, ttl: int = 300, rclass: int = 1) -> bytes:
    return (
        _name(name)
        + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata))
        + rdata
    )


def _packet(questions=(), answers=(), authority=(), additional=(),
            id_=0x1234, flags=0x8180) -> bytes:
    header = struct.pack(
        "!HHHHHH", id_, flags,
        len(questions), len(answers), len(authority), len(additional),
    )
    body = b"".join(questions) + b"".join(answers)
    body += b"".join(authority) + b"".join(additional)
    return header + body


class TestHeader(unittest.TestCase):
    def test_standard_query_header(self):
        # flags 0x0100 => RD set, QR clear, standard query
        pkt = decode(struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
                     + _question("example", 1))
        self.assertEqual(pkt.header.id, 0xABCD)
        self.assertFalse(pkt.header.is_response)
        self.assertEqual(pkt.header.opcode, 0)
        self.assertFalse(pkt.header.authoritative)
        self.assertFalse(pkt.header.truncated)
        self.assertTrue(pkt.header.recursion_desired)
        self.assertFalse(pkt.header.recursion_available)
        self.assertEqual(pkt.header.rcode, 0)

    def test_response_flags(self):
        # flags 0x8180 => QR+RD+RA, rcode 0
        pkt = decode(struct.pack("!HHHHHH", 1, 0x8180, 0, 0, 0, 0))
        self.assertTrue(pkt.header.is_response)
        self.assertTrue(pkt.header.recursion_available)
        self.assertEqual(pkt.header.rcode, 0)

    def test_rcode_nxdomain(self):
        # flags 0x8183 => rcode 3
        pkt = decode(struct.pack("!HHHHHH", 1, 0x8183, 0, 0, 0, 0))
        self.assertEqual(pkt.header.rcode, 3)


class TestQuestions(unittest.TestCase):
    def test_single_question(self):
        pkt = decode(_packet(questions=[_question("example", 1)]))
        self.assertEqual(len(pkt.questions), 1)
        q = pkt.questions[0]
        self.assertEqual(q.name, "example")
        self.assertEqual(q.qtype, 1)
        self.assertEqual(q.qclass, 1)

    def test_root_question(self):
        # DNS root is a single zero-length label.
        pkt = decode(_packet(questions=[_question("", 6)]))
        self.assertEqual(pkt.questions[0].name, "")

    def test_multi_label(self):
        pkt = decode(_packet(questions=[_question("a.b.c", 16)]))
        self.assertEqual(pkt.questions[0].name, "a.b.c")


class TestARecord(unittest.TestCase):
    def test_a_record(self):
        rdata = bytes([192, 0, 2, 1])
        pkt = decode(_packet(answers=[_rr("example", 1, rdata)]))
        rr = pkt.answers[0]
        self.assertEqual(rr.rtype, 1)
        self.assertIsInstance(rr.rdata, RdataA)
        self.assertEqual(rr.rdata.address, "192.0.2.1")

    def test_a_wrong_length(self):
        with self.assertRaises(DecodeError):
            decode(_packet(answers=[_rr("example", 1, bytes([1, 2, 3]))]))


class TestAAAARecord(unittest.TestCase):
    def test_aaaa_record(self):
        rdata = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 12)
        pkt = decode(_packet(answers=[_rr("example", 28, rdata)]))
        self.assertEqual(pkt.answers[0].rdata.address, "2001:db8::")


class TestCNAMERecord(unittest.TestCase):
    def test_cname_with_compression(self):
        # Build a packet where the CNAME target uses a compression pointer
        # back to the owner name of the record.
        owner = _name("alias")
        q = _question("alias", 1)
        # rdata = pointer to offset 12 (start of owner name in the question)
        rdata = bytes([0xC0, 0x0C])
        rr_body = owner + struct.pack("!HHIH", 5, 1, 60, len(rdata)) + rdata
        raw = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + q + rr_body
        pkt = decode(raw)
        self.assertEqual(pkt.answers[0].rdata.name, "alias")


class TestNSAndPTR(unittest.TestCase):
    def test_ns_record(self):
        rdata = _name("ns1.example")
        pkt = decode(_packet(authority=[_rr("example", 2, rdata)]))
        self.assertEqual(pkt.authority[0].rdata.name, "ns1.example")

    def test_ptr_record(self):
        rdata = _name("host.example")
        pkt = decode(_packet(answers=[_rr("1.0.168.192.in-addr.arpa", 12, rdata)]))
        self.assertEqual(pkt.answers[0].rdata.name, "host.example")


class TestTXTRecord(unittest.TestCase):
    def test_single_string(self):
        s = b"hello world"
        rdata = bytes([len(s)]) + s
        pkt = decode(_packet(answers=[_rr("example", 16, rdata)]))
        self.assertEqual(pkt.answers[0].rdata.strings, ["hello world"])

    def test_multiple_strings(self):
        a = b"v=spf1"
        b = b"-all"
        rdata = bytes([len(a)]) + a + bytes([len(b)]) + b
        pkt = decode(_packet(answers=[_rr("example", 16, rdata)]))
        self.assertEqual(pkt.answers[0].rdata.strings, ["v=spf1", "-all"])

    def test_empty_txt(self):
        pkt = decode(_packet(answers=[_rr("example", 16, b"")]))
        self.assertEqual(pkt.answers[0].rdata.strings, [])

    def test_txt_truncated(self):
        # Declared length 10 but only 3 bytes follow.
        rdata = bytes([10]) + b"abc"
        with self.assertRaises(DecodeError):
            decode(_packet(answers=[_rr("example", 16, rdata)]))


class TestMXRecord(unittest.TestCase):
    def test_mx_record(self):
        rdata = struct.pack("!H", 10) + _name("mail.example")
        pkt = decode(_packet(answers=[_rr("example", 15, rdata)]))
        mx = pkt.answers[0].rdata
        self.assertEqual(mx.preference, 10)
        self.assertEqual(mx.exchange, "mail.example")


class TestSOARecord(unittest.TestCase):
    def test_soa_record(self):
        rdata = (_name("ns1.example") + _name("admin.example")
                 + struct.pack("!IIIII", 2024010101, 3600, 900, 604800, 86400))
        pkt = decode(_packet(authority=[_rr("example", 6, rdata)]))
        soa = pkt.authority[0].rdata
        self.assertEqual(soa.mname, "ns1.example")
        self.assertEqual(soa.rname, "admin.example")
        self.assertEqual(soa.serial, 2024010101)
        self.assertEqual(soa.refresh, 3600)
        self.assertEqual(soa.retry, 900)
        self.assertEqual(soa.expire, 604800)
        self.assertEqual(soa.minimum, 86400)


class TestSRVRecord(unittest.TestCase):
    def test_srv_record(self):
        rdata = struct.pack("!HHH", 10, 20, 5060) + _name("sip.example")
        pkt = decode(_packet(answers=[_rr("_sip._tcp.example", 33, rdata)]))
        srv = pkt.answers[0].rdata
        self.assertEqual(srv.priority, 10)
        self.assertEqual(srv.weight, 20)
        self.assertEqual(srv.port, 5060)
        self.assertEqual(srv.target, "sip.example")


class TestUnknownRecord(unittest.TestCase):
    def test_unknown_type_preserved(self):
        rdata = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        pkt = decode(_packet(answers=[_rr("example", 999, rdata)]))
        rr = pkt.answers[0]
        self.assertIsInstance(rr.rdata, RdataUnknown)
        self.assertEqual(rr.rdata.rtype, 999)
        self.assertEqual(rr.rdata.raw, rdata)


class TestCompression(unittest.TestCase):
    def test_two_pointer_hops(self):
        # owner = example; rdata points to owner, owner itself is compressed
        # to a suffix shared with the question.  This exercises the
        # multi-hop pointer path.
        q = _question("example", 1)               # offset 12 ..
        owner = bytes([0xC0, 0x0C])               # pointer to "example"
        rdata = bytes([0xC0, 0x0C])               # pointer to "example"
        rr = owner + struct.pack("!HHIH", 5, 1, 60, len(rdata)) + rdata
        raw = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + q + rr
        pkt = decode(raw)
        self.assertEqual(pkt.answers[0].name, "example")
        self.assertEqual(pkt.answers[0].rdata.name, "example")

    def test_forward_pointer_rejected(self):
        # A pointer that targets a later offset is illegal and would risk
        # an infinite loop if allowed.
        rdata = bytes([0xC0, 0x20])  # points well past current position
        rr = _name("x") + struct.pack("!HHIH", 5, 1, 60, len(rdata)) + rdata
        raw = struct.pack("!HHHHHH", 1, 0x8180, 0, 1, 0, 0) + rr
        with self.assertRaises(DecodeError):
            decode(raw)

    def test_pointer_hop_limit(self):
        # Construct two rdata pointers that reference each other.  We place
        # them as two CNAME records so each rdata is a pointer.
        # Pointer A at offset X points to offset Y; pointer B at offset Y
        # points back to offset X.  The decoder must refuse after 64 hops.
        q = _question("example", 1)  # offset 12
        owner1 = _name("a")
        owner2 = _name("b")
        # Compute offsets: header (12) + q + owner1 + fixed fields (10) = rdata1 start
        offset_rdata1 = 12 + len(q) + len(owner1) + 10
        # rdata1 (2 bytes) + owner2 + fixed fields (10) = rdata2 start
        offset_rdata2 = offset_rdata1 + 2 + len(owner2) + 10
        rr1 = owner1 + struct.pack("!HHIH", 5, 1, 60, 2) + struct.pack("!BB", 0xC0 | ((offset_rdata2 >> 8) & 0x3F), offset_rdata2 & 0xFF)
        rr2 = owner2 + struct.pack("!HHIH", 5, 1, 60, 2) + struct.pack("!BB", 0xC0 | ((offset_rdata1 >> 8) & 0x3F), offset_rdata1 & 0xFF)
        raw = struct.pack("!HHHHHH", 1, 0x8180, 1, 2, 0, 0) + q + rr1 + rr2
        with self.assertRaises(DecodeError):
            decode(raw)


class TestTruncation(unittest.TestCase):
    def test_short_header(self):
        with self.assertRaises(DecodeError):
            decode(b"\x00\x00\x00")

    def test_truncated_question(self):
        # Header claims 1 question but body is empty.
        raw = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        with self.assertRaises(DecodeError):
            decode(raw)

    def test_truncated_rrdata(self):
        # rdlength says 4 but only 2 bytes present.
        rr = _name("x") + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02"
        raw = struct.pack("!HHHHHH", 1, 0x8180, 0, 1, 0, 0) + rr
        with self.assertRaises(DecodeError):
            decode(raw)


class TestNonBytes(unittest.TestCase):
    def test_rejects_str(self):
        with self.assertRaises(TypeError):
            decode("not bytes")


class TestRoundtripSections(unittest.TestCase):
    def test_all_four_sections_populated(self):
        pkt_bytes = _packet(
            questions=[_question("example", 1)],
            answers=[_rr("example", 1, bytes([192, 0, 2, 1]))],
            authority=[_rr("example", 2, _name("ns1.example"))],
            additional=[_rr("ns1.example", 1, bytes([192, 0, 2, 53]))],
        )
        pkt = decode(pkt_bytes)
        self.assertEqual(len(pkt.questions), 1)
        self.assertEqual(len(pkt.answers), 1)
        self.assertEqual(len(pkt.authority), 1)
        self.assertEqual(len(pkt.additional), 1)
        self.assertEqual(pkt.additional[0].rdata.address, "192.0.2.53")


if __name__ == "__main__":
    unittest.main()
