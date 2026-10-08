"""Decode raw DNS wire-format bytes into structured Python objects.

The decoder is deliberately minimal: it reads the five standard sections
(header, question, answer, authority, additional) and understands the rdata
formats that are common in real traffic on the public Internet.  Rdata types
we do not model are returned verbatim as ``RdataUnknown``, so callers never
lose bytes and can post-process them however they like.

Design decisions worth stating plainly:

* Only a single parser pass is made.  DNS name compression is resolved on the
  fly against the already-seen prefix of the packet, which is the only region
  the RFC allows pointers to target.
* EDNS0 OPT pseudo-records are decoded as ordinary resource records of type
  41 (their rdata is opaque) rather than being promoted to a first-class
  concept.  This keeps the public surface small; callers that care about EDNS
  can filter on type 41 themselves.
* All multi-byte integer fields are interpreted as network byte order
  (big-endian), per RFC 1035 §4.1.1.
* WKS records (type 11) are not given a typed rdata class.  Their rdata is
  returned as ``RdataUnknown``.  We chose this over a half-correct typed
  parser because a wrong address-length assumption in WKS is historically a
  source of silent corruption.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------


class DecodeError(Exception):
    """Raised when the wire bytes are truncated or otherwise malformed."""


# ---------------------------------------------------------------------------
# Rdata containers
# ---------------------------------------------------------------------------
#
# Each typed rdata class carries exactly the fields that its RFC defines.  We
# use plain dataclasses so the decoded values are trivially comparable in
# tests and serialisable with ``dataclasses.asdict``.


@dataclass(frozen=True)
class RdataA:
    address: str


@dataclass(frozen=True)
class RdataAAAA:
    address: str


@dataclass(frozen=True)
class RdataCNAME:
    name: str


@dataclass(frozen=True)
class RdataNS:
    name: str


@dataclass(frozen=True)
class RdataPTR:
    name: str


@dataclass(frozen=True)
class RdataTXT:
    # One entry per <character-string> in the rdata, preserving order.
    strings: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class RdataMX:
    preference: int
    exchange: str


@dataclass(frozen=True)
class RdataSOA:
    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int


@dataclass(frozen=True)
class RdataSRV:
    priority: int
    weight: int
    port: int
    target: str


@dataclass(frozen=True)
class RdataUnknown:
    rtype: int
    raw: bytes


# ---------------------------------------------------------------------------
# Structural containers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Header:
    id: int
    flags: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)

    @property
    def opcode(self) -> int:
        return (self.flags >> 11) & 0xF

    @property
    def authoritative(self) -> bool:
        return bool(self.flags & 0x0400)

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)

    @property
    def recursion_desired(self) -> bool:
        return bool(self.flags & 0x0100)

    @property
    def recursion_available(self) -> bool:
        return bool(self.flags & 0x0080)

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F


@dataclass(frozen=True)
class Question:
    name: str
    qtype: int
    qclass: int


@dataclass(frozen=True)
class ResourceRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: object  # one of the Rdata* dataclasses


@dataclass(frozen=True)
class DNSPacket:
    header: Header
    questions: List[Question] = field(default_factory=list)
    answers: List[ResourceRecord] = field(default_factory=list)
    authority: List[ResourceRecord] = field(default_factory=list)
    additional: List[ResourceRecord] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
#
# The parser holds its state in a tiny cursor object so that name-compression
# pointers can be resolved by rewinding the read position, following the
# pointer, and then restoring the position to continue parsing the outer
# record.  This is the standard technique; doing it without mutation would
# require threading (offset, bytes) through every call, which is noisy.


class _Cursor:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read(self, n: int) -> bytes:
        if n < 0:
            raise DecodeError("negative read length")
        end = self.pos + n
        if end > len(self.data):
            raise DecodeError("packet truncated")
        chunk = self.data[self.pos : end]
        self.pos = end
        return chunk

    def read_u16(self) -> int:
        return struct.unpack("!H", self.read(2))[0]

    def read_u32(self) -> int:
        return struct.unpack("!I", self.read(4))[0]


def _decode_name(cursor: _Cursor) -> str:
    """Decode a compressed domain name, honouring the 0xC0 pointer scheme.

    The RFC limits compression pointers to earlier offsets; we additionally
    cap the total number of pointer hops at 64, which is far more than any
    legitimate packet needs.  Without that cap a malicious pair of pointers
    that reference each other would loop until the Python recursion limit is
    hit.
    """
    labels: List[str] = []
    hops = 0
    offset = cursor.pos
    data = cursor.data
    followed = False

    while True:
        if offset >= len(data):
            raise DecodeError("name runs past end of packet")
        length = data[offset]
        offset += 1

        if length == 0:
            break

        if (length & 0xC0) == 0xC0:
            if offset >= len(data):
                raise DecodeError("truncated compression pointer")
            ptr = ((length & 0x3F) << 8) | data[offset]
            offset += 1
            hops += 1
            if hops > 64:
                raise DecodeError("too many compression pointers")
            if ptr >= offset - 2:
                # Pointers must target earlier bytes.  Allowing forward or
                # self-referential pointers is what creates infinite loops.
                raise DecodeError("illegal forward compression pointer")
            if not followed:
                cursor.pos = offset
                followed = True
            offset = ptr
            continue

        if (length & 0xC0) != 0:
            raise DecodeError("reserved label length flags")

        end = offset + length
        if end > len(data):
            raise DecodeError("label runs past end of packet")
        labels.append(data[offset:end].decode("ascii", errors="strict"))
        offset = end

    if not followed:
        cursor.pos = offset

    return ".".join(labels)


def _decode_rdata(
    cursor: _Cursor, rtype: int, rdata_len: int, packet: bytes, rdata_start: int
) -> object:
    """Decode rdata bytes for ``rtype`` into a typed container.

    Names embedded in rdata may use compression pointers that resolve
    against the whole packet, not just the rdata window.  To support that we
    slice the declared rdata region out of the cursor and, for name-bearing
    types, parse the name with a fresh cursor positioned at the packet-level
    offset.  For non-name types we parse directly off ``rdata_bytes``.
    """
    rdata_bytes = cursor.read(rdata_len)

    if rtype == 1:  # A
        if rdata_len != 4:
            raise DecodeError("A record rdata must be 4 bytes")
        return RdataA(address=str(ipaddress.IPv4Address(rdata_bytes)))

    if rtype == 28:  # AAAA
        if rdata_len != 16:
            raise DecodeError("AAAA record rdata must be 16 bytes")
        return RdataAAAA(address=str(ipaddress.IPv6Address(rdata_bytes)))

    if rtype in (5, 2, 12):  # CNAME, NS, PTR
        sub = _Cursor(packet)
        sub.pos = rdata_start
        name = _decode_name(sub)
        if rtype == 5:
            return RdataCNAME(name=name)
        if rtype == 2:
            return RdataNS(name=name)
        return RdataPTR(name=name)

    if rtype == 16:  # TXT
        strings: List[str] = []
        i = 0
        while i < len(rdata_bytes):
            slen = rdata_bytes[i]
            i += 1
            if i + slen > len(rdata_bytes):
                raise DecodeError("TXT character-string runs past rdata")
            strings.append(rdata_bytes[i : i + slen].decode("utf-8", errors="strict"))
            i += slen
        return RdataTXT(strings=strings)

    if rtype == 15:  # MX
        if rdata_len < 3:
            raise DecodeError("MX rdata too short")
        preference = struct.unpack("!H", rdata_bytes[:2])[0]
        sub = _Cursor(packet)
        sub.pos = rdata_start + 2
        exchange = _decode_name(sub)
        return RdataMX(preference=preference, exchange=exchange)

    if rtype == 6:  # SOA
        sub = _Cursor(packet)
        sub.pos = rdata_start
        mname = _decode_name(sub)
        rname = _decode_name(sub)
        if sub.remaining() < 20:
            raise DecodeError("SOA rdata missing fixed fields")
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", sub.read(20))
        return RdataSOA(
            mname=mname,
            rname=rname,
            serial=serial,
            refresh=refresh,
            retry=retry,
            expire=expire,
            minimum=minimum,
        )

    if rtype == 33:  # SRV
        if rdata_len < 7:
            raise DecodeError("SRV rdata too short")
        priority, weight, port = struct.unpack("!HHH", rdata_bytes[:6])
        sub = _Cursor(packet)
        sub.pos = rdata_start + 6
        target = _decode_name(sub)
        return RdataSRV(priority=priority, weight=weight, port=port, target=target)

    return RdataUnknown(rtype=rtype, raw=rdata_bytes)


def _decode_question(cursor: _Cursor) -> Question:
    name = _decode_name(cursor)
    qtype = cursor.read_u16()
    qclass = cursor.read_u16()
    return Question(name=name, qtype=qtype, qclass=qclass)


def _decode_rr(cursor: _Cursor, packet: bytes) -> ResourceRecord:
    name = _decode_name(cursor)
    rtype = cursor.read_u16()
    rclass = cursor.read_u16()
    ttl = cursor.read_u32()
    rdlength = cursor.read_u16()
    rdata_start = cursor.pos
    rdata = _decode_rdata(cursor, rtype, rdlength, packet, rdata_start)
    return ResourceRecord(name=name, rtype=rtype, rclass=rclass, ttl=ttl, rdata=rdata)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def decode(data: bytes) -> DNSPacket:
    """Decode ``data`` (raw DNS wire bytes) into a :class:`DNSPacket`.

    Raises :class:`DecodeError` on truncation or structural violation.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("decode() expects bytes")
    cursor = _Cursor(bytes(data))
    if cursor.remaining() < 12:
        raise DecodeError("packet shorter than 12-byte header")
    id_, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", cursor.read(12))
    header = Header(
        id=id_,
        flags=flags,
        qdcount=qd,
        ancount=an,
        nscount=ns,
        arcount=ar,
    )

    questions: List[Question] = []
    for _ in range(qd):
        questions.append(_decode_question(cursor))

    answers: List[ResourceRecord] = []
    for _ in range(an):
        answers.append(_decode_rr(cursor, cursor.data))

    authority: List[ResourceRecord] = []
    for _ in range(ns):
        authority.append(_decode_rr(cursor, cursor.data))

    additional: List[ResourceRecord] = []
    for _ in range(ar):
        additional.append(_decode_rr(cursor, cursor.data))

    return DNSPacket(
        header=header,
        questions=questions,
        answers=answers,
        authority=authority,
        additional=additional,
    )
