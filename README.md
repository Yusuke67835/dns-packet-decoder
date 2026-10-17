# dns-packet-decoder

Decode raw DNS wire-format bytes into structured query, answer, authority, and additional section records. Standard library only, no third-party dependencies.

## Usage

```python
from dns_packet_decoder import decode, DNSPacket

raw = bytes.fromhex(
    "123481800001000000000000076578616d706c650000010001"
)
pkt: DNSPacket = decode(raw)
print(pkt.header.id, pkt.header.rcode)
print(pkt.questions[0].name, pkt.questions[0].qtype)
```

The exported names are: `decode`, `DNSPacket`, `Header`, `Question`, `ResourceRecord`, `RdataA`, `RdataAAAA`, `RdataCNAME`, `RdataNS`, `RdataPTR`, `RdataTXT`, `RdataMX`, `RdataSOA`, `RdataSRV`, `RdataUnknown`, `DecodeError`.

## Why this exists

The problem is narrow: you have a buffer of DNS bytes (from a socket, a pcap, or a test fixture) and you need the fields broken out into plain Python objects you can assert against. There are general-purpose DNS libraries on PyPI, but pulling one in for a decoder-only task tends to drag in networking, async, or resolver machinery. This library does one thing — decode — and returns immutable dataclasses.

The trade-off: rdata types that are rare or awkward to parse correctly (WKS, some EDNS option structures) are returned as `RdataUnknown` with their raw bytes intact rather than risk a silently wrong typed interpretation. Callers who need those types can post-process the `raw` field. EDNS0 OPT records (type 41) are decoded as ordinary resource records, not promoted to a first-class concept.

## Edge you will hit

DNS name compression. Owner names and names embedded in CNAME, NS, MX, SOA, and SRV rdata may use 0xC0-style pointers back into earlier bytes. The decoder resolves these against the packet prefix and refuses forward or self-referential pointers (capped at 64 hops) to avoid infinite loops on hostile input. If you construct test packets by hand, get the pointer offsets right or expect a `DecodeError`.

## Running the tests

```
PYTHONPATH=src python -m unittest discover -s tests
```

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

