"""Pure-Python DNS and TLS SNI parser for ZerTrus.

Parses raw IP packets without any external dependencies (no scapy, no dpkt).
Uses ``struct`` and ``socket`` for byte-level parsing.
"""

import logging
import socket
import struct
from typing import Optional

logger = logging.getLogger("zertrus.dns_sni")


def get_transport_info(ip_payload: bytes) -> tuple[str, str, int, int, str]:
    """Parse an IP packet and return transport-layer details.

    Returns:
        (src_ip, dst_ip, src_port, dst_port, protocol_name)

    Raises nothing — returns ``("", "", 0, 0, "unknown")`` on failure.
    """
    try:
        if len(ip_payload) < 20:
            return ("", "", 0, 0, "unknown")

        # IP header
        version_ihl = ip_payload[0]
        ihl = (version_ihl & 0x0F) * 4
        protocol_num = ip_payload[9]
        src_ip = socket.inet_ntoa(ip_payload[12:16])
        dst_ip = socket.inet_ntoa(ip_payload[16:20])

        transport = ip_payload[ihl:]
        src_port = 0
        dst_port = 0

        if protocol_num == 6:  # TCP
            protocol_name = "tcp"
            if len(transport) >= 4:
                src_port, dst_port = struct.unpack("!HH", transport[:4])
        elif protocol_num == 17:  # UDP
            protocol_name = "udp"
            if len(transport) >= 4:
                src_port, dst_port = struct.unpack("!HH", transport[:4])
        elif protocol_num == 1:
            protocol_name = "icmp"
        else:
            protocol_name = str(protocol_num)

        return (src_ip, dst_ip, src_port, dst_port, protocol_name)
    except Exception:
        logger.debug("Failed to parse IP header", exc_info=True)
        return ("", "", 0, 0, "unknown")


def _read_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a DNS-encoded domain name from *data* starting at *offset*.

    Handles label compression (pointer bytes 0xC0+).  Returns the domain
    string and the new offset after the name field.
    """
    labels: list[str] = []
    original_offset: Optional[int] = None
    jumps = 0

    while offset < len(data):
        length = data[offset]

        if length == 0:
            # End of name
            if original_offset is None:
                offset += 1
            break

        if (length & 0xC0) == 0xC0:
            # Pointer — two bytes encode a 14-bit offset
            if offset + 1 >= len(data):
                break
            if original_offset is None:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
            offset = pointer
            jumps += 1
            if jumps > 20:
                break  # safety
            continue

        # Normal label
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length

    name = ".".join(labels)
    return (name, original_offset if original_offset is not None else offset)


def parse_dns_query(payload: bytes) -> Optional[str]:
    """Extract the queried domain name from a raw DNS UDP payload.

    *payload* is the UDP data section (i.e. starting at the DNS header,
    **not** at the IP header).

    Returns the queried domain or ``None`` on failure.
    """
    try:
        if len(payload) < 12:
            return None

        # DNS header is 12 bytes: ID(2), Flags(2), QDCOUNT(2), ...
        flags = struct.unpack("!H", payload[2:4])[0]
        qr = (flags >> 15) & 1
        if qr != 0:
            # This is a response, not a query
            return None

        qdcount = struct.unpack("!H", payload[4:6])[0]
        if qdcount < 1:
            return None

        # Parse first question
        name, _ = _read_dns_name(payload, 12)
        return name if name else None
    except Exception:
        logger.debug("Failed to parse DNS query", exc_info=True)
        return None


def parse_dns_response(payload: bytes) -> list[tuple[str, str]]:
    """Extract (domain, resolved_ip) pairs from DNS response A records.

    *payload* is the raw UDP data (DNS header + body).

    Returns a list of ``(domain, ip)`` tuples.
    """
    results: list[tuple[str, str]] = []
    try:
        if len(payload) < 12:
            return results

        flags = struct.unpack("!H", payload[2:4])[0]
        qr = (flags >> 15) & 1
        if qr != 1:
            return results  # not a response

        qdcount = struct.unpack("!H", payload[4:6])[0]
        ancount = struct.unpack("!H", payload[6:8])[0]

        # Skip questions section
        offset = 12
        for _ in range(qdcount):
            _, offset = _read_dns_name(payload, offset)
            offset += 4  # QTYPE(2) + QCLASS(2)

        # Parse answer section
        for _ in range(ancount):
            if offset >= len(payload):
                break
            name, offset = _read_dns_name(payload, offset)
            if offset + 10 > len(payload):
                break

            rtype, rclass, rttl, rdlength = struct.unpack(
                "!HHIH", payload[offset : offset + 10]
            )
            offset += 10

            if offset + rdlength > len(payload):
                break

            if rtype == 1 and rdlength == 4:
                # A record
                ip = socket.inet_ntoa(payload[offset : offset + 4])
                results.append((name, ip))

            offset += rdlength

    except Exception:
        logger.debug("Failed to parse DNS response", exc_info=True)

    return results


def extract_sni(payload: bytes) -> Optional[str]:
    """Extract the SNI hostname from a TLS ClientHello.

    *payload* is the raw TCP data (starting at the TLS record header).

    Returns the hostname or ``None`` if the packet is not a ClientHello or
    has no SNI extension.
    """
    try:
        if len(payload) < 6:
            return None

        # TLS record header
        content_type = payload[0]
        if content_type != 0x16:  # Handshake
            return None

        # TLS version (2 bytes) + record length (2 bytes)
        record_length = struct.unpack("!H", payload[3:5])[0]
        if len(payload) < 5 + record_length:
            return None

        # Handshake header
        handshake_type = payload[5]
        if handshake_type != 0x01:  # ClientHello
            return None

        # Handshake length (3 bytes)
        handshake_length = struct.unpack("!I", b"\x00" + payload[6:9])[0]
        if len(payload) < 9 + handshake_length:
            return None

        offset = 9  # past TLS record header + handshake header

        # ClientHello: client_version (2) + random (32) = 34 bytes
        offset += 34

        # Session ID
        if offset >= len(payload):
            return None
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        # Cipher suites
        if offset + 2 > len(payload):
            return None
        cipher_suites_len = struct.unpack("!H", payload[offset : offset + 2])[0]
        offset += 2 + cipher_suites_len

        # Compression methods
        if offset >= len(payload):
            return None
        compression_len = payload[offset]
        offset += 1 + compression_len

        # Extensions total length
        if offset + 2 > len(payload):
            return None
        extensions_len = struct.unpack("!H", payload[offset : offset + 2])[0]
        offset += 2
        extensions_end = offset + extensions_len

        # Walk extensions
        while offset + 4 <= extensions_end and offset + 4 <= len(payload):
            ext_type = struct.unpack("!H", payload[offset : offset + 2])[0]
            ext_len = struct.unpack("!H", payload[offset + 2 : offset + 4])[0]
            offset += 4

            if ext_type == 0x0000:  # SNI
                # SNI extension data: server_name_list_length(2) + entries
                if offset + 2 > len(payload):
                    return None
                # sni_list_length = struct.unpack("!H", payload[offset:offset+2])[0]
                sni_offset = offset + 2

                if sni_offset >= len(payload):
                    return None
                name_type = payload[sni_offset]
                sni_offset += 1

                if name_type != 0:  # host_name
                    return None

                if sni_offset + 2 > len(payload):
                    return None
                name_len = struct.unpack("!H", payload[sni_offset : sni_offset + 2])[0]
                sni_offset += 2

                if sni_offset + name_len > len(payload):
                    return None
                hostname = payload[sni_offset : sni_offset + name_len].decode(
                    "ascii", errors="replace"
                )
                return hostname

            offset += ext_len

        return None
    except Exception:
        logger.debug("Failed to extract SNI", exc_info=True)
        return None
