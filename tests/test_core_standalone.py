import unittest
import os
import tempfile
import struct
import socket
from datetime import datetime, timedelta

from src.models import Rule, PendingRequest, DnsEntry
from src.database import Database
from src.rule_engine import RuleEngine
from src.dns_sni import (
    parse_dns_query,
    parse_dns_response,
    extract_sni,
    get_transport_info
)

class TestZerTrusCore(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        self.db = Database(self.temp_db.name)
        self.engine = RuleEngine(self.db)

    def tearDown(self):
        try:
            os.remove(self.temp_db.name)
        except OSError:
            pass

    def test_database_and_rule_engine(self):
        # 1. Add rule
        rule = Rule(
            src_ip="192.168.50.100",
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="udp",
            action="allow",
            duration="permanent"
        )
        rule_id = self.engine.add_rule(rule)
        self.assertIsNotNone(rule_id)

        # 2. Check rule match
        res = self.engine.check("192.168.50.100", "8.8.8.8", 53, "udp")
        self.assertEqual(res, "allow")

        # 3. Check non-match
        res_none = self.engine.check("192.168.50.101", "8.8.8.8", 53, "udp")
        self.assertIsNone(res_none)

        # 4. Timed expired rule
        expired_rule = Rule(
            src_ip="*",
            dst_ip="1.1.1.1",
            dst_port=443,
            protocol="tcp",
            action="deny",
            duration="timed",
            expires_at=(datetime.now() - timedelta(minutes=1)).isoformat()
        )
        self.engine.add_rule(expired_rule)
        self.assertIsNone(self.engine.check("192.168.50.5", "1.1.1.1", 443, "tcp"))

    def test_pending_request_flow(self):
        req = PendingRequest(
            src_ip="192.168.50.50",
            dst_ip="142.250.180.206",
            dst_port=443,
            protocol="tcp",
            domain="google.com"
        )
        req_id = self.db.add_pending(req)
        self.assertIsNotNone(req_id)

        pending_list = self.db.get_pending(status="pending")
        self.assertEqual(len(pending_list), 1)
        self.assertEqual(pending_list[0].domain, "google.com")

        # Convert to rule
        new_rule = Rule(
            src_ip=pending_list[0].src_ip,
            dst_ip=pending_list[0].dst_ip,
            dst_port=pending_list[0].dst_port,
            protocol=pending_list[0].protocol,
            domain=pending_list[0].domain,
            action="allow",
            duration="permanent"
        )
        self.engine.add_rule(new_rule)
        self.db.update_pending_status(req_id, "approved")

        # Check rule match
        res = self.engine.check("192.168.50.50", "142.250.180.206", 443, "tcp", "google.com")
        self.assertEqual(res, "allow")

    def test_dns_parser(self):
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        qname = b"\x07example\x03com\x00"
        qtype_qclass = struct.pack(">HH", 1, 1)
        dns_query_payload = header + qname + qtype_qclass

        domain = parse_dns_query(dns_query_payload)
        self.assertEqual(domain, "example.com")

    def test_dns_response_parser(self):
        # DNS Response for example.com -> 93.184.216.34
        # Header: ID=0x1234, Flags=0x8180 (QR=1, RD=1, RA=1), QD=1, AN=1, NS=0, AR=0
        header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        qname = b"\x07example\x03com\x00"
        qtype_qclass = struct.pack(">HH", 1, 1)
        # Answer: Name pointer to 0x000c (offset 12), Type=1 (A), Class=1 (IN), TTL=300, RDLENGTH=4, RDATA=93.184.216.34
        ans_name = b"\xc0\x0c"
        ans_meta = struct.pack(">HHIH", 1, 1, 300, 4)
        ans_ip = socket.inet_aton("93.184.216.34")
        payload = header + qname + qtype_qclass + ans_name + ans_meta + ans_ip

        mappings = parse_dns_response(payload)
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0][0], "example.com")
        self.assertEqual(mappings[0][1], "93.184.216.34")

    def test_tls_sni_extraction(self):
        # Synthetic TLS ClientHello with SNI "test.com"
        # SNI extension:
        # server_name list: length 10 -> [name_type=0, name_len=8, "test.com"]
        server_name = b"test.com"
        sni_entry = b"\x00" + struct.pack(">H", len(server_name)) + server_name
        sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
        ext_sni = struct.pack(">HH", 0, len(sni_list)) + sni_list
        exts_data = struct.pack(">H", len(ext_sni)) + ext_sni

        # Handshake ClientHello payload
        # version 0x0303 (TLS 1.2), random 32 bytes, session_id len 0, cipher_suites len 2 (0x002f), compression len 1 (0)
        ch_body = (
            b"\x03\x03" +
            b"\x00" * 32 +
            b"\x00" + # session id len
            b"\x00\x02\x00\x2f" + # cipher suites
            b"\x01\x00" + # compression
            exts_data
        )
        # Handshake header: type=1 (ClientHello), len (3 bytes)
        ch_len = len(ch_body)
        ch_hdr = b"\x01" + bytes([(ch_len >> 16) & 0xFF, (ch_len >> 8) & 0xFF, ch_len & 0xFF])
        handshake_payload = ch_hdr + ch_body

        # TLS Record Header: 0x16 (Handshake), 0x0301 (TLS 1.0), len (2 bytes)
        record_len = len(handshake_payload)
        tls_record = struct.pack(">BHH", 0x16, 0x0301, record_len) + handshake_payload

        sni = extract_sni(tls_record)
        self.assertEqual(sni, "test.com")

if __name__ == '__main__':
    unittest.main()
