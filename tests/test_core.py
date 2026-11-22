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
from web.app import create_app


class TestZerTrus(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        self.db = Database(self.temp_db.name)
        self.engine = RuleEngine(self.db)
        self.app = create_app(self.db, self.engine)
        self.client = self.app.test_client()

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
        # Add pending
        req = PendingRequest(
            src_ip="192.168.50.50",
            dst_ip="142.250.180.206",
            dst_port=443,
            protocol="tcp",
            domain="google.com"
        )
        req_id = self.db.add_pending(req)
        self.assertIsNotNone(req_id)

        # Check pending in API
        resp = self.client.get('/api/pending')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['domain'], "google.com")

        # Approve pending via API
        approve_resp = self.client.post(f'/api/pending/{req_id}/approve', json={
            "duration": "permanent",
            "description": "Allowed Google"
        })
        self.assertEqual(approve_resp.status_code, 200)

        # Now rule should match
        res = self.engine.check("192.168.50.50", "142.250.180.206", 443, "tcp", "google.com")
        self.assertEqual(res, "allow")

    def test_dns_parser(self):
        # Build synthetic DNS query for example.com
        # Header: ID=0x1234, Flags=0x0100 (standard query), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        # QNAME: 7example3com0
        qname = b"\x07example\x03com\x00"
        qtype_qclass = struct.pack(">HH", 1, 1) # A record, IN class
        dns_query_payload = header + qname + qtype_qclass

        domain = parse_dns_query(dns_query_payload)
        self.assertEqual(domain, "example.com")


if __name__ == '__main__':
    unittest.main()
