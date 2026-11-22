"""NFQUEUE-based packet interceptor for ZerTrus.

Binds to a Linux NetfilterQueue, inspects every forwarded packet,
evaluates it against the rule engine, and either accepts or drops it.
Unknown traffic is dropped and a pending approval request is created.
"""

import logging
from datetime import datetime
from typing import Any

from netfilterqueue import NetfilterQueue  # type: ignore[import-untyped]

from .config import Config
from .database import Database
from .dns_sni import (
    extract_sni,
    get_transport_info,
    parse_dns_query,
    parse_dns_response,
)
from .models import DnsEntry, PendingRequest
from .rule_engine import RuleEngine

logger = logging.getLogger("zertrus.interceptor")


class Interceptor:
    """NetfilterQueue packet handler implementing Zero Trust enforcement."""

    def __init__(
        self, rule_engine: RuleEngine, database: Database, config: Config
    ) -> None:
        """Create an interceptor bound to the queue number in *config*."""
        self._rule_engine = rule_engine
        self._db = database
        self._config = config
        self._nfqueue: NetfilterQueue | None = None
        self._running = False

        # Tracking in-flight DNS queries: query_domain keyed by (src_ip, txn_id)
        self._dns_queries: dict[tuple[str, int], str] = {}

    # ---- public API ----

    def start(self) -> None:
        """Bind to the NFQUEUE and start the blocking packet loop.

        This method **blocks** — run it in a daemon thread.
        """
        queue_num: int = self._config.get("nfqueue_num", 1)
        self._nfqueue = NetfilterQueue()
        self._nfqueue.bind(queue_num, self._packet_callback)
        self._running = True
        logger.info("Interceptor bound to NFQUEUE %d — processing packets", queue_num)

        try:
            self._nfqueue.run()
        except KeyboardInterrupt:
            logger.info("Interceptor interrupted")
        finally:
            self.stop()

    def stop(self) -> None:
        """Unbind the queue and clean up."""
        self._running = False
        if self._nfqueue is not None:
            try:
                self._nfqueue.unbind()
                logger.info("Interceptor unbound from NFQUEUE")
            except Exception:
                logger.debug("Error unbinding NFQUEUE", exc_info=True)
            self._nfqueue = None

    # ---- internal ----

    def _packet_callback(self, packet: Any) -> None:
        """Inspect a single packet and accept or drop it."""
        try:
            ip_payload: bytes = packet.get_payload()
            src_ip, dst_ip, src_port, dst_port, protocol = get_transport_info(
                ip_payload
            )

            if not src_ip:
                packet.accept()
                return

            domain = ""

            # --- DNS handling ---
            if protocol == "udp" and dst_port == 53:
                # Outgoing DNS query — always ACCEPT so resolution works,
                # but cache the queried domain for later lookup.
                self._handle_dns_query(ip_payload, src_ip)
                packet.accept()
                return

            if protocol == "udp" and src_port == 53:
                # Incoming DNS response — always ACCEPT, cache mappings.
                self._handle_dns_response(ip_payload)
                packet.accept()
                return

            # --- SNI extraction ---
            if (
                protocol == "tcp"
                and dst_port == 443
                and self._config.get("sni_extraction", True)
            ):
                domain = self._extract_domain_from_sni(ip_payload) or ""

            # Fall back to DNS cache if we still have no domain
            if not domain:
                cached = self._db.get_domain_for_ip(dst_ip)
                if cached:
                    domain = cached

            # --- Rule check ---
            action = self._rule_engine.check(
                src_ip, dst_ip, dst_port, protocol, domain
            )

            if action == "allow":
                packet.accept()
                return

            if action == "deny":
                packet.drop()
                return

            # No matching rule → default policy: drop + create/update pending
            packet.drop()
            self._create_or_update_pending(
                src_ip, dst_ip, dst_port, protocol, domain
            )

        except Exception:
            logger.error("Error processing packet", exc_info=True)
            try:
                packet.accept()  # fail-open to avoid total network lockout
            except Exception:
                pass

    # ---- DNS helpers ----

    def _handle_dns_query(self, ip_payload: bytes, src_ip: str) -> None:
        """Cache the queried domain from an outgoing DNS query."""
        try:
            ihl = (ip_payload[0] & 0x0F) * 4
            udp_data = ip_payload[ihl:]
            if len(udp_data) < 8:
                return
            dns_payload = udp_data[8:]  # skip UDP header
            domain = parse_dns_query(dns_payload)
            if domain:
                # Store by (src_ip, txn_id) for matching the response later
                import struct

                txn_id = struct.unpack("!H", dns_payload[:2])[0]
                self._dns_queries[(src_ip, txn_id)] = domain
                logger.debug("DNS query from %s: %s", src_ip, domain)
        except Exception:
            logger.debug("Error handling DNS query", exc_info=True)

    def _handle_dns_response(self, ip_payload: bytes) -> None:
        """Cache IP→domain mappings from DNS responses."""
        try:
            ihl = (ip_payload[0] & 0x0F) * 4
            udp_data = ip_payload[ihl:]
            if len(udp_data) < 8:
                return
            dns_payload = udp_data[8:]

            mappings = parse_dns_response(dns_payload)
            for domain, ip in mappings:
                entry = DnsEntry(ip=ip, domain=domain)
                self._db.add_dns_entry(entry)
                logger.debug("DNS cache: %s → %s", ip, domain)
        except Exception:
            logger.debug("Error handling DNS response", exc_info=True)

    def _extract_domain_from_sni(self, ip_payload: bytes) -> str | None:
        """Extract SNI hostname from a TLS ClientHello inside the IP packet."""
        try:
            ihl = (ip_payload[0] & 0x0F) * 4
            tcp_data = ip_payload[ihl:]
            if len(tcp_data) < 20:
                return None
            # TCP data offset
            data_offset = ((tcp_data[12] >> 4) & 0x0F) * 4
            tls_data = tcp_data[data_offset:]
            if not tls_data:
                return None
            return extract_sni(tls_data)
        except Exception:
            return None

    # ---- Pending-request helper ----

    def _create_or_update_pending(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        domain: str,
    ) -> None:
        """Create a new pending request or increment an existing one."""
        try:
            existing = self._db.find_existing_pending(dst_ip, dst_port, protocol)
            if existing and existing.id is not None:
                self._db.increment_pending_count(existing.id)
            else:
                req = PendingRequest(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol,
                    domain=domain,
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                )
                self._db.add_pending(req)
                logger.info(
                    "New pending: %s → %s:%d/%s (%s)",
                    src_ip,
                    dst_ip,
                    dst_port,
                    protocol,
                    domain or "unknown",
                )
        except Exception:
            logger.error("Failed to create/update pending request", exc_info=True)
