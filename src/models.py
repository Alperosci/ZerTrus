"""ZerTrus data models.

Defines the core domain objects used across the application:
Rule, PendingRequest, and DnsEntry.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Rule:
    """A network-access rule evaluated by the rule engine."""

    id: Optional[int] = None
    src_ip: str = "*"
    dst_ip: str = "*"
    dst_port: int = 0
    protocol: str = "*"
    domain: str = ""
    action: str = "allow"
    duration: str = "permanent"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    expires_at: Optional[str] = None
    hit_count: int = 0
    last_hit: Optional[str] = None
    description: str = ""

    def is_expired(self) -> bool:
        """Return True when the rule has passed its expiration time."""
        if self.duration == "permanent" or not self.expires_at:
            return False
        try:
            return datetime.fromisoformat(self.expires_at) < datetime.now()
        except ValueError:
            return False

    def matches(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        domain: str = "",
    ) -> bool:
        """Return True when this rule matches the given traffic parameters."""
        if self.is_expired():
            return False
        if self.src_ip != "*" and self.src_ip != src_ip:
            return False
        if self.dst_ip != "*" and self.dst_ip != dst_ip:
            return False
        if self.dst_port != 0 and self.dst_port != dst_port:
            return False
        if self.protocol != "*" and self.protocol.lower() != protocol.lower():
            return False
        if self.domain and domain:
            if self.domain != domain and not domain.endswith("." + self.domain):
                return False
        return True


@dataclass
class PendingRequest:
    """An observed connection attempt awaiting admin approval."""

    id: Optional[int] = None
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = "tcp"
    domain: str = ""
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    packet_count: int = 1
    status: str = "pending"


@dataclass
class DnsEntry:
    """A cached DNS resolution mapping an IP to a domain."""

    ip: str = ""
    domain: str = ""
    resolved_at: str = field(default_factory=lambda: datetime.now().isoformat())
    ttl: int = 300
