"""Thread-safe SQLite database layer for ZerTrus.

Uses WAL journal mode for concurrent reads and a threading.Lock for all
write operations.  Returns model objects, never raw tuples.
"""

import logging
import os
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Optional

from .models import DnsEntry, PendingRequest, Rule

logger = logging.getLogger("zertrus.database")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL DEFAULT '*',
    dst_ip TEXT NOT NULL DEFAULT '*',
    dst_port INTEGER NOT NULL DEFAULT 0,
    protocol TEXT NOT NULL DEFAULT '*',
    domain TEXT DEFAULT '',
    action TEXT NOT NULL CHECK(action IN ('allow', 'deny')),
    duration TEXT NOT NULL DEFAULT 'permanent',
    created_at TEXT NOT NULL,
    expires_at TEXT,
    hit_count INTEGER DEFAULT 0,
    last_hit TEXT,
    description TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS pending_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL DEFAULT 0,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    domain TEXT DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    packet_count INTEGER DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'denied', 'expired'))
);

CREATE TABLE IF NOT EXISTS dns_cache (
    ip TEXT NOT NULL,
    domain TEXT NOT NULL,
    resolved_at TEXT NOT NULL,
    ttl INTEGER DEFAULT 300,
    PRIMARY KEY (ip, domain)
);

CREATE INDEX IF NOT EXISTS idx_rules_lookup ON rules(dst_ip, dst_port, protocol);
CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_requests(status);
CREATE INDEX IF NOT EXISTS idx_dns_ip ON dns_cache(ip);
"""


class Database:
    """Thread-safe SQLite persistence layer for ZerTrus."""

    def __init__(self, db_path: str) -> None:
        """Open (or create) the database at *db_path* and ensure schema exists."""
        self._db_path = db_path
        self._write_lock = threading.Lock()

        # Ensure parent directory exists
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)

        # Create tables
        conn = self._connect()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
            logger.info("Database initialised at %s", db_path)
        finally:
            conn.close()

    # ---- internal helpers ----

    def _connect(self) -> sqlite3.Connection:
        """Return a new connection with WAL journal mode."""
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_rule(row: sqlite3.Row) -> Rule:
        return Rule(
            id=row["id"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            dst_port=row["dst_port"],
            protocol=row["protocol"],
            domain=row["domain"] or "",
            action=row["action"],
            duration=row["duration"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            hit_count=row["hit_count"] or 0,
            last_hit=row["last_hit"],
            description=row["description"] or "",
        )

    @staticmethod
    def _row_to_pending(row: sqlite3.Row) -> PendingRequest:
        return PendingRequest(
            id=row["id"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            dst_port=row["dst_port"],
            protocol=row["protocol"],
            domain=row["domain"] or "",
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            packet_count=row["packet_count"] or 1,
            status=row["status"],
        )

    # ---- Rule operations ----

    def add_rule(self, rule: Rule) -> int:
        """Insert a rule and return its new id."""
        with self._write_lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    """INSERT INTO rules
                       (src_ip, dst_ip, dst_port, protocol, domain, action,
                        duration, created_at, expires_at, hit_count, last_hit, description)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        rule.src_ip,
                        rule.dst_ip,
                        rule.dst_port,
                        rule.protocol,
                        rule.domain,
                        rule.action,
                        rule.duration,
                        rule.created_at,
                        rule.expires_at,
                        rule.hit_count,
                        rule.last_hit,
                        rule.description,
                    ),
                )
                conn.commit()
                rule_id: int = cur.lastrowid  # type: ignore[assignment]
                logger.debug("Added rule id=%d", rule_id)
                return rule_id
            finally:
                conn.close()

    def get_rules(self, active_only: bool = True) -> list[Rule]:
        """Return all rules, optionally filtering out expired ones."""
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM rules ORDER BY id").fetchall()
            rules = [self._row_to_rule(r) for r in rows]
            if active_only:
                rules = [r for r in rules if not r.is_expired()]
            return rules
        finally:
            conn.close()

    def get_rule(self, rule_id: int) -> Optional[Rule]:
        """Return a single rule by id, or None."""
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
            return self._row_to_rule(row) if row else None
        finally:
            conn.close()

    def delete_rule(self, rule_id: int) -> bool:
        """Delete a rule by id.  Returns True if a row was removed."""
        with self._write_lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
                conn.commit()
                deleted = cur.rowcount > 0
                if deleted:
                    logger.debug("Deleted rule id=%d", rule_id)
                return deleted
            finally:
                conn.close()

    def update_rule_hit(self, rule_id: int) -> None:
        """Increment the hit_count and update last_hit for a rule."""
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    """UPDATE rules SET hit_count = hit_count + 1,
                       last_hit = ? WHERE id = ?""",
                    (datetime.now().isoformat(), rule_id),
                )
                conn.commit()
            finally:
                conn.close()

    # ---- Pending-request operations ----

    def add_pending(self, req: PendingRequest) -> int:
        """Insert a pending request and return its new id."""
        with self._write_lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    """INSERT INTO pending_requests
                       (src_ip, dst_ip, dst_port, protocol, domain,
                        first_seen, last_seen, packet_count, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        req.src_ip,
                        req.dst_ip,
                        req.dst_port,
                        req.protocol,
                        req.domain,
                        req.first_seen,
                        req.last_seen,
                        req.packet_count,
                        req.status,
                    ),
                )
                conn.commit()
                req_id: int = cur.lastrowid  # type: ignore[assignment]
                logger.debug("Added pending request id=%d", req_id)
                return req_id
            finally:
                conn.close()

    def get_pending(self, status: str = "pending") -> list[PendingRequest]:
        """Return pending requests filtered by status."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM pending_requests WHERE status = ? ORDER BY last_seen DESC",
                (status,),
            ).fetchall()
            return [self._row_to_pending(r) for r in rows]
        finally:
            conn.close()

    def get_pending_by_id(self, req_id: int) -> Optional[PendingRequest]:
        """Return a single pending request by id, or None."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM pending_requests WHERE id = ?", (req_id,)
            ).fetchone()
            return self._row_to_pending(row) if row else None
        finally:
            conn.close()

    def update_pending_status(self, req_id: int, status: str) -> None:
        """Set the status of a pending request."""
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE pending_requests SET status = ? WHERE id = ?",
                    (status, req_id),
                )
                conn.commit()
                logger.debug("Pending id=%d status → %s", req_id, status)
            finally:
                conn.close()

    def increment_pending_count(self, req_id: int) -> None:
        """Increment packet_count and update last_seen for a pending request."""
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    """UPDATE pending_requests
                       SET packet_count = packet_count + 1, last_seen = ?
                       WHERE id = ?""",
                    (datetime.now().isoformat(), req_id),
                )
                conn.commit()
            finally:
                conn.close()

    def find_existing_pending(
        self, dst_ip: str, dst_port: int, protocol: str
    ) -> Optional[PendingRequest]:
        """Find an existing pending request matching the given criteria."""
        conn = self._connect()
        try:
            row = conn.execute(
                """SELECT * FROM pending_requests
                   WHERE dst_ip = ? AND dst_port = ? AND protocol = ?
                     AND status = 'pending'
                   LIMIT 1""",
                (dst_ip, dst_port, protocol),
            ).fetchone()
            return self._row_to_pending(row) if row else None
        finally:
            conn.close()

    # ---- DNS cache operations ----

    def add_dns_entry(self, entry: DnsEntry) -> None:
        """Insert or update a DNS cache entry."""
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO dns_cache (ip, domain, resolved_at, ttl)
                       VALUES (?, ?, ?, ?)""",
                    (entry.ip, entry.domain, entry.resolved_at, entry.ttl),
                )
                conn.commit()
            finally:
                conn.close()

    def get_domain_for_ip(self, ip: str) -> Optional[str]:
        """Return the most recently resolved domain for *ip*, or None."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT domain FROM dns_cache WHERE ip = ? ORDER BY resolved_at DESC LIMIT 1",
                (ip,),
            ).fetchone()
            return row["domain"] if row else None
        finally:
            conn.close()

    # ---- Maintenance ----

    def cleanup_expired(self) -> None:
        """Remove expired rules and stale pending requests."""
        with self._write_lock:
            conn = self._connect()
            try:
                # Delete expired rules
                now = datetime.now().isoformat()
                conn.execute(
                    """DELETE FROM rules
                       WHERE duration != 'permanent'
                         AND expires_at IS NOT NULL
                         AND expires_at < ?""",
                    (now,),
                )

                # Expire old pending requests
                cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
                conn.execute(
                    """UPDATE pending_requests SET status = 'expired'
                       WHERE status = 'pending' AND last_seen < ?""",
                    (cutoff,),
                )

                # Remove very old resolved/expired pendings
                old_cutoff = (datetime.now() - timedelta(days=7)).isoformat()
                conn.execute(
                    """DELETE FROM pending_requests
                       WHERE status IN ('expired', 'approved', 'denied')
                         AND last_seen < ?""",
                    (old_cutoff,),
                )

                # Prune stale DNS cache entries
                conn.execute(
                    """DELETE FROM dns_cache
                       WHERE datetime(resolved_at, '+' || ttl || ' seconds') < ?""",
                    (now,),
                )

                conn.commit()
                logger.debug("Cleanup completed")
            finally:
                conn.close()
