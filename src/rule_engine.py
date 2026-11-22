"""Thread-safe in-memory rule engine with database backing.

Maintains an ordered list of :class:`Rule` objects in memory for fast
packet-matching, synchronised with the SQLite database.
"""

import logging
import threading
from typing import Optional

from .database import Database
from .models import Rule

logger = logging.getLogger("zertrus.rule_engine")


class RuleEngine:
    """Evaluate traffic against cached rules, backed by the database."""

    def __init__(self, database: Database) -> None:
        """Load active rules from *database* into memory."""
        self._db = database
        self._lock = threading.RLock()
        self._rules: list[Rule] = []
        self.reload_rules()

    # ---- public API ----

    def reload_rules(self) -> None:
        """Replace the in-memory rule list with current DB state."""
        with self._lock:
            self._rules = self._db.get_rules(active_only=True)
            logger.info("Loaded %d active rules", len(self._rules))

    def check(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        domain: str = "",
    ) -> Optional[str]:
        """Return the first matching rule's action, or ``None``.

        Returns:
            ``"allow"``, ``"deny"``, or ``None`` (no match).
        """
        with self._lock:
            for rule in self._rules:
                if rule.matches(src_ip, dst_ip, dst_port, protocol, domain):
                    # Update hit statistics in background-safe manner
                    if rule.id is not None:
                        try:
                            self._db.update_rule_hit(rule.id)
                        except Exception:
                            logger.debug("Failed to update hit for rule %d", rule.id)
                    return rule.action
        return None

    def add_rule(self, rule: Rule) -> int:
        """Add a rule to the database and in-memory cache. Returns the rule id."""
        with self._lock:
            rule_id = self._db.add_rule(rule)
            rule.id = rule_id
            self._rules.append(rule)
            logger.info("Added rule id=%d → %s", rule_id, rule.action)
            return rule_id

    def remove_rule(self, rule_id: int) -> bool:
        """Remove a rule from the database and in-memory cache."""
        with self._lock:
            deleted = self._db.delete_rule(rule_id)
            if deleted:
                self._rules = [r for r in self._rules if r.id != rule_id]
                logger.info("Removed rule id=%d", rule_id)
            return deleted

    def get_all_rules(self) -> list[Rule]:
        """Return a copy of the current in-memory rule list."""
        with self._lock:
            return list(self._rules)

    def cleanup(self) -> None:
        """Remove expired rules from cache and database."""
        with self._lock:
            expired_ids = [r.id for r in self._rules if r.is_expired()]
            for rid in expired_ids:
                if rid is not None:
                    self._db.delete_rule(rid)
            self._rules = [r for r in self._rules if not r.is_expired()]
            if expired_ids:
                logger.info("Cleaned up %d expired rules", len(expired_ids))
