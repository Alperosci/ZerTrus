"""ZerTrus configuration loader.

Loads settings from a JSON file, falls back to defaults, and provides
get / set / save helpers.
"""

import json
import logging
import os
from typing import Any, Optional

logger = logging.getLogger("zertrus.config")

DEFAULT_CONFIG = {
    "nfqueue_num": 1,
    "web_host": "0.0.0.0",
    "web_port": 8443,
    "web_secret_key": "CHANGE_ME_IN_PRODUCTION",
    "db_path": "/var/lib/zertrus/zertrus.db",
    "log_path": "/var/log/zertrus/zertrus.log",
    "log_level": "INFO",
    "default_action": "drop",
    "dns_intercept": True,
    "sni_extraction": True,
    "request_timeout_seconds": 300,
    "lan_interface": "eth0",
    "wan_interface": "wlan0",
    "lan_subnet": "192.168.50.0/24",
    "pi_lan_ip": "192.168.50.1",
    "auto_allow_established": True,
    "auto_allow_dhcp": True,
    "auto_allow_dns_to_pi": True,
    "web_username": "admin",
    "web_password": "zertrus",
}


class Config:
    """Application configuration backed by a JSON file."""

    def __init__(self, config_path: Optional[str] = None) -> None:
        """Load configuration from *config_path*.

        Falls back to ``/etc/zertrus/config.json``, then a project-local
        ``config.json``, then built-in defaults.
        """
        self._data: dict[str, Any] = dict(DEFAULT_CONFIG)
        self._path: Optional[str] = None

        # Determine which file to load
        candidates = []
        if config_path:
            candidates.append(config_path)
        candidates.append("/etc/zertrus/config.json")
        candidates.append(
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
        )

        for candidate in candidates:
            if os.path.isfile(candidate):
                self._path = candidate
                try:
                    with open(candidate, "r", encoding="utf-8") as fh:
                        loaded = json.load(fh)
                    self._data.update(loaded)
                    logger.info("Loaded configuration from %s", candidate)
                except (json.JSONDecodeError, OSError) as exc:
                    logger.warning("Failed to load %s: %s", candidate, exc)
                break
        else:
            logger.info("No config file found; using defaults")

    # ----- public helpers -----

    def get(self, key: str, default: Any = None) -> Any:
        """Return the value for *key*, or *default* if absent."""
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value in memory."""
        self._data[key] = value

    def save(self) -> None:
        """Persist the current configuration to disk.

        Writes to the path the config was loaded from, or to the
        project-local ``config.json`` as a fallback.
        """
        path = self._path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "config.json"
        )
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=2)
        logger.info("Configuration saved to %s", path)

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def __repr__(self) -> str:
        return f"Config(path={self._path!r})"
