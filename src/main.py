"""ZerTrus entry point.

Initialises configuration, database, rule engine, and the NFQUEUE
interceptor, then starts the Flask web UI.
"""

import argparse
import logging
import os
import signal
import sys
import threading

from .config import Config
from .database import Database
from .interceptor import Interceptor
from .rule_engine import RuleEngine

logger = logging.getLogger("zertrus")


def _setup_logging(config: Config) -> None:
    """Configure root logger with file and console handlers."""
    log_level = getattr(logging, config.get("log_level", "INFO").upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(log_level)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(log_level)
    console.setFormatter(fmt)
    root.addHandler(console)

    # File handler
    log_path = config.get("log_path", "/var/log/zertrus/zertrus.log")
    try:
        os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(log_level)
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
    except OSError as exc:
        logger.warning("Could not open log file %s: %s", log_path, exc)


def main() -> None:
    """Parse arguments and run ZerTrus."""
    parser = argparse.ArgumentParser(description="ZerTrus — Zero Trust Network Controller")
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to config.json (default: /etc/zertrus/config.json or project-local)",
    )
    args = parser.parse_args()

    # ----- Core initialisation -----
    config = Config(config_path=args.config)
    _setup_logging(config)
    logger.info("ZerTrus starting up")

    db = Database(config.get("db_path", "/var/lib/zertrus/zertrus.db"))
    rule_engine = RuleEngine(db)

    # ----- Interceptor (daemon thread) -----
    interceptor = Interceptor(rule_engine, db, config)
    interceptor_thread = threading.Thread(
        target=interceptor.start, name="interceptor", daemon=True
    )
    interceptor_thread.start()
    logger.info("Interceptor thread started")

    # ----- Signal handling -----
    def _shutdown(signum: int, frame: object) -> None:
        logger.info("Received signal %d — shutting down", signum)
        interceptor.stop()
        db.cleanup_expired()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    # ----- Flask web server -----
    # Import the Flask app from the web package and inject dependencies.
    # web/app.py expects these to be set on app.config (or module globals).
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from web.app import app  # type: ignore[import-untyped]

    app.config["DATABASE"] = db
    app.config["RULE_ENGINE"] = rule_engine
    app.config["ZERTRUS_CONFIG"] = config
    app.secret_key = config.get("web_secret_key", "CHANGE_ME_IN_PRODUCTION")

    host = config.get("web_host", "0.0.0.0")
    port = config.get("web_port", 8443)
    logger.info("Starting web UI on %s:%d", host, port)

    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
