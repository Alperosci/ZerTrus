"""ZerTrus Web Frontend — Flask application for the Zero Trust network controller."""

import sys
import os
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Optional

from flask import (
    Flask, render_template, request, jsonify, Response, flash, redirect, url_for
)

# Allow imports from the project root
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from src.models import Rule, PendingRequest
from src.database import Database
from src.rule_engine import RuleEngine

logger = logging.getLogger("zertrus.web")

app = Flask(__name__)
app.secret_key = "CHANGE_ME_IN_PRODUCTION"

# These globals are set by main.py via create_app()
database: Optional[Database] = None
rule_engine: Optional[RuleEngine] = None


def create_app(db: Database, re: RuleEngine) -> Flask:
    """Initialize the Flask app with shared database and rule engine instances."""
    global database, rule_engine
    database = db
    rule_engine = re
    return app


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

@app.route('/')
def dashboard() -> str:
    """Render the dashboard page with overview statistics."""
    rules = rule_engine.get_all_rules() if rule_engine else []
    pending = database.get_pending(status="pending") if database else []

    total_rules = len(rules)
    pending_count = len(pending)
    total_allowed = sum(1 for r in rules if r.action == "allow")
    total_denied = sum(1 for r in rules if r.action == "deny")

    recent_pending = sorted(pending, key=lambda p: p.last_seen, reverse=True)[:10]

    return render_template(
        'dashboard.html',
        total_rules=total_rules,
        pending_count=pending_count,
        total_allowed=total_allowed,
        total_denied=total_denied,
        recent_pending=recent_pending,
    )


@app.route('/pending')
def pending_page() -> str:
    """Render the pending requests management page."""
    pending = database.get_pending(status="pending") if database else []
    return render_template('pending.html', pending=pending)


@app.route('/rules')
def rules_page() -> str:
    """Render the rules management page."""
    rules = rule_engine.get_all_rules() if rule_engine else []
    return render_template('rules.html', rules=rules)


# ---------------------------------------------------------------------------
# API routes — Pending Requests
# ---------------------------------------------------------------------------

@app.route('/api/pending/<int:req_id>/approve', methods=['POST'])
def approve_pending(req_id: int):
    """Approve a pending request and create an allow rule."""
    if not database or not rule_engine:
        return jsonify({"success": False, "error": "Not initialized"}), 500

    pending = database.get_pending_by_id(req_id)
    if not pending:
        return jsonify({"success": False, "error": "Request not found"}), 404

    data = request.get_json(force=True) if request.data else {}
    duration = data.get("duration", "permanent")
    duration_minutes = data.get("duration_minutes", 60)
    description = data.get("description", "")

    expires_at = None
    if duration == "timed":
        expires_at = (datetime.now() + timedelta(minutes=int(duration_minutes))).isoformat()

    rule = Rule(
        src_ip=pending.src_ip,
        dst_ip=pending.dst_ip,
        dst_port=pending.dst_port,
        protocol=pending.protocol,
        domain=pending.domain,
        action="allow",
        duration=duration,
        expires_at=expires_at,
        description=description or f"Approved pending #{req_id}",
    )

    rule_id = rule_engine.add_rule(rule)
    database.update_pending_status(req_id, "approved")
    logger.info("Approved pending request %d → rule %d", req_id, rule_id)

    return jsonify({"success": True, "rule_id": rule_id})


@app.route('/api/pending/<int:req_id>/deny', methods=['POST'])
def deny_pending(req_id: int):
    """Deny a pending request and create a deny rule."""
    if not database or not rule_engine:
        return jsonify({"success": False, "error": "Not initialized"}), 500

    pending = database.get_pending_by_id(req_id)
    if not pending:
        return jsonify({"success": False, "error": "Request not found"}), 404

    rule = Rule(
        src_ip=pending.src_ip,
        dst_ip=pending.dst_ip,
        dst_port=pending.dst_port,
        protocol=pending.protocol,
        domain=pending.domain,
        action="deny",
        duration="permanent",
        description=f"Denied pending #{req_id}",
    )

    rule_engine.add_rule(rule)
    database.update_pending_status(req_id, "denied")
    logger.info("Denied pending request %d", req_id)

    return jsonify({"success": True})


@app.route('/api/pending/<int:req_id>', methods=['DELETE'])
def dismiss_pending(req_id: int):
    """Dismiss (expire) a pending request without creating a rule."""
    if not database:
        return jsonify({"success": False, "error": "Not initialized"}), 500

    pending = database.get_pending_by_id(req_id)
    if not pending:
        return jsonify({"success": False, "error": "Request not found"}), 404

    database.update_pending_status(req_id, "expired")
    logger.info("Dismissed pending request %d", req_id)

    return jsonify({"success": True})


@app.route('/api/pending')
def api_pending():
    """Return JSON list of pending requests."""
    pending = database.get_pending(status="pending") if database else []
    return jsonify([vars(p) for p in pending])


# ---------------------------------------------------------------------------
# API routes — Rules
# ---------------------------------------------------------------------------

@app.route('/api/rules')
def api_rules():
    """Return JSON list of all active rules."""
    rules = rule_engine.get_all_rules() if rule_engine else []
    return jsonify([vars(r) for r in rules])


@app.route('/api/rules/<int:rule_id>', methods=['DELETE'])
def delete_rule(rule_id: int):
    """Delete a rule by ID."""
    if not rule_engine:
        return jsonify({"success": False, "error": "Not initialized"}), 500

    success = rule_engine.remove_rule(rule_id)
    if not success:
        return jsonify({"success": False, "error": "Rule not found"}), 404

    logger.info("Deleted rule %d", rule_id)
    return jsonify({"success": True})


@app.route('/api/rules', methods=['POST'])
def add_rule():
    """Manually add a new rule from JSON body."""
    if not rule_engine:
        return jsonify({"success": False, "error": "Not initialized"}), 500

    data = request.get_json(force=True)

    rule = Rule(
        src_ip=data.get("src_ip", "*"),
        dst_ip=data.get("dst_ip", "*"),
        dst_port=int(data.get("dst_port", 0)),
        protocol=data.get("protocol", "*"),
        domain=data.get("domain", ""),
        action=data.get("action", "allow"),
        duration=data.get("duration", "permanent"),
        description=data.get("description", "Manually added rule"),
    )

    if rule.duration == "timed":
        minutes = int(data.get("duration_minutes", 60))
        rule.expires_at = (datetime.now() + timedelta(minutes=minutes)).isoformat()

    rule_id = rule_engine.add_rule(rule)
    logger.info("Manually added rule %d", rule_id)

    return jsonify({"success": True, "rule_id": rule_id})


# ---------------------------------------------------------------------------
# API routes — Stats & Events
# ---------------------------------------------------------------------------

@app.route('/api/stats')
def api_stats():
    """Return dashboard statistics."""
    rules = rule_engine.get_all_rules() if rule_engine else []
    pending = database.get_pending(status="pending") if database else []

    return jsonify({
        "total_rules": len(rules),
        "pending_count": len(pending),
        "total_allowed": sum(1 for r in rules if r.action == "allow"),
        "total_denied": sum(1 for r in rules if r.action == "deny"),
    })


@app.route('/api/events')
def events():
    """Server-Sent Events stream — push updates when pending requests change."""
    def generate():
        last_count = 0
        while True:
            try:
                pending = database.get_pending(status="pending") if database else []
                if len(pending) != last_count:
                    last_count = len(pending)
                    data = json.dumps([vars(p) for p in pending])
                    yield f"data: {data}\n\n"
            except Exception as exc:
                logger.error("SSE error: %s", exc)
            time.sleep(2)

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})
