import logging
import os
import sys
from functools import wraps

import bcrypt
import yaml
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

from audit import AuditLog
from proxy import ProxyManager


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def create_app(config: dict) -> Flask:
    app = Flask(__name__)
    app.secret_key = config["secret_key"]
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SECURE"] = config.get("session_cookie_secure", False)

    if config.get("trust_proxy", False):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    users = config.get("users", {})
    audit = AuditLog(config.get("audit_log_path"))
    rotation = config.get("audit_rotation", "weekly")  # "weekly" | "daily" | "off"
    if rotation in ("weekly", "daily"):
        audit.start_rotation(weekly=(rotation == "weekly"))
    proxy = ProxyManager(config.get("services", []), audit=audit)
    proxy.start()
    app.config["proxy"] = proxy
    app.config["audit"] = audit

    def login_required(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if not session.get("user"):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "unauthorized"}), 401
                return redirect(url_for("login", next=request.path))
            return f(*a, **kw)
        return wrapper

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            u = request.form.get("username", "")
            p = request.form.get("password", "")
            user = users.get(u)
            if user and bcrypt.checkpw(p.encode(), user["password_hash"].encode()):
                session["user"] = u
                audit.record("login", user=u, ip=request.remote_addr)
                return redirect(request.args.get("next") or url_for("dashboard"))
            audit.record("login_failed", user=u or None, ip=request.remote_addr)
            error = "Invalid username or password"
        return render_template("login.html", error=error)

    @app.route("/logout", methods=["POST"])
    def logout():
        user = session.pop("user", None)
        if user:
            audit.record("logout", user=user, ip=request.remote_addr)
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def dashboard():
        return render_template(
            "dashboard.html",
            user=session["user"],
            ip=request.remote_addr,
            services=list(proxy.services.values()),
        )

    @app.route("/api/status")
    @login_required
    def api_status():
        ip = request.remote_addr
        return jsonify({"ip": ip, "grants": proxy.status_for_ip(ip)})

    @app.route("/api/activate/<name>", methods=["POST"])
    @login_required
    def api_activate(name: str):
        if name not in proxy.services:
            return jsonify({"error": "unknown service"}), 404
        ip = request.remote_addr
        exp = proxy.activate(name, ip, user=session["user"])
        audit.record("activate", user=session["user"], ip=ip, service=name, expires_at=exp)
        return jsonify({"service": name, "expires_at": exp})

    @app.route("/api/extend/<name>", methods=["POST"])
    @login_required
    def api_extend(name: str):
        if name not in proxy.services:
            return jsonify({"error": "unknown service"}), 404
        ip = request.remote_addr
        exp = proxy.extend(name, ip, user=session["user"])
        audit.record("extend", user=session["user"], ip=ip, service=name, expires_at=exp)
        return jsonify({"service": name, "expires_at": exp})

    @app.route("/api/deactivate/<name>", methods=["POST"])
    @login_required
    def api_deactivate(name: str):
        if name not in proxy.services:
            return jsonify({"error": "unknown service"}), 404
        ip = request.remote_addr
        proxy.deactivate(name, ip)
        audit.record("deactivate", user=session["user"], ip=ip, service=name)
        return jsonify({"service": name})

    @app.route("/api/audit")
    @login_required
    def api_audit():
        try:
            offset = max(0, int(request.args.get("offset", 0)))
            limit = min(max(1, int(request.args.get("limit", 50))), 500)
        except ValueError:
            return jsonify({"error": "bad offset/limit"}), 400
        return jsonify(audit.query(
            offset=offset,
            limit=limit,
            category=request.args.get("category") or None,
            user=request.args.get("user") or None,
            service=request.args.get("service") or None,
            ip=request.args.get("ip") or None,
        ))

    return app


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config_path = os.environ.get("CONFIG", "config.yaml")
    if not os.path.exists(config_path):
        print(f"Config not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    config = load_config(config_path)
    app = create_app(config)
    web = config.get("web", {})
    app.run(
        host=web.get("host", "0.0.0.0"),
        port=web.get("port", 8080),
        use_reloader=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
