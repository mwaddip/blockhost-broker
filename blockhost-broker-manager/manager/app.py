"""Main Flask application for Blockhost Broker Manager."""

import os
import secrets
from functools import wraps
from pathlib import Path

from datetime import timedelta

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .auth import AuthManager
from .broker import BrokerManager

app = Flask(__name__, template_folder="templates", static_folder="../static")

# Configuration - loaded from environment or config file
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Session configuration - match AuthManager.SESSION_EXPIRY
SESSION_LIFETIME_HOURS = int(os.environ.get("SESSION_LIFETIME_HOURS", "24"))
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=SESSION_LIFETIME_HOURS)
app.config["SESSION_COOKIE_SECURE"] = True  # HTTPS only
app.config["SESSION_COOKIE_HTTPONLY"] = True  # No JS access
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # CSRF protection

# Paths
CONFIG_DIR = Path(os.environ.get("CONFIG_DIR", "/etc/blockhost-broker-manager"))
BROKER_CONFIG_DIR = Path(os.environ.get("BROKER_CONFIG_DIR", "/etc/blockhost-broker"))
BROKER_DATA_DIR = Path(os.environ.get("BROKER_DATA_DIR", "/var/lib/blockhost-broker"))

# Initialize managers (done lazily)
_auth_manager: AuthManager | None = None
_broker_manager: BrokerManager | None = None


def get_auth_manager() -> AuthManager:
    """Get or create the auth manager."""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager(
            config_path=CONFIG_DIR / "auth.json",
            secret_key=app.secret_key,
            session_expiry_hours=SESSION_LIFETIME_HOURS,
        )
    return _auth_manager


def get_broker_manager() -> BrokerManager:
    """Get or create the broker manager."""
    global _broker_manager
    if _broker_manager is None:
        # Load broker config
        import tomllib

        broker_config_file = BROKER_CONFIG_DIR / "config.toml"
        if broker_config_file.exists():
            with open(broker_config_file, "rb") as f:
                broker_config = tomllib.load(f)
        else:
            broker_config = {}

        onchain = broker_config.get("onchain", {})

        _broker_manager = BrokerManager(
            db_path=BROKER_DATA_DIR / "ipam.db",
            operator_key_path=Path(
                onchain.get("private_key_file", BROKER_CONFIG_DIR / "operator.key")
            ),
            requests_contract=onchain.get("requests_contract", ""),
            rpc_url=onchain.get("rpc_url", "https://ethereum-sepolia-rpc.publicnode.com"),
            chain_id=onchain.get("chain_id", 11155111),
            wg_interface=broker_config.get("wireguard", {}).get("interface", "wg-broker"),
        )
    return _broker_manager


def login_required(f):
    """Decorator to require authentication."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get("auth_token")
        if not token:
            return redirect(url_for("login"))

        auth = get_auth_manager()
        address = auth.validate_session(token)
        if not address:
            session.pop("auth_token", None)
            return redirect(url_for("login"))

        # Make address available to the route
        request.wallet_address = address
        return f(*args, **kwargs)

    return decorated_function


# ============ Routes ============


@app.route("/")
def index():
    """Redirect to dashboard or login."""
    token = session.get("auth_token")
    if token:
        auth = get_auth_manager()
        if auth.validate_session(token):
            return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login")
def login():
    """Login page."""
    return render_template("login.html")


@app.route("/logout")
def logout():
    """Logout and invalidate session."""
    token = session.pop("auth_token", None)
    if token:
        get_auth_manager().invalidate_session(token)
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    """Main dashboard showing leases."""
    broker = get_broker_manager()
    leases = broker.get_leases()
    return render_template(
        "dashboard.html",
        leases=leases,
        wallet_address=request.wallet_address,
    )


# ============ API Routes ============


@app.route("/api/auth/nonce", methods=["POST"])
def api_get_nonce():
    """Get a nonce for wallet signing."""
    auth = get_auth_manager()
    nonce = auth.generate_nonce()
    message = f"Sign this message to authenticate with Blockhost Broker Manager.\n\nNonce: {nonce}"
    return jsonify({"nonce": nonce, "message": message})


@app.route("/api/auth/verify", methods=["POST"])
def api_verify_signature():
    """Verify a signed nonce and create session."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    nonce = data.get("nonce")
    signature = data.get("signature")

    if not nonce or not signature:
        return jsonify({"error": "Missing nonce or signature"}), 400

    auth = get_auth_manager()

    # Verify signature and get address
    address = auth.verify_signature(nonce, signature)
    if not address:
        return jsonify({"error": "Invalid or expired signature"}), 401

    # Check if wallet is authorized
    if not auth.is_authorized(address):
        return jsonify({"error": "Wallet not authorized"}), 403

    # Create session
    token = auth.create_session(address)
    session.permanent = True  # Use PERMANENT_SESSION_LIFETIME for cookie expiry
    session["auth_token"] = token

    return jsonify({"success": True, "address": address})


@app.route("/api/leases", methods=["GET"])
@login_required
def api_get_leases():
    """Get all current leases."""
    broker = get_broker_manager()
    leases = broker.get_leases()
    return jsonify(
        {
            "leases": [
                {
                    "id": l.id,
                    "prefix": l.prefix,
                    "wg_pubkey": l.wg_pubkey,
                    "nft_contract": l.nft_contract,
                    "allocated_at": l.allocated_at,
                }
                for l in leases
            ]
        }
    )


@app.route("/api/leases/<int:lease_id>/release", methods=["POST"])
@login_required
def api_release_lease(lease_id: int):
    """Release a specific lease."""
    broker = get_broker_manager()
    result = broker.release_lease(lease_id)

    if result["success"]:
        return jsonify(result)
    else:
        return jsonify(result), 400


# ============ CLI Entry Point ============


def create_app():
    """Create and configure the Flask app."""
    return app


def main():
    """Run the development server."""
    import argparse
    import ssl

    parser = argparse.ArgumentParser(description="Blockhost Broker Manager")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8443, help="Port to bind to")
    parser.add_argument("--cert", help="SSL certificate file")
    parser.add_argument("--key", help="SSL key file")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    ssl_context = None
    if args.cert and args.key:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(args.cert, args.key)
    elif args.cert or args.key:
        print("Error: Both --cert and --key must be provided for SSL")
        return 1

    app.run(
        host=args.host,
        port=args.port,
        ssl_context=ssl_context,
        debug=args.debug,
    )


if __name__ == "__main__":
    main()
